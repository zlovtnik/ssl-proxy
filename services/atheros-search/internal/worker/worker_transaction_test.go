package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type checkingEmbedder struct {
	t       *testing.T
	dbPing  func(context.Context) error
	vectors [][]float32
}

func (e checkingEmbedder) Embed(ctx context.Context, texts []string, kind string) ([][]float32, error) {
	e.t.Helper()
	require.Equal(e.t, []string{"normalized wireless event"}, texts)
	require.Equal(e.t, "event", kind)
	require.NoError(e.t, e.dbPing(ctx), "claim transaction must commit before embedding I/O")
	return e.vectors, nil
}

func TestProcessBatchCommitsClaimBeforeEmbeddingAndCompletesAtomically(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	job := testJob()
	mock.ExpectBegin()
	mock.ExpectQuery("UPDATE embedding_jobs").
		WithArgs("worker-1", sqlmock.AnyArg(), 1).
		WillReturnRows(sqlmock.NewRows([]string{
			"job_id", "document_id", "embedding_kind", "embedding_model",
			"content_sha256", "priority", "lease_token", "lease_fence",
		}).AddRow(
			job.JobID, job.DocumentID, job.EmbeddingKind, job.EmbeddingModel,
			job.ContentSHA256, job.Priority, job.LeaseToken, job.LeaseFence,
		))
	mock.ExpectQuery("SELECT normalized_text FROM search_documents").
		WithArgs(job.DocumentID).
		WillReturnRows(sqlmock.NewRows([]string{"normalized_text"}).AddRow("normalized wireless event"))
	mock.ExpectCommit()
	mock.ExpectPing()
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO search_vectors_event").
		WithArgs(job.DocumentID, job.EmbeddingModel, job.ContentSHA256, "[0.25,0.5]").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("UPDATE embedding_jobs").
		WithArgs(job.JobID, job.LeaseToken, job.LeaseFence).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	pool := NewPool(db, checkingEmbedder{
		t:       t,
		dbPing:  db.PingContext,
		vectors: [][]float32{{0.25, 0.5}},
	}, PoolConfig{WorkerCount: 1, LeaseSeconds: 60, BatchSize: 1}, zerolog.Nop())
	pool.processBatch(context.Background(), "worker-1", zerolog.Nop())

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestStoreCompletionRollsBackVectorWhenLeaseIsLost(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	job := testJob()
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO search_vectors_event").
		WithArgs(job.DocumentID, job.EmbeddingModel, job.ContentSHA256, "[1]").
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("UPDATE embedding_jobs").
		WithArgs(job.JobID, job.LeaseToken, job.LeaseFence).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	pool := NewPool(db, checkingEmbedder{}, PoolConfig{}, zerolog.Nop())
	err = pool.storeCompletion(context.Background(), job, []float32{1})
	require.ErrorContains(t, err, "lease lost")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestStoreCompletionRollsBackWhenVectorWriteFails(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	job := testJob()
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO search_vectors_event").
		WithArgs(job.DocumentID, job.EmbeddingModel, job.ContentSHA256, "[1]").
		WillReturnError(errors.New("vector write failed"))
	mock.ExpectRollback()

	pool := NewPool(db, checkingEmbedder{}, PoolConfig{}, zerolog.Nop())
	err = pool.storeCompletion(context.Background(), job, []float32{1})
	require.ErrorContains(t, err, "vector write failed")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestStoreCompletionHonorsCancellationBeforeTransaction(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	pool := NewPool(db, checkingEmbedder{}, PoolConfig{}, zerolog.Nop())
	err = pool.storeCompletion(ctx, testJob(), []float32{1})
	require.ErrorIs(t, err, context.Canceled)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRenewJobLeaseUsesTokenFenceAndReportsLeaseLoss(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	job := testJob()
	expiresAt := time.Now().Add(time.Minute)
	mock.ExpectExec("UPDATE embedding_jobs").
		WithArgs(expiresAt, job.JobID, job.LeaseToken, job.LeaseFence).
		WillReturnResult(sqlmock.NewResult(0, 0))

	renewed, err := renewJobLease(context.Background(), db, job, expiresAt)
	require.NoError(t, err)
	require.False(t, renewed)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRecoverExpiredLeasesIsBounded(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	mock.ExpectExec("UPDATE embedding_jobs").
		WithArgs(25).
		WillReturnResult(sqlmock.NewResult(0, 3))

	recovered, err := recoverExpiredLeases(context.Background(), db, 25)
	require.NoError(t, err)
	require.Equal(t, int64(3), recovered)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPoolStopCancelsWorkersAndRecovery(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	pool := NewPool(db, checkingEmbedder{}, PoolConfig{
		WorkerCount:  2,
		LeaseSeconds: 60,
		PollInterval: time.Hour,
		BatchSize:    1,
	}, zerolog.Nop())
	pool.Start(context.Background())

	stopped := make(chan struct{})
	go func() {
		pool.Stop()
		close(stopped)
	}()

	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("worker pool did not stop after cancellation")
	}
	require.NoError(t, mock.ExpectationsWereMet())
}

func testJob() Job {
	return Job{
		JobID:          "job-1",
		DocumentID:     "document-1",
		EmbeddingKind:  "event",
		EmbeddingModel: "model-1",
		ContentSHA256:  "sha-256",
		Priority:       10,
		LeaseToken:     "token-1",
		LeaseFence:     7,
	}
}
