package db

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestCountEmbeddingsReturnsCountsByKind(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })

	mock.ExpectQuery("SELECT").WillReturnRows(
		sqlmock.NewRows([]string{"event", "device", "behaviour", "sequence"}).
			AddRow(4, 0, 2, 0),
	)

	counts, err := (&Pool{DB: sqlDB}).CountEmbeddings(context.Background())
	require.NoError(t, err)
	require.Equal(t, EmbeddingCounts{Event: 4, Device: 0, Behaviour: 2, Sequence: 0}, counts)
	require.Equal(t, []string{"device", "frame_sequence"}, counts.EmptyKinds())
	require.NoError(t, mock.ExpectationsWereMet())
}
