package health

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/db"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/embed"
)

type Database interface {
	Health(ctx context.Context) error
	SchemaReady(ctx context.Context) (db.SchemaReadyStatus, error)
	CountEmbeddings(ctx context.Context) (int64, error)
}

type Readiness struct {
	DB                  Database
	Embedder            embed.Client
	SchemaReadyRequired bool
}

func (r *Readiness) Check(ctx context.Context) error {
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if r.DB == nil {
		return errors.New("postgres pool is not initialized")
	}
	if err := r.DB.Health(checkCtx); err != nil {
		return err
	}
	if r.SchemaReadyRequired {
		status, err := r.DB.SchemaReady(checkCtx)
		if err != nil {
			return fmt.Errorf("schema readiness: %w", err)
		}
		if !status.Ready {
			return fmt.Errorf("schema not ready: %s", schemaStatusSummary(status))
		}
	}
	count, err := r.DB.CountEmbeddings(checkCtx)
	if err != nil {
		return fmt.Errorf("count embeddings: %w", err)
	}
	if count < 1 {
		log.Warn().Msg("vec_embeddings is empty")
	}
	if r.Embedder != nil {
		if err := r.Embedder.Health(checkCtx); err != nil {
			return fmt.Errorf("embedding backend: %w", err)
		}
	}
	return nil
}

func WaitForSchemaReady(ctx context.Context, store Database, timeout, pollInterval time.Duration, logger zerolog.Logger) error {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	if pollInterval <= 0 {
		pollInterval = time.Second
	}

	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	var lastStatus *db.SchemaReadyStatus
	var lastErr error
	for {
		status, err := store.SchemaReady(waitCtx)
		if err == nil {
			lastStatus = &status
			lastErr = nil
			if status.Ready {
				logger.Info().
					Int64("total_count", status.TotalCount).
					Int64("pending_count", status.PendingCount).
					Int64("failed_count", status.FailedCount).
					Msg("schema readiness gate passed")
				return nil
			}
			if status.FailedCount > 0 {
				return fmt.Errorf("schema readiness gate failed: %s", schemaStatusSummary(status))
			}
			logger.Debug().Str("schema_status", schemaStatusSummary(status)).Msg("waiting for schema readiness gate")
		} else {
			lastErr = err
			logger.Debug().Err(err).Msg("waiting for schema readiness view")
		}

		select {
		case <-waitCtx.Done():
			if lastErr != nil {
				return fmt.Errorf("schema readiness timeout after %s: %w", timeout, lastErr)
			}
			if lastStatus != nil {
				return fmt.Errorf("schema readiness timeout after %s: %s", timeout, schemaStatusSummary(*lastStatus))
			}
			return fmt.Errorf("schema readiness timeout after %s", timeout)
		case <-ticker.C:
		}
	}
}

func schemaStatusSummary(status db.SchemaReadyStatus) string {
	return fmt.Sprintf(
		"ready=%t all_applied=%t total_count=%d pending_count=%d failed_count=%d failed_objects=%v",
		status.Ready,
		status.AllApplied,
		status.TotalCount,
		status.PendingCount,
		status.FailedCount,
		status.FailedObjects,
	)
}
