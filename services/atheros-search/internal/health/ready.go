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
		return errors.New("TiDB pool is not initialized")
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
		log.Warn().Msg("search vector tables are empty")
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
					Bool("vector_ready", status.VectorReady).
					Str("manifest_sha256", status.ManifestSHA256).
					Msg("schema readiness gate passed")
				return nil
			}
			logger.Debug().Str("schema_status", schemaStatusSummary(status)).Msg("waiting for schema readiness gate")
		} else {
			lastErr = err
			logger.Debug().Err(err).Msg("waiting for schema readiness view")
		}

		select {
		case <-waitCtx.Done():
			switch {
			case errors.Is(waitCtx.Err(), context.Canceled):
				return fmt.Errorf("schema readiness canceled: %w", waitCtx.Err())
			case errors.Is(waitCtx.Err(), context.DeadlineExceeded):
				if lastErr != nil {
					return fmt.Errorf("schema readiness timeout after %s: %w", timeout, lastErr)
				}
				if lastStatus != nil {
					return fmt.Errorf("schema readiness timeout after %s: %s", timeout, schemaStatusSummary(*lastStatus))
				}
				return fmt.Errorf("schema readiness timeout after %s", timeout)
			default:
				return fmt.Errorf("schema readiness wait ended: %w", waitCtx.Err())
			}
		case <-ticker.C:
		}
	}
}

func schemaStatusSummary(status db.SchemaReadyStatus) string {
	return fmt.Sprintf(
		"ready=%t vector_ready=%t manifest_sha256=%s expected_sha256=%s",
		status.Ready,
		status.VectorReady,
		status.ManifestSHA256,
		status.ExpectedSHA256,
	)
}
