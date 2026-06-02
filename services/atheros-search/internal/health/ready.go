package health

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/db"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/embed"
)

type Readiness struct {
	DB       *db.Pool
	Embedder embed.Client
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
