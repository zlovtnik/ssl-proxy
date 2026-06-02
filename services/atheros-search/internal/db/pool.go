package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	pgxvec "github.com/pgvector/pgvector-go/pgx"
)

type Pool struct {
	*pgxpool.Pool
}

func NewPool(ctx context.Context, dsn string) (*Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse postgres dsn: %w", err)
	}
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		return pgxvec.RegisterTypes(ctx, conn)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create postgres pool: %w", err)
	}
	wrapped := &Pool{Pool: pool}
	if err := wrapped.Health(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return wrapped, nil
}

func (p *Pool) Health(ctx context.Context) error {
	var one int
	if err := p.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
		return fmt.Errorf("postgres health query: %w", err)
	}
	if one != 1 {
		return fmt.Errorf("postgres health query returned %d", one)
	}
	return nil
}

func (p *Pool) CountEmbeddings(ctx context.Context) (int64, error) {
	var count int64
	err := p.QueryRow(ctx, "SELECT count(*) FROM vec_embeddings").Scan(&count)
	return count, err
}

func WithApplicationName(ctx context.Context, tx pgx.Tx, name string) error {
	_, err := tx.Exec(ctx, "SET LOCAL application_name = $1", name)
	return err
}
