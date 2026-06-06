package alerts

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

func CheckRogueClusters(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	var inserted int32
	if err := pool.QueryRow(ctx, "SELECT vec_detect_rogue_clusters()").Scan(&inserted); err != nil {
		return 0, fmt.Errorf("rogue cluster query failed: %w", err)
	}
	if inserted < 0 {
		return 0, nil
	}
	return int(inserted), nil
}
