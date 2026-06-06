package alerts

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

func CheckHighRiskAPs(ctx context.Context, pool *pgxpool.Pool, threshold float64) (int, error) {
	var inserted int32
	if err := pool.QueryRow(ctx, "SELECT check_high_risk_aps($1)", threshold).Scan(&inserted); err != nil {
		return 0, fmt.Errorf("high_risk_ap query failed: %w", err)
	}
	if inserted < 0 {
		return 0, nil
	}
	return int(inserted), nil
}
