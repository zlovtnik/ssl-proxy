package search

import (
	"context"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

var subtypeToken = regexp.MustCompile(`(?i)\b(probe_request|probe_response|beacon|authentication|deauthentication|association_request|association_response|reassociation_request|reassociation_response|disassociation|data|qos_data)\b`)

func ExtractSequenceTokens(query string) []string {
	matches := subtypeToken.FindAllString(query, -1)
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		out = append(out, strings.ToLower(match))
	}
	if len(out) < 2 {
		return nil
	}
	return out
}

func ScoreSequence(ctx context.Context, pool *pgxpool.Pool, tokens []string) (float64, error) {
	if len(tokens) < 2 {
		return 0, nil
	}
	var score float64
	err := pool.QueryRow(ctx, "SELECT vec_score_sequence($1::text[])", tokens).Scan(&score)
	return score, err
}
