package search

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"regexp"
	"strings"
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

func ScoreSequence(ctx context.Context, pool *sql.DB, tokens []string) (float64, error) {
	if len(tokens) < 2 {
		return 0, nil
	}
	const defaultVocabularySize = 16
	score := 0.0
	for i := 0; i < len(tokens)-1; i++ {
		var count, total, vocabulary int64
		err := pool.QueryRowContext(ctx, `
SELECT transition_count, previous_total, vocabulary_size
FROM atheros_search.sequence_transitions
WHERE previous_token = $1 AND next_token = $2 AND sequence_kind = 'frame_sequence'
LIMIT 1`, tokens[i], tokens[i+1]).Scan(&count, &total, &vocabulary)
		if errors.Is(err, sql.ErrNoRows) {
			score += math.Log2(1.0 / defaultVocabularySize)
			continue
		}
		if err != nil {
			return 0, err
		}
		if vocabulary <= 0 {
			vocabulary = defaultVocabularySize
		}
		if count < 0 {
			count = 0
		}
		if total < 0 {
			total = 0
		}
		score += math.Log2((float64(count) + 1) / (float64(total) + float64(vocabulary)))
	}
	return score, nil
}
