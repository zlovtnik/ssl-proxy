package seqscore

import (
	"context"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const defaultVocabSize = 16

type bigramKey struct {
	prev string
	next string
}

type Scorer struct {
	counts    map[bigramKey]int64
	totals    map[string]int64
	vocabSize int
}

type transitionRow struct {
	prev  string
	next  string
	count int64
}

type Transition struct {
	Prev  string
	Next  string
	Count int64
}

func Empty() *Scorer {
	return FromRows(nil)
}

func FromRows(rows []Transition) *Scorer {
	typed := make([]transitionRow, 0, len(rows))
	for _, row := range rows {
		typed = append(typed, transitionRow{prev: row.Prev, next: row.Next, count: row.Count})
	}
	return fromTransitionRows(typed)
}

func Load(ctx context.Context, pool *pgxpool.Pool) (*Scorer, error) {
	rows, err := pool.Query(ctx, `
SELECT prev_token, next_token, count
FROM vec_transition_model
WHERE embedding_kind = 'frame_sequence'
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	transitions := []transitionRow{}
	for rows.Next() {
		var row transitionRow
		if err := rows.Scan(&row.prev, &row.next, &row.count); err != nil {
			return nil, err
		}
		transitions = append(transitions, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return fromTransitionRows(transitions), nil
}

func (s *Scorer) ScoreText(tokens string) float64 {
	return s.ScoreTokens(strings.Fields(tokens))
}

func (s *Scorer) ScoreTokens(tokens []string) float64 {
	if len(tokens) < 2 {
		return 0
	}
	vocabSize := s.vocabSize
	if vocabSize <= 0 {
		vocabSize = defaultVocabSize
	}
	logProb := 0.0
	for i := 0; i < len(tokens)-1; i++ {
		prev := tokens[i]
		next := tokens[i+1]
		total := s.totals[prev]
		var probability float64
		if total <= 0 {
			probability = 1.0 / float64(vocabSize)
		} else {
			count := s.counts[bigramKey{prev: prev, next: next}]
			probability = (float64(count) + 1.0) / (float64(total) + float64(vocabSize))
		}
		logProb += math.Log2(probability)
	}
	return logProb
}

type Cache struct {
	TTL time.Duration

	mu       sync.Mutex
	scorer   *Scorer
	loadedAt time.Time
}

func NewCache(ttl time.Duration) *Cache {
	return &Cache{TTL: ttl}
}

func (c *Cache) Get(ctx context.Context, pool *pgxpool.Pool) (*Scorer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	ttl := c.TTL
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	if c.scorer != nil && time.Since(c.loadedAt) < ttl {
		return c.scorer, nil
	}
	scorer, err := Load(ctx, pool)
	if err != nil {
		return nil, err
	}
	c.scorer = scorer
	c.loadedAt = time.Now()
	return scorer, nil
}

func fromTransitionRows(rows []transitionRow) *Scorer {
	counts := make(map[bigramKey]int64, len(rows))
	totals := map[string]int64{}
	vocab := map[string]struct{}{}
	for _, row := range rows {
		count := row.count
		if count < 0 {
			count = 0
		}
		vocab[row.prev] = struct{}{}
		vocab[row.next] = struct{}{}
		counts[bigramKey{prev: row.prev, next: row.next}] = count
		totals[row.prev] += count
	}
	vocabSize := len(vocab)
	if vocabSize == 0 {
		vocabSize = defaultVocabSize
	}
	return &Scorer{
		counts:    counts,
		totals:    totals,
		vocabSize: vocabSize,
	}
}
