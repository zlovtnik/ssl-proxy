package textbuilder

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/db"
)

func Build(ctx context.Context, pool *pgxpool.Pool, job db.EmbeddingJob) (db.EmbeddingInput, error) {
	inputs, err := BuildBatch(ctx, pool, []db.EmbeddingJob{job})
	if err != nil {
		return db.EmbeddingInput{}, err
	}
	input, ok := inputs[job.SourceKey]
	if !ok {
		return db.EmbeddingInput{}, fmt.Errorf("%s source row not found: %s", job.EmbeddingKind, job.SourceKey)
	}
	return input, nil
}

func BuildBatch(ctx context.Context, pool *pgxpool.Pool, jobs []db.EmbeddingJob) (map[string]db.EmbeddingInput, error) {
	out := make(map[string]db.EmbeddingInput, len(jobs))
	if len(jobs) == 0 {
		return out, nil
	}

	groups := map[string][]db.EmbeddingJob{}
	sourceKinds := map[string]string{}
	for _, job := range jobs {
		if existingKind, ok := sourceKinds[job.SourceKey]; ok && existingKind != job.EmbeddingKind {
			return nil, fmt.Errorf("duplicate source_key across embedding kinds: %s (%s, %s)", job.SourceKey, existingKind, job.EmbeddingKind)
		}
		sourceKinds[job.SourceKey] = job.EmbeddingKind
		groups[job.EmbeddingKind] = append(groups[job.EmbeddingKind], job)
	}

	for kind, group := range groups {
		var err error
		switch kind {
		case "event":
			err = buildEventsBatch(ctx, pool, group, out)
		case "device":
			err = buildDevicesBatch(ctx, pool, group, out)
		case "behaviour_window":
			err = buildBehaviourWindowsBatch(ctx, pool, group, out)
		case "baseline_profile":
			err = buildBaselineProfilesBatch(ctx, pool, group, out)
		case "frame_sequence":
			err = buildFrameSequencesBatch(ctx, pool, group, out)
		case "infrastructure_subgraph":
			err = buildInfrastructureSubgraphsBatch(ctx, pool, group, out)
		case "timing_profile":
			err = buildTimingProfilesBatch(ctx, pool, group, out)
		default:
			return nil, fmt.Errorf("unsupported embedding_kind: %s", kind)
		}
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func sourceKeys(jobs []db.EmbeddingJob) []string {
	keys := make([]string, 0, len(jobs))
	for _, job := range jobs {
		keys = append(keys, job.SourceKey)
	}
	return keys
}
