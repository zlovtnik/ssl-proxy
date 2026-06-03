package search

import "sort"

func Fuse(dense []RawResult, sparse []RawResult, topK int, alpha float64) []RawResult {
	byKey := make(map[string]*RawResult, len(dense)+len(sparse))
	add := func(result RawResult, rank int, dense bool) {
		item := byKey[result.SourceKey]
		if item == nil {
			copied := result
			item = &copied
			item.Score = 0
			byKey[result.SourceKey] = item
		}
		weight := float32(1 - alpha)
		if dense {
			weight = float32(alpha)
			if result.CosineSimilarity > item.CosineSimilarity {
				item.CosineSimilarity = result.CosineSimilarity
			}
		} else if result.KeywordRank > item.KeywordRank {
			item.KeywordRank = result.KeywordRank
		}
		item.Score += weight * float32(1.0/(rrfK+float64(rank)))
	}
	for i, result := range dense {
		add(result, i+1, true)
	}
	for i, result := range sparse {
		add(result, i+1, false)
	}
	out := make([]RawResult, 0, len(byKey))
	for _, result := range byKey {
		out = append(out, *result)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score == out[j].Score {
			return out[i].SourceKey < out[j].SourceKey
		}
		return out[i].Score > out[j].Score
	})
	if topK > 0 && len(out) > topK {
		out = out[:topK]
	}
	return out
}
