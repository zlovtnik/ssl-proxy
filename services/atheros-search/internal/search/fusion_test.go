package search

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFuseUsesWeightedRRFAndDeduplicates(t *testing.T) {
	dense := []RawResult{
		{SourceKey: "a", CosineSimilarity: 0.9},
		{SourceKey: "b", CosineSimilarity: 0.8},
	}
	sparse := []RawResult{
		{SourceKey: "b", KeywordRank: 2.0},
		{SourceKey: "c", KeywordRank: 1.0},
	}
	got := Fuse(dense, sparse, 10, 0.5)
	require.Len(t, got, 3)
	require.Equal(t, "b", got[0].SourceKey)
	require.Equal(t, float32(0.8), got[0].CosineSimilarity)
	require.Equal(t, float32(2.0), got[0].KeywordRank)
}
