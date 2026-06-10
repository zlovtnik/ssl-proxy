package seqscore

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func testScorer() *Scorer {
	return FromRows([]Transition{
		{Prev: "AUTH", Next: "ASSOC_REQ", Count: 3},
		{Prev: "AUTH", Next: "DEAUTH", Count: 1},
		{Prev: "ASSOC_REQ", Next: "EAPOL", Count: 2},
	})
}

func TestEmptyAndShortSequencesScoreZero(t *testing.T) {
	scorer := testScorer()

	require.Equal(t, 0.0, scorer.ScoreTokens(nil))
	require.Equal(t, 0.0, scorer.ScoreTokens([]string{"AUTH"}))
}

func TestKnownBigramUsesLaplaceSmoothing(t *testing.T) {
	score := testScorer().ScoreTokens([]string{"AUTH", "ASSOC_REQ"})
	expected := math.Log2((3.0 + 1.0) / (4.0 + 4.0))

	require.InDelta(t, expected, score, 0.000001)
}

func TestUnseenBigramUnderKnownPrefix(t *testing.T) {
	score := testScorer().ScoreTokens([]string{"AUTH", "PROBE_REQ"})
	expected := math.Log2(1.0 / (4.0 + 4.0))

	require.InDelta(t, expected, score, 0.000001)
}

func TestUnknownPrefixUsesUniformVocabularyProbability(t *testing.T) {
	score := testScorer().ScoreTokens([]string{"PROBE_REQ", "AUTH"})
	expected := math.Log2(1.0 / 4.0)

	require.InDelta(t, expected, score, 0.000001)
}

func TestEmptyModelUsesDefaultVocabularySize(t *testing.T) {
	score := Empty().ScoreTokens([]string{"A", "B"})
	expected := math.Log2(1.0 / float64(defaultVocabSize))

	require.InDelta(t, expected, score, 0.000001)
}
