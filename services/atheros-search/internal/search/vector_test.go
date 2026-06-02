package search

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVectorLiteralSanitizesNonFiniteValues(t *testing.T) {
	got := VectorLiteral([]float32{1, float32(math.NaN()), float32(math.Inf(1)), float32(math.Inf(-1))})

	require.Equal(t, "[1,0,0,0]", got)
}
