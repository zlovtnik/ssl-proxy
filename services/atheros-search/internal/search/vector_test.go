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

func TestVectorLiteralFormatsEmptyAndFractionalValues(t *testing.T) {
	require.Equal(t, "[]", VectorLiteral(nil))
	require.Equal(t, "[0.123456,-1.5,3.14159]", VectorLiteral([]float32{0.123456, -1.5, 3.14159}))
}
