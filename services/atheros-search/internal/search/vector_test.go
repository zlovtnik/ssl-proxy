package search

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateVectorRejectsNonFiniteAndWrongDimension(t *testing.T) {
	vector := make([]float32, embeddingDimensions)
	vector[7] = float32(math.NaN())
	require.ErrorContains(t, validateVector(vector), "non-finite")

	require.ErrorContains(t, validateVector(make([]float32, 3)), "expected 768")
}

func TestVectorLiteralFormatsEmptyAndFractionalValues(t *testing.T) {
	require.Equal(t, "[]", VectorLiteral(nil))
	require.Equal(t, "[0.123456,-1.5,3.14159]", VectorLiteral([]float32{0.123456, -1.5, 3.14159}))
}
