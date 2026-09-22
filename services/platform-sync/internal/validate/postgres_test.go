package validate

import (
	"strings"
	"testing"
)

func TestPgvectorProbeDoesNotConstructAnEmptyVector(t *testing.T) {
	t.Parallel()

	if strings.Contains(pgvectorTypeProbeQuery, "'[]'::public.vector") {
		t.Fatal("pgvector probe must not construct a zero-dimensional vector")
	}
	if !strings.Contains(pgvectorTypeProbeQuery, "null::public.vector is null") {
		t.Fatal("pgvector probe must resolve public.vector without parsing vector input")
	}
}
