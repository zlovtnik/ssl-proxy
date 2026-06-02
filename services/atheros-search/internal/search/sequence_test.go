package search

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractSequenceTokensRequiresOrderedSubtypes(t *testing.T) {
	require.Nil(t, ExtractSequenceTokens("probe_request only"))
	require.Equal(t, []string{"probe_request", "deauthentication", "association_request"}, ExtractSequenceTokens("probe_request deauthentication association_request"))
}
