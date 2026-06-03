package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunHealthcheckUsesConfiguredHTTPPort(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/healthz", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(parsed.Host)
	require.NoError(t, err)
	_, err = strconv.Atoi(port)
	require.NoError(t, err)
	t.Setenv("ATHSEARCH_HTTP_PORT", port)

	require.NoError(t, runHealthcheck())
}

func TestRunHealthcheckRejectsBadPort(t *testing.T) {
	t.Setenv("ATHSEARCH_HTTP_PORT", "not-a-port")
	require.ErrorContains(t, runHealthcheck(), "invalid ATHSEARCH_HTTP_PORT")
}
