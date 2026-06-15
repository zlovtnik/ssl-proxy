package api

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestHTTPStatusFromError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "nil", err: nil, want: http.StatusOK},
		{name: "deadline", err: context.DeadlineExceeded, want: http.StatusGatewayTimeout},
		{name: "canceled", err: context.Canceled, want: http.StatusGatewayTimeout},
		{name: "too large", err: errors.New("request body too large"), want: http.StatusRequestEntityTooLarge},
		{name: "graph validation", err: errors.New("unsupported graph node kind \"embedding\""), want: http.StatusBadRequest},
		{name: "range validation", err: errors.New("observed_after must be before observed_before"), want: http.StatusBadRequest},
		{name: "search query validation", err: errors.New("search query is required and must contain meaningful terms"), want: http.StatusBadRequest},
		{name: "fallback", err: errors.New("boom"), want: http.StatusInternalServerError},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := httpStatusFromError(tc.err); got != tc.want {
				t.Fatalf("httpStatusFromError(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}
