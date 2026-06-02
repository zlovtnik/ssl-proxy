package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/rs/zerolog"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/auth"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/health"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/search"
	searchv1 "github.com/zlovtnik/ssl-proxy/services/atheros-search/proto/atheros/search/v1"
)

func StartHTTP(ctx context.Context, port int, svc *search.Service, readiness *health.Readiness, tokenAuth *auth.TokenAuth, logger zerolog.Logger) (*http.Server, error) {
	mux := runtime.NewServeMux()
	registerJSON(mux, "POST", "/v1/search", tokenAuth, func(w http.ResponseWriter, r *http.Request) {
		var req searchv1.SearchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		resp, err := svc.Search(r.Context(), &req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, resp)
	})
	registerJSON(mux, "POST", "/v1/search/stream", tokenAuth, func(w http.ResponseWriter, r *http.Request) {
		var req searchv1.SearchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		resp, err := svc.Search(r.Context(), &req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		for _, result := range resp.Results {
			if err := json.NewEncoder(w).Encode(result); err != nil {
				return
			}
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
	})
	registerJSON(mux, "GET", "/v1/explain/{source_key}", tokenAuth, func(w http.ResponseWriter, r *http.Request) {
		req := &searchv1.ExplainRequest{
			SourceKey: strings.TrimPrefix(r.URL.Path, "/v1/explain/"),
			Query:     r.URL.Query().Get("query"),
			Kind:      parseKind(r.URL.Query().Get("kind")),
		}
		resp, err := svc.Explain(r.Context(), req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, resp)
	})
	registerJSON(mux, "GET", "/v1/suggest/filters", tokenAuth, func(w http.ResponseWriter, r *http.Request) {
		resp, err := svc.SuggestFilters(r.Context(), &searchv1.SuggestFiltersRequest{Prefix: r.URL.Query().Get("prefix")})
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, resp)
	})
	mux.HandlePath("GET", "/healthz", func(w http.ResponseWriter, r *http.Request, _ map[string]string) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandlePath("GET", "/readyz", func(w http.ResponseWriter, r *http.Request, _ map[string]string) {
		if err := readiness.Check(r.Context()); err != nil {
			writeError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	go func() {
		logger.Info().Int("port", port).Msg("http gateway listening")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error().Err(err).Msg("http gateway stopped")
		}
	}()
	return server, nil
}

func registerJSON(mux *runtime.ServeMux, method, pattern string, tokenAuth *auth.TokenAuth, handler func(http.ResponseWriter, *http.Request)) {
	mux.HandlePath(method, pattern, func(w http.ResponseWriter, r *http.Request, _ map[string]string) {
		if tokenAuth != nil && tokenAuth.Enabled() && !tokenAuth.VerifyAuthorization(r.Header.Get("Authorization")) {
			writeError(w, http.StatusUnauthorized, "missing or invalid bearer token")
			return
		}
		handler(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func parseKind(value string) searchv1.SearchKind {
	switch strings.ToLower(value) {
	case "behaviour", "behavior", "behaviour_window":
		return searchv1.SearchKind_SEARCH_KIND_BEHAVIOUR
	case "sequence", "frame_sequence":
		return searchv1.SearchKind_SEARCH_KIND_SEQUENCE
	case "device":
		return searchv1.SearchKind_SEARCH_KIND_DEVICE
	case "cross":
		return searchv1.SearchKind_SEARCH_KIND_CROSS
	default:
		return searchv1.SearchKind_SEARCH_KIND_EVENT
	}
}
