package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/rs/zerolog"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/auth"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/health"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/search"
	searchv1 "github.com/zlovtnik/ssl-proxy/services/atheros-search/proto/atheros/search/v1"
)

func httpStatusFromError(err error) int {
	if err == nil {
		return http.StatusInternalServerError
	}
	msg := err.Error()
	if strings.Contains(msg, "context deadline exceeded") || strings.Contains(msg, "context canceled") {
		return http.StatusGatewayTimeout
	}
	if strings.Contains(msg, "request body too large") {
		return http.StatusRequestEntityTooLarge
	}
	if strings.Contains(msg, "unsupported search kind") || strings.Contains(msg, "is required") || strings.Contains(msg, "required") {
		return http.StatusBadRequest
	}
	return http.StatusBadRequest
}

const maxRequestBodyBytes int64 = 1 << 20

func corsMiddleware(next http.Handler, allowedOrigins []string) http.Handler {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		if origin = strings.TrimSpace(origin); origin != "" {
			allowed[origin] = struct{}{}
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Add("Vary", "Origin")
			if _, ok := allowed[origin]; ok {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func StartHTTP(ctx context.Context, port int, allowedOrigins []string, svc *search.Service, readiness *health.Readiness, tokenAuth *auth.TokenAuth, logger zerolog.Logger) (*http.Server, error) {
	mux := runtime.NewServeMux()
	registerJSON(mux, "POST", "/v1/search", tokenAuth, func(w http.ResponseWriter, r *http.Request, _ map[string]string) {
		body, ok := readRequestBody(w, r)
		if !ok {
			return
		}
		var req searchv1.SearchRequest
		if err := protojson.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		resp, err := svc.Search(r.Context(), &req)
		if err != nil {
			writeError(w, httpStatusFromError(err), err.Error())
			return
		}
		writeJSON(w, http.StatusOK, resp)
	})
	registerJSON(mux, "POST", "/v1/search/stream", tokenAuth, func(w http.ResponseWriter, r *http.Request, _ map[string]string) {
		body, ok := readRequestBody(w, r)
		if !ok {
			return
		}
		var req searchv1.SearchRequest
		if err := protojson.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		resp, err := svc.Search(r.Context(), &req)
		if err != nil {
			writeError(w, httpStatusFromError(err), err.Error())
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
	registerJSON(mux, "GET", "/v1/explain/{source_key}", tokenAuth, func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		req := &searchv1.ExplainRequest{
			SourceKey: params["source_key"],
			Query:     r.URL.Query().Get("query"),
			Kind:      parseKind(r.URL.Query().Get("kind")),
		}
		resp, err := svc.Explain(r.Context(), req)
		if err != nil {
			writeError(w, httpStatusFromError(err), err.Error())
			return
		}
		writeJSON(w, http.StatusOK, resp)
	})
	registerJSON(mux, "GET", "/v1/suggest/filters", tokenAuth, func(w http.ResponseWriter, r *http.Request, _ map[string]string) {
		resp, err := svc.SuggestFilters(r.Context(), &searchv1.SuggestFiltersRequest{Prefix: r.URL.Query().Get("prefix")})
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, resp)
	})
	registerJSON(mux, "POST", "/v1/graph", tokenAuth, func(w http.ResponseWriter, r *http.Request, _ map[string]string) {
		body, ok := readRequestBody(w, r)
		if !ok {
			return
		}
		var filters search.GraphFilters
		if len(strings.TrimSpace(string(body))) > 0 {
			if err := json.Unmarshal(body, &filters); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		if err := search.ValidateGraphFilters(filters); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		resp, err := svc.Graph(r.Context(), filters)
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
		Handler:           corsMiddleware(mux, allowedOrigins),
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

func readRequestBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBodyBytes))
	if err == nil {
		return body, true
	}
	var maxBytesError *http.MaxBytesError
	if errors.As(err, &maxBytesError) {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return nil, false
	}
	writeError(w, http.StatusBadRequest, err.Error())
	return nil, false
}

func registerJSON(mux *runtime.ServeMux, method, pattern string, tokenAuth *auth.TokenAuth, handler func(http.ResponseWriter, *http.Request, map[string]string)) {
	mux.HandlePath(method, pattern, func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		if tokenAuth != nil && tokenAuth.Enabled() && !tokenAuth.VerifyAuthorization(r.Header.Get("Authorization")) {
			writeError(w, http.StatusUnauthorized, "missing or invalid bearer token")
			return
		}
		handler(w, r, params)
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
