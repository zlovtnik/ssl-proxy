package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
	"google.golang.org/protobuf/proto"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/auth"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/health"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/search"
	searchv1 "github.com/zlovtnik/ssl-proxy/services/atheros-search/proto/atheros/search/v1"
)

func httpStatusFromError(err error) int {
	if err == nil {
		return http.StatusOK
	}
	msg := err.Error()
	if strings.Contains(msg, "context deadline exceeded") || strings.Contains(msg, "context canceled") {
		return http.StatusGatewayTimeout
	}
	if strings.Contains(msg, "request body too large") {
		return http.StatusRequestEntityTooLarge
	}
	if strings.Contains(msg, "unsupported search kind") || strings.Contains(msg, "unsupported graph node kind") || strings.Contains(msg, "unsupported inventory grouping") || strings.Contains(msg, "unsupported merge decision") || strings.Contains(msg, "must be before") || strings.Contains(msg, "is required") || strings.Contains(msg, "required") {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
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
		start := time.Now()
		reqID := requestID()
		log := logger.With().Str("endpoint", "/v1/search").Str("method", "POST").Str("req_id", reqID).Logger()
		log.Info().Msg("search request started")

		body, ok := readRequestBody(w, r)
		if !ok {
			log.Error().Dur("latency", time.Since(start)).Msg("search request failed: read body")
			return
		}
		var req searchv1.SearchRequest
		if err := protojson.Unmarshal(body, &req); err != nil {
			log.Error().Err(err).Dur("latency", time.Since(start)).Msg("search request failed: unmarshal")
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		log = log.With().
			Bool("has_query", strings.TrimSpace(req.Query) != "").
			Str("query_hash", shortHash(req.Query)).
			Str("kind", req.Kind.String()).
			Str("mode", req.Mode.String()).
			Int32("top_k", req.TopK).
			Bool("has_session_id", strings.TrimSpace(req.SessionId) != "").
			Str("session_id_hash", shortHash(req.SessionId)).
			Bool("has_filters", req.Filters != nil).
			Logger()
		log.Info().Msg("search dispatched")

		resp, err := svc.Search(r.Context(), &req)
		if err != nil {
			log.Error().Err(err).Dur("latency", time.Since(start)).Msg("search failed")
			writeError(w, httpStatusFromError(err), err.Error())
			return
		}
		log.Info().
			Dur("latency", time.Since(start)).
			Int("result_count", len(resp.Results)).
			Str("mode_used", resp.ModeUsed.String()).
			Str("fallback_reason", resp.FallbackReason).
			Int32("dense_count", resp.DenseResultCount).
			Int32("sparse_count", resp.SparseResultCount).
			Int32("fused_count", resp.FusedResultCount).
			Int64("query_id", resp.QueryId).
			Msg("search completed")
		writeProtoJSON(w, http.StatusOK, resp)
	})
	registerJSON(mux, "POST", "/v1/search/stream", tokenAuth, func(w http.ResponseWriter, r *http.Request, _ map[string]string) {
		start := time.Now()
		reqID := requestID()
		log := logger.With().Str("endpoint", "/v1/search/stream").Str("method", "POST").Str("req_id", reqID).Logger()
		log.Info().Msg("search stream request started")

		body, ok := readRequestBody(w, r)
		if !ok {
			log.Error().Dur("latency", time.Since(start)).Msg("search stream failed: read body")
			return
		}
		var req searchv1.SearchRequest
		if err := protojson.Unmarshal(body, &req); err != nil {
			log.Error().Err(err).Dur("latency", time.Since(start)).Msg("search stream failed: unmarshal")
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		log = log.With().
			Bool("has_query", strings.TrimSpace(req.Query) != "").
			Str("query_hash", shortHash(req.Query)).
			Str("kind", req.Kind.String()).
			Str("mode", req.Mode.String()).
			Int32("top_k", req.TopK).
			Bool("has_session_id", strings.TrimSpace(req.SessionId) != "").
			Str("session_id_hash", shortHash(req.SessionId)).
			Bool("has_filters", req.Filters != nil).
			Logger()
		log.Info().Msg("search stream dispatched")

		resp, err := svc.Search(r.Context(), &req)
		if err != nil {
			log.Error().Err(err).Dur("latency", time.Since(start)).Msg("search stream failed")
			writeError(w, httpStatusFromError(err), err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		streamed := 0
		for _, result := range resp.Results {
			encoded, err := protojson.Marshal(result)
			if err != nil {
				log.Warn().Err(err).Int("streamed", streamed).Dur("latency", time.Since(start)).Msg("search stream marshal error")
				return
			}
			if _, err := io.Copy(w, bytes.NewReader(encoded)); err != nil {
				log.Warn().Err(err).Int("streamed", streamed).Dur("latency", time.Since(start)).Msg("search stream write error")
				return
			}
			if _, err := io.WriteString(w, "\n"); err != nil {
				log.Warn().Err(err).Int("streamed", streamed).Dur("latency", time.Since(start)).Msg("search stream write newline error")
				return
			}
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			streamed++
		}
		if _, err := io.WriteString(w, `{"type":"done"}`+"\n"); err != nil {
			log.Warn().Err(err).Int("streamed", streamed).Dur("latency", time.Since(start)).Msg("search stream done marker write error")
			return
		}
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		log.Info().
			Dur("latency", time.Since(start)).
			Int("result_count", streamed).
			Int64("query_id", resp.QueryId).
			Msg("search stream completed")
	})
	registerJSON(mux, "GET", "/v1/explain/{source_key}", tokenAuth, func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		start := time.Now()
		reqID := requestID()
		log := logger.With().Str("endpoint", "/v1/explain").Str("method", "GET").Str("req_id", reqID).Logger()

		sourceKey := params["source_key"]
		query := r.URL.Query().Get("query")
		kind := parseKind(r.URL.Query().Get("kind"))
		log = log.With().
			Bool("has_source_key", strings.TrimSpace(sourceKey) != "").
			Str("source_key_hash", shortHash(sourceKey)).
			Bool("has_query", strings.TrimSpace(query) != "").
			Str("query_hash", shortHash(query)).
			Str("kind", kind.String()).
			Logger()
		log.Info().Msg("explain request started")

		req := &searchv1.ExplainRequest{
			SourceKey: sourceKey,
			Query:     query,
			Kind:      kind,
		}
		resp, err := svc.Explain(r.Context(), req)
		if err != nil {
			log.Error().Err(err).Dur("latency", time.Since(start)).Msg("explain failed")
			writeError(w, httpStatusFromError(err), err.Error())
			return
		}
		log.Info().
			Dur("latency", time.Since(start)).
			Float64("fused_score", float64(resp.FusedScore)).
			Int("boost_reasons", len(resp.BoostReasons)).
			Msg("explain completed")
		writeProtoJSON(w, http.StatusOK, resp)
	})
	registerJSON(mux, "GET", "/v1/suggest/filters", tokenAuth, func(w http.ResponseWriter, r *http.Request, _ map[string]string) {
		start := time.Now()
		reqID := requestID()
		prefix := r.URL.Query().Get("prefix")
		log := logger.With().
			Str("endpoint", "/v1/suggest/filters").
			Str("method", "GET").
			Str("req_id", reqID).
			Bool("has_prefix", strings.TrimSpace(prefix) != "").
			Str("prefix_hash", shortHash(prefix)).
			Logger()
		log.Info().Msg("suggest filters request started")

		resp, err := svc.SuggestFilters(r.Context(), &searchv1.SuggestFiltersRequest{Prefix: prefix})
		if err != nil {
			log.Error().Err(err).Dur("latency", time.Since(start)).Msg("suggest filters failed")
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		log.Info().
			Dur("latency", time.Since(start)).
			Int("ssids", len(resp.Ssids)).
			Int("location_ids", len(resp.LocationIds)).
			Int("sensor_ids", len(resp.SensorIds)).
			Int("frame_subtypes", len(resp.FrameSubtypes)).
			Msg("suggest filters completed")
		writeProtoJSON(w, http.StatusOK, resp)
	})
	registerJSON(mux, "POST", "/v1/graph", tokenAuth, func(w http.ResponseWriter, r *http.Request, _ map[string]string) {
		start := time.Now()
		reqID := requestID()
		log := logger.With().Str("endpoint", "/v1/graph").Str("method", "POST").Str("req_id", reqID).Logger()
		log.Info().Msg("graph request started")

		body, ok := readRequestBody(w, r)
		if !ok {
			log.Error().Dur("latency", time.Since(start)).Msg("graph failed: read body")
			return
		}
		var filters search.GraphFilters
		if len(strings.TrimSpace(string(body))) > 0 {
			if err := json.Unmarshal(body, &filters); err != nil {
				log.Error().Err(err).Dur("latency", time.Since(start)).Msg("graph failed: unmarshal filters")
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		log = log.With().
			Bool("has_mac", strings.TrimSpace(filters.SourceMAC) != "").
			Str("mac_hash", shortHash(filters.SourceMAC)).
			Bool("has_ssid", strings.TrimSpace(filters.SSID) != "").
			Str("ssid_hash", shortHash(filters.SSID)).
			Int("kinds", len(filters.Kinds)).
			Int("location_ids", len(filters.LocationIDs)).
			Int("sensor_ids", len(filters.SensorIDs)).
			Bool("threat_only", filters.ThreatOnly).
			Logger()
		if filters.ObservedAfter != nil {
			log = log.With().Time("observed_after", *filters.ObservedAfter).Logger()
		}
		if filters.ObservedBefore != nil {
			log = log.With().Time("observed_before", *filters.ObservedBefore).Logger()
		}

		if err := search.ValidateGraphFilters(filters); err != nil {
			log.Warn().Err(err).Dur("latency", time.Since(start)).Msg("graph failed: validation")
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		resp, err := svc.Graph(r.Context(), filters)
		if err != nil {
			log.Error().Err(err).Dur("latency", time.Since(start)).Msg("graph failed")
			writeError(w, httpStatusFromError(err), err.Error())
			return
		}
		log.Info().
			Dur("latency", time.Since(start)).
			Int("nodes", len(resp.Nodes)).
			Int("edges", len(resp.Edges)).
			Msg("graph completed")
		writeJSON(w, http.StatusOK, resp)
	})
	registerJSON(mux, "POST", "/v1/inventory", tokenAuth, func(w http.ResponseWriter, r *http.Request, _ map[string]string) {
		start := time.Now()
		reqID := requestID()
		log := logger.With().Str("endpoint", "/v1/inventory").Str("method", "POST").Str("req_id", reqID).Logger()
		log.Info().Msg("inventory request started")

		body, ok := readRequestBody(w, r)
		if !ok {
			log.Error().Dur("latency", time.Since(start)).Msg("inventory failed: read body")
			return
		}
		var filters search.InventoryFilters
		if len(strings.TrimSpace(string(body))) > 0 {
			if err := json.Unmarshal(body, &filters); err != nil {
				log.Error().Err(err).Dur("latency", time.Since(start)).Msg("inventory failed: unmarshal filters")
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		log = log.With().
			Str("grouping", string(filters.Grouping)).
			Int("location_ids", len(filters.LocationIDs)).
			Int("owner_ids", len(filters.OwnerIDs)).
			Bool("active_only", filters.ActiveOnly).
			Int("tags", len(filters.Tags)).
			Int("limit", filters.Limit).
			Logger()

		resp, err := svc.Inventory(r.Context(), filters)
		if err != nil {
			log.Error().Err(err).Dur("latency", time.Since(start)).Msg("inventory failed")
			writeError(w, httpStatusFromError(err), err.Error())
			return
		}
		log.Info().
			Dur("latency", time.Since(start)).
			Int("nodes", len(resp.Nodes)).
			Int("edges", len(resp.Edges)).
			Int("total_registered", resp.TotalRegisteredCount).
			Msg("inventory completed")
		writeJSON(w, http.StatusOK, resp)
	})
	registerJSON(mux, "POST", "/v1/inventory/merge-candidates/{candidate_id}/decision", tokenAuth, func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		start := time.Now()
		reqID := requestID()
		candidateID := params["candidate_id"]
		log := logger.With().
			Str("endpoint", "/v1/inventory/merge-candidates/:id/decision").
			Str("method", "POST").
			Str("req_id", reqID).
			Str("candidate_hash", shortHash(candidateID)).
			Logger()
		log.Info().Msg("merge decision request started")

		body, ok := readRequestBody(w, r)
		if !ok {
			log.Error().Dur("latency", time.Since(start)).Msg("merge decision failed: read body")
			return
		}
		var req search.MergeDecisionRequest
		if err := json.Unmarshal(body, &req); err != nil {
			log.Error().Err(err).Dur("latency", time.Since(start)).Msg("merge decision failed: unmarshal")
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		resp, err := svc.MergeDecision(r.Context(), candidateID, req.Decision)
		if err != nil {
			log.Error().Err(err).Dur("latency", time.Since(start)).Msg("merge decision failed")
			writeError(w, httpStatusFromError(err), err.Error())
			return
		}
		log.Info().
			Dur("latency", time.Since(start)).
			Str("decision", string(req.Decision)).
			Bool("accepted", resp.Accepted).
			Msg("merge decision completed")
		writeJSON(w, http.StatusOK, resp)
	})
	mux.HandlePath("GET", "/healthz", func(w http.ResponseWriter, r *http.Request, _ map[string]string) {
		logger.Debug().Str("endpoint", "/healthz").Msg("healthz check")
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandlePath("GET", "/readyz", func(w http.ResponseWriter, r *http.Request, _ map[string]string) {
		logger.Debug().Str("endpoint", "/readyz").Msg("readyz check")
		if err := readiness.Check(r.Context()); err != nil {
			logger.Warn().Err(err).Msg("readyz check failed")
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

func writeProtoJSON(w http.ResponseWriter, status int, msg proto.Message) {
	encoded, err := protojson.Marshal(msg)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(encoded)
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

func shortHash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:12]
}

func requestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
