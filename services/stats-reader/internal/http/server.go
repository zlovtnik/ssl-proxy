// Package httpsrv serves the public stats endpoints: a store-backed
// snapshot with a strict key allowlist, plus always-on readiness probes.
package httpsrv

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// SnapshotStore supplies validated snapshot bytes and store health.
type SnapshotStore interface {
	Snapshot(ctx context.Context) ([]byte, error)
	Health(ctx context.Context) (redisOK, minioOK bool)
}

const (
	unavailableBody = `{"error":"Metrics unavailable"}`
	healthTimeout   = 2 * time.Second
)

// Top-level snapshot v2 allowlist. Unknown keys are stripped before emit.
var topLevelKeys = []string{
	"asOf",
	"peaksComputedAt",
	"peakRecordsDay",
	"peakRecordsDayDate",
	"peakRecordsWeek",
	"peakRecordsWeekStart",
	"peakRecordsWeekEnd",
	"liveStrip",
	"lifetimeTotals",
	"throughput24h",
	"throughput7d",
}

var liveStripKeys = []string{
	"ingestProcessedRatePerSec",
	"pendingLedgerCount",
	"lastIngestSuccessAt",
	"backpressureActive",
}

var lifetimeTotalsKeys = []string{
	"recordsTotal",
	"daysCounted",
	"computedAt",
}

var throughputKeys = []string{
	"bucket",
	"series",
}

var seriesItemKeys = []string{
	"bucketStart",
	"records",
}

// Server routes public stats, readiness, and operator health.
type Server struct {
	store   SnapshotStore
	origins map[string]struct{}
	mux     *http.ServeMux
}

// New builds the handler set. allowedOrigins is the CORS allowlist.
func New(store SnapshotStore, allowedOrigins []string) *Server {
	s := &Server{
		store:   store,
		origins: make(map[string]struct{}, len(allowedOrigins)),
		mux:     http.NewServeMux(),
	}
	for _, o := range allowedOrigins {
		if o != "" {
			s.origins[o] = struct{}{}
		}
	}
	s.mux.HandleFunc("GET /public/stats", s.handleStats)
	s.mux.HandleFunc("OPTIONS /public/stats", s.handlePreflight)
	s.mux.HandleFunc("GET /ready", s.handleReady)
	s.mux.HandleFunc("GET /live", s.handleLive)
	s.mux.HandleFunc("GET /health", s.handleHealth)
	return s
}

// Handler returns the root handler.
func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	s.applyCORS(w, r)
	w.Header().Set("Cache-Control", "public, max-age=30")
	w.Header().Set("Vary", "Origin")
	w.Header().Set("Content-Type", "application/json")

	raw, err := s.store.Snapshot(r.Context())
	if err != nil {
		writeUnavailable(w)
		return
	}
	out, err := sanitizeSnapshot(raw)
	if err != nil {
		writeUnavailable(w)
		return
	}
	_, _ = w.Write(out)
}

func (s *Server) handlePreflight(w http.ResponseWriter, r *http.Request) {
	allowed := s.applyCORS(w, r)
	w.Header().Set("Vary", "Origin")
	if allowed {
		w.Header().Set("Access-Control-Max-Age", "600")
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleReady is always 200 once the process is up. Store health never
// gates readiness, so Traefik keeps routing to this service.
func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleLive(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ok"))
}

// handleHealth reports store reachability for operators. Traefik does
// not use it.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), healthTimeout)
	defer cancel()
	redisOK, minioOK := s.store.Health(ctx)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{
		"redis": redisOK,
		"minio": minioOK,
	})
}

func writeUnavailable(w http.ResponseWriter) {
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(unavailableBody))
}

// applyCORS sets CORS headers when the request Origin is allowlisted and
// reports whether it was.
func (s *Server) applyCORS(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	if _, ok := s.origins[origin]; !ok {
		return false
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type")
	return true
}

// sanitizeSnapshot keeps only allowlisted keys and requires asOf. Keys
// that are absent stay absent; values are never invented.
func sanitizeSnapshot(raw []byte) ([]byte, error) {
	var top map[string]any
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, err
	}
	out := make(map[string]any, len(topLevelKeys))
	for _, k := range topLevelKeys {
		v, ok := top[k]
		if !ok {
			continue
		}
		switch k {
		case "liveStrip":
			out[k] = filterObject(v, liveStripKeys)
		case "lifetimeTotals":
			out[k] = filterObject(v, lifetimeTotalsKeys)
		case "throughput24h", "throughput7d":
			out[k] = filterThroughput(v)
		default:
			out[k] = v
		}
	}
	asOf, ok := out["asOf"].(string)
	if !ok || asOf == "" {
		return nil, errors.New("snapshot missing asOf")
	}
	return json.Marshal(out)
}

// filterObject keeps only allowlisted keys of a JSON object. Non-objects
// (including null) pass through unchanged.
func filterObject(v any, allowed []string) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	out := make(map[string]any, len(allowed))
	for _, k := range allowed {
		if nv, ok := m[k]; ok {
			out[k] = nv
		}
	}
	return out
}

func filterThroughput(v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	out := make(map[string]any, len(throughputKeys))
	for _, k := range throughputKeys {
		nv, ok := m[k]
		if !ok {
			continue
		}
		if k == "series" {
			out[k] = filterSeries(nv)
			continue
		}
		out[k] = nv
	}
	return out
}

func filterSeries(v any) any {
	arr, ok := v.([]any)
	if !ok {
		return v
	}
	out := make([]any, 0, len(arr))
	for _, item := range arr {
		out = append(out, filterObject(item, seriesItemKeys))
	}
	return out
}
