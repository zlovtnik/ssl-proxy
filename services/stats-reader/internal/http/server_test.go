package httpsrv

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zlovtnik/ssl-proxy/services/stats-reader/internal/store"
)

const validSnapshot = `{
  "asOf": "2026-02-01T12:00:00Z",
  "peaksComputedAt": "2026-02-01T11:55:00Z",
  "peakRecordsDay": 12,
  "peakRecordsDayDate": "2026-01-31",
  "peakRecordsWeek": 80,
  "peakRecordsWeekStart": "2026-01-26T00:00:00Z",
  "peakRecordsWeekEnd": "2026-02-01T23:59:59Z",
  "liveStrip": {
    "ingestProcessedRatePerSec": 1.5,
    "pendingLedgerCount": 3,
    "lastIngestSuccessAt": "2026-02-01T11:59:00Z",
    "backpressureActive": false
  },
  "lifetimeTotals": {
    "recordsTotal": 1000,
    "daysCounted": 40,
    "computedAt": "2026-02-01T11:55:00Z"
  },
  "throughput24h": {
    "bucket": "hour",
    "series": [{"bucketStart": "2026-02-01T10:00:00Z", "records": 5}]
  },
  "throughput7d": {
    "bucket": "hour",
    "series": [{"bucketStart": "2026-01-26T00:00:00Z", "records": 0}]
  }
}`

// stubStore is a SnapshotStore for handler-level tests.
type stubStore struct {
	raw     []byte
	err     error
	redisOK bool
	minioOK bool
}

func (s stubStore) Snapshot(context.Context) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.raw, nil
}

func (s stubStore) Health(context.Context) (bool, bool) {
	return s.redisOK, s.minioOK
}

// fakeRedis and fakeObjects back a real store.Store for the fallback
// matrix tests.
type fakeRedis struct {
	value []byte
	err   error
}

func (f *fakeRedis) Get(context.Context, string) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.value == nil {
		return nil, errors.New("redis: nil")
	}
	return f.value, nil
}

func (f *fakeRedis) Ping(context.Context) error {
	if f.err != nil {
		return f.err
	}
	return nil
}

type fakeObjects struct {
	value []byte
	err   error
}

func (f *fakeObjects) GetObject(context.Context, string, string) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.value == nil {
		return nil, errors.New("no such key")
	}
	return f.value, nil
}

func (f *fakeObjects) BucketExists(context.Context, string) (bool, error) {
	return true, nil
}

func newServer(s SnapshotStore) *Server {
	return New(s, []string{"https://rclabs.uk", "https://www.rclabs.uk"})
}

func doGet(t *testing.T, h http.Handler, path, origin string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestPublicStatsRedisHit(t *testing.T) {
	rec := doGet(t, newServer(stubStore{raw: []byte(validSnapshot)}).Handler(), "/public/stats", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=30" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := rec.Header().Get("Vary"); !strings.Contains(got, "Origin") {
		t.Fatalf("Vary = %q, want Origin", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if body["asOf"] != "2026-02-01T12:00:00Z" {
		t.Fatalf("asOf = %v", body["asOf"])
	}
}

func TestPublicStatsFallbackMatrix(t *testing.T) {
	valid := []byte(validSnapshot)
	tests := []struct {
		name       string
		redis      *fakeRedis
		objects    *fakeObjects
		prime      bool
		wantStatus int
		wantAsOf   string
	}{
		{
			name:       "redis hit",
			redis:      &fakeRedis{value: valid},
			objects:    &fakeObjects{},
			wantStatus: http.StatusOK,
			wantAsOf:   "2026-02-01T12:00:00Z",
		},
		{
			name:       "redis miss minio hit",
			redis:      &fakeRedis{err: errors.New("redis: nil")},
			objects:    &fakeObjects{value: valid},
			wantStatus: http.StatusOK,
			wantAsOf:   "2026-02-01T12:00:00Z",
		},
		{
			name:       "both fail last good",
			redis:      &fakeRedis{err: errors.New("connection refused")},
			objects:    &fakeObjects{err: errors.New("no such key")},
			prime:      true,
			wantStatus: http.StatusOK,
			wantAsOf:   "2026-02-01T12:00:00Z",
		},
		{
			name:       "all fail no last good",
			redis:      &fakeRedis{err: errors.New("connection refused")},
			objects:    &fakeObjects{err: errors.New("no such key")},
			wantStatus: http.StatusServiceUnavailable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := store.New(tt.redis, tt.objects, "stats:current:v2", "ssl-proxy-stats", "stats/latest.json")
			if tt.prime {
				// Populate last-good through a healthy pass, then break
				// both backends to prove the in-process copy is used.
				rv, re := tt.redis.value, tt.redis.err
				ov, oe := tt.objects.value, tt.objects.err
				tt.redis.value, tt.redis.err = valid, nil
				tt.objects.value, tt.objects.err = nil, nil
				if _, err := st.Snapshot(context.Background()); err != nil {
					t.Fatalf("prime: %v", err)
				}
				tt.redis.value, tt.redis.err = rv, re
				tt.objects.value, tt.objects.err = ov, oe
			}
			rec := doGet(t, newServer(st).Handler(), "/public/stats", "")
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if tt.wantStatus == http.StatusOK {
				var body map[string]any
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
					t.Fatalf("body not JSON: %v", err)
				}
				if body["asOf"] != tt.wantAsOf {
					t.Fatalf("asOf = %v, want %s", body["asOf"], tt.wantAsOf)
				}
				return
			}
			if rec.Body.String() != `{"error":"Metrics unavailable"}` {
				t.Fatalf("body = %s", rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "ssl-proxy-minio") || strings.Contains(rec.Body.String(), "redis") {
				t.Fatalf("body leaks store details: %s", rec.Body.String())
			}
		})
	}
}

func TestAllowlistStripsExtraKeys(t *testing.T) {
	raw := []byte(`{
		"asOf": "2026-02-01T12:00:00Z",
		"internalHost": "ssl-proxy-minio-api:9000",
		"secrets": "nope",
		"peakRecordsDay": 3,
		"liveStrip": {
			"pendingLedgerCount": 1,
			"debugDump": "raw"
		},
		"throughput24h": {
			"bucket": "hour",
			"series": [{"bucketStart": "2026-02-01T10:00:00Z", "records": 2, "internalNote": "x"}],
			"rawQuery": "select 1"
		},
		"notARealSection": {"boom": true}
	}`)
	rec := doGet(t, newServer(stubStore{raw: raw}).Handler(), "/public/stats", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, banned := range []string{"internalHost", "secrets", "debugDump", "rawQuery", "notARealSection", "internalNote", "ssl-proxy-minio-api", "select 1"} {
		if strings.Contains(body, banned) {
			t.Fatalf("body contains %q: %s", banned, body)
		}
	}

	var top map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &top); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if top["peakRecordsDay"] != float64(3) {
		t.Fatalf("peakRecordsDay = %v, want 3", top["peakRecordsDay"])
	}
	strip, ok := top["liveStrip"].(map[string]any)
	if !ok {
		t.Fatalf("liveStrip missing or wrong type: %v", top["liveStrip"])
	}
	if strip["pendingLedgerCount"] != float64(1) {
		t.Fatalf("pendingLedgerCount = %v", strip["pendingLedgerCount"])
	}
	if _, ok := strip["debugDump"]; ok {
		t.Fatalf("debugDump survived allowlist: %v", strip)
	}
}

func TestMissingFieldsStayMissing(t *testing.T) {
	raw := []byte(`{
		"asOf": "2026-02-01T12:00:00Z",
		"liveStrip": {"pendingLedgerCount": 2},
		"lifetimeTotals": {"recordsTotal": 9}
	}`)
	rec := doGet(t, newServer(stubStore{raw: raw}).Handler(), "/public/stats", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var top map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &top); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}

	for _, k := range []string{
		"peaksComputedAt", "peakRecordsDay", "peakRecordsDayDate",
		"peakRecordsWeek", "peakRecordsWeekStart", "peakRecordsWeekEnd",
		"throughput24h", "throughput7d",
	} {
		if _, ok := top[k]; ok {
			t.Fatalf("missing key %q was invented: %v", k, top[k])
		}
	}

	strip := top["liveStrip"].(map[string]any)
	for _, k := range []string{"ingestProcessedRatePerSec", "lastIngestSuccessAt", "backpressureActive"} {
		if _, ok := strip[k]; ok {
			t.Fatalf("missing liveStrip key %q was invented: %v", k, strip)
		}
	}
	if strip["pendingLedgerCount"] != float64(2) {
		t.Fatalf("pendingLedgerCount = %v, want 2", strip["pendingLedgerCount"])
	}

	totals := top["lifetimeTotals"].(map[string]any)
	for _, k := range []string{"daysCounted", "computedAt"} {
		if _, ok := totals[k]; ok {
			t.Fatalf("missing lifetimeTotals key %q was invented: %v", k, totals)
		}
	}
	if totals["recordsTotal"] != float64(9) {
		t.Fatalf("recordsTotal = %v, want 9", totals["recordsTotal"])
	}
}

func TestNeverSynthesizesZerosForEmptySnapshotFields(t *testing.T) {
	raw := []byte(`{"asOf": "2026-02-01T12:00:00Z", "throughput24h": {"bucket": "hour"}}`)
	rec := doGet(t, newServer(stubStore{raw: raw}).Handler(), "/public/stats", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var top map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &top); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	series := top["throughput24h"].(map[string]any)
	if _, ok := series["series"]; ok {
		t.Fatalf("series invented where absent: %v", series)
	}
}

func TestReadyAndLiveAlwaysOK(t *testing.T) {
	broken := stubStore{err: errors.New("everything is down")}
	h := newServer(broken).Handler()
	for _, path := range []string{"/ready", "/live"} {
		rec := doGet(t, h, path, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d, want 200 even with broken stores", path, rec.Code)
		}
		if rec.Body.String() != "ok" {
			t.Fatalf("%s body = %q, want ok", path, rec.Body.String())
		}
	}
}

func TestCORSPreflightAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodOptions, "/public/stats", nil)
	req.Header.Set("Origin", "https://rclabs.uk")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec := httptest.NewRecorder()
	newServer(stubStore{raw: []byte(validSnapshot)}).Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://rclabs.uk" {
		t.Fatalf("ACAO = %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, "GET") {
		t.Fatalf("ACAM = %q", got)
	}
	if got := rec.Header().Get("Vary"); !strings.Contains(got, "Origin") {
		t.Fatalf("Vary = %q", got)
	}
}

func TestCORSPreflightDisallowedOrigin(t *testing.T) {
	req := httptest.NewRequest(http.MethodOptions, "/public/stats", nil)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec := httptest.NewRecorder()
	newServer(stubStore{raw: []byte(validSnapshot)}).Handler().ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("ACAO = %q for disallowed origin, want empty", got)
	}
}

func TestCORSOnStatsResponse(t *testing.T) {
	rec := doGet(t, newServer(stubStore{raw: []byte(validSnapshot)}).Handler(), "/public/stats", "https://www.rclabs.uk")
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://www.rclabs.uk" {
		t.Fatalf("ACAO = %q", got)
	}

	rec = doGet(t, newServer(stubStore{raw: []byte(validSnapshot)}).Handler(), "/public/stats", "https://evil.example")
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("ACAO = %q for disallowed origin, want empty", got)
	}
}

func TestHealthShape(t *testing.T) {
	rec := doGet(t, newServer(stubStore{redisOK: true, minioOK: false}).Handler(), "/health", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body map[string]bool
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if !body["redis"] || body["minio"] {
		t.Fatalf("health = %v, want redis=true minio=false", body)
	}
}

func TestSanitizeRejectsMissingAsOf(t *testing.T) {
	if _, err := sanitizeSnapshot([]byte(`{"peakRecordsDay":1}`)); err == nil {
		t.Fatal("sanitizeSnapshot accepted payload without asOf")
	}
	if _, err := sanitizeSnapshot([]byte(`{"asOf":""}`)); err == nil {
		t.Fatal("sanitizeSnapshot accepted empty asOf")
	}
	if _, err := sanitizeSnapshot([]byte(`not json`)); err == nil {
		t.Fatal("sanitizeSnapshot accepted non-JSON")
	}
}
