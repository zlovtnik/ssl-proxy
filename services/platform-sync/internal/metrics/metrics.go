package metrics

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

type Server struct {
	mux    *http.ServeMux
	server *http.Server
	mu     sync.RWMutex
	counts map[string]int
}

func NewServer() *Server {
	s := &Server{
		mux:    http.NewServeMux(),
		counts: make(map[string]int),
	}
	s.server = &http.Server{
		Addr:    "127.0.0.1:9105",
		Handler: s.mux,
	}
	s.mux.HandleFunc("/metrics", s.handleMetrics)
	s.mux.HandleFunc("/health", s.handleHealth)
	return s
}

func (s *Server) ListenAndServe() error {
	return s.server.ListenAndServe()
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "# HELP sync_runs_total Total number of sync runs\n")
	fmt.Fprintf(w, "# TYPE sync_runs_total counter\n")
	for result, count := range s.counts {
		fmt.Fprintf(w, "sync_runs_total{result=\"%s\"} %d\n", result, count)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

var (
	runStart     time.Time
	runStartOnce sync.Once
)

func SetRunStart(t time.Time) {
	runStartOnce.Do(func() {
		runStart = t
	})
}

func RecordRun(result string) {
}

func RecordInputsWritten(count int) {
}
