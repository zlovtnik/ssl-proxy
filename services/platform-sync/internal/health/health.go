package health

import (
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"time"
)

type Server struct {
	mux    *http.ServeMux
	server *http.Server
	mu     sync.RWMutex
	status string
	message string
}

type HealthStatus struct {
	Status    string    `json:"status"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

func NewServer() *Server {
	s := &Server{
		mux:    http.NewServeMux(),
		status: "starting",
		message: "initializing",
	}
	s.server = &http.Server{
		Addr:    "127.0.0.1:9106",
		Handler: s.mux,
	}
	s.mux.HandleFunc("/healthz", s.handleHealthz)
	return s
}

func (s *Server) ListenAndServe() error {
	return s.server.ListenAndServe()
}

func (s *Server) SetStatus(status, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = status
	s.message = message

	statusData := HealthStatus{
		Status:    status,
		Message:   message,
		Timestamp: time.Now().UTC(),
	}
	data, err := json.Marshal(statusData)
	if err == nil {
		os.WriteFile("/run/platform-sync/health.json", data, 0600)
	}
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(HealthStatus{
		Status:    s.status,
		Message:   s.message,
		Timestamp: time.Now().UTC(),
	})
}
