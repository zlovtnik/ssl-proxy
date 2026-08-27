package health

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const defaultHealthPath = "/run/platform-sync/health.json"

type Recorder struct {
	mu   sync.Mutex
	path string
}

type Status struct {
	Status    string    `json:"status"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

func NewRecorder() *Recorder {
	path := strings.TrimSpace(os.Getenv("SYNC_HEALTH_PATH"))
	if path == "" {
		path = defaultHealthPath
	}
	return &Recorder{path: path}
}

func (r *Recorder) SetStatus(status, message string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	data, err := json.Marshal(Status{Status: status, Message: message, Timestamp: time.Now().UTC()})
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(r.path), ".health-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer func() { _ = os.Remove(tempName) }()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempName, r.path)
}
