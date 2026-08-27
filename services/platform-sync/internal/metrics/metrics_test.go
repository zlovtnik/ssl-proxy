package metrics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRecorderPersistsCountersAcrossProcesses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics.prom")
	t.Setenv("SYNC_METRICS_PATH", path)
	first := NewRecorder()
	first.SetRunStart(time.Now().Add(-time.Second))
	if err := first.RecordRun("success", 19); err != nil {
		t.Fatal(err)
	}
	second := NewRecorder()
	if err := second.RecordRun("success", 19); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `platform_sync_runs_total{result="success"} 2`) {
		t.Fatalf("counter was not persisted: %s", data)
	}
}
