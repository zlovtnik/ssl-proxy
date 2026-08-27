package health

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRecorderWritesMachineReadableStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "health.json")
	t.Setenv("SYNC_HEALTH_PATH", path)
	if err := NewRecorder().SetStatus("ok", "sync complete"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var status Status
	if err := json.Unmarshal(data, &status); err != nil {
		t.Fatal(err)
	}
	if status.Status != "ok" || status.Message != "sync complete" || status.Timestamp.IsZero() {
		t.Fatalf("unexpected health status: %#v", status)
	}
}
