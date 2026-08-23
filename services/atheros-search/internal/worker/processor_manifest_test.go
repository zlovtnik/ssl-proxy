package worker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type processorManifest struct {
	Processors []struct {
		ID             string `json:"id"`
		Owner          string `json:"owner"`
		DefaultEnabled bool   `json:"default_enabled"`
	} `json:"processors"`
}

func TestSharedManifestAssignsAtherosSearchProcessorsExactlyOnce(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	manifestPath := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", "..", "..", "sql", "postgres", "contracts", "processors.json"))
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read processor manifest: %v", err)
	}
	var manifest processorManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("decode processor manifest: %v", err)
	}

	owned := make(map[string]int)
	all := make(map[string]int)
	for _, processor := range manifest.Processors {
		all[processor.ID]++
		if processor.DefaultEnabled {
			t.Errorf("processor %q must be disabled by default", processor.ID)
		}
		if processor.Owner == "atheros-search" {
			owned[processor.ID]++
		}
	}
	for id, count := range all {
		if count != 1 {
			t.Errorf("processor %q has %d manifest owners", id, count)
		}
	}
	expected := map[string]int{"embedding-completer": 1, "embedding-lease-recovery": 1}
	if len(owned) != len(expected) {
		t.Fatalf("unexpected Atheros Search ownership: %#v", owned)
	}
	for id, count := range expected {
		if owned[id] != count {
			t.Errorf("processor %q ownership = %d, want %d", id, owned[id], count)
		}
	}
}

func TestGroupJobsByKindKeepsEveryJob(t *testing.T) {
	jobs := []Job{{JobID: "1", EmbeddingKind: "event"}, {JobID: "2", EmbeddingKind: "device"}, {JobID: "3", EmbeddingKind: "event"}}
	grouped := groupJobsByKind(jobs)
	if len(grouped["event"]) != 2 || len(grouped["device"]) != 1 {
		t.Fatalf("unexpected groups: %#v", grouped)
	}
}
