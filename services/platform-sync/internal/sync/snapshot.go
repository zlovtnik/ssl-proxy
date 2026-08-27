package sync

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/contract"
	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/log"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const defaultSnapshotPath = "/run/platform-sync/last-known-good.json"

type SnapshotEntry struct {
	Name            string `json:"name"`
	Kind            string `json:"kind"`
	ResourceVersion string `json:"resourceVersion"`
	Checksum        string `json:"checksum"`
}

type Snapshot struct {
	Timestamp time.Time       `json:"timestamp"`
	Entries   []SnapshotEntry `json:"entries"`
}

// saveSnapshot records only resource versions and checksums on disk. Secret
// data used for an immediate rollback remains in memory and is never persisted.
func saveSnapshot(logger *log.Logger, inputs []contract.Input, objects []*unstructured.Unstructured) error {
	if len(inputs) != len(objects) {
		return fmt.Errorf("snapshot input/object count mismatch")
	}
	entries := make([]SnapshotEntry, 0, len(objects))
	for i, item := range objects {
		entries = append(entries, SnapshotEntry{
			Name:            inputs[i].Name,
			Kind:            inputs[i].Kind,
			ResourceVersion: item.GetResourceVersion(),
			Checksum:        computeChecksum(item.Object),
		})
	}
	snapshot := Snapshot{Timestamp: time.Now().UTC(), Entries: entries}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}
	path := os.Getenv("SYNC_SNAPSHOT_PATH")
	if path == "" {
		path = defaultSnapshotPath
	}
	if err := writeFileAtomically(path, data, 0o600); err != nil {
		return err
	}
	logger.Info("snapshot saved", "path", path, "entries", len(entries))
	return nil
}

func computeChecksum(obj map[string]interface{}) string {
	data, err := json.Marshal(obj)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum)
}

func writeFileAtomically(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".platform-sync-*")
	if err != nil {
		return fmt.Errorf("create temporary file for %s: %w", path, err)
	}
	tempName := temp.Name()
	defer func() { _ = os.Remove(tempName) }()
	if err := temp.Chmod(mode); err != nil {
		_ = temp.Close()
		return fmt.Errorf("set mode on temporary file for %s: %w", path, err)
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write temporary file for %s: %w", path, err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("sync temporary file for %s: %w", path, err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary file for %s: %w", path, err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}
