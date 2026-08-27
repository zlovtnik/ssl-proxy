package sync

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const snapshotPath = "/run/platform-sync/last-known-good.json"

type SnapshotEntry struct {
	Name            string `json:"name"`
	Kind            string `json:"kind"`
	ResourceVersion string `json:"resourceVersion"`
	Checksum        string `json:"checksum"`
}

type Snapshot struct {
	Timestamp time.Time        `json:"timestamp"`
	Entries   []SnapshotEntry `json:"entries"`
}

func takeSnapshot(ctx context.Context, logger *log.Logger) *Snapshot {
	dynClient, ns, err := newDynamicClient()
	if err != nil {
		logger.Warn("failed to create client for snapshot", "error", err)
		return nil
	}

	entries := []SnapshotEntry{}

	for _, resource := range []string{"secrets", "configmaps"} {
		list, err := dynClient.Resource(schemaForResource(resource)).Namespace(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.Warn("failed to list resources for snapshot", "resource", resource, "error", err)
			continue
		}

		for _, item := range list.Items {
			entry := SnapshotEntry{
				Name:            item.GetName(),
				Kind:            resource[:len(resource)-1],
				ResourceVersion: item.GetResourceVersion(),
			}
			checksum := computeChecksum(item.Object)
			entry.Checksum = checksum
			entries = append(entries, entry)
		}
	}

	snapshot := &Snapshot{
		Timestamp: time.Now().UTC(),
		Entries:   entries,
	}

	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		logger.Warn("failed to marshal snapshot", "error", err)
		return nil
	}

	if err := os.WriteFile(snapshotPath, data, 0600); err != nil {
		logger.Warn("failed to write snapshot", "path", snapshotPath, "error", err)
		return nil
	}

	logger.Info("snapshot saved", "path", snapshotPath, "entries", len(entries))
	return snapshot
}

func computeChecksum(obj map[string]interface{}) string {
	data, err := json.Marshal(obj)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h)
}

func schemaForResource(resource string) schema.GroupVersionResource {
	switch resource {
	case "secrets":
		return schema.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}
	case "configmaps":
		return schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}
	default:
		return schema.GroupVersionResource{Group: "", Version: "v1", Resource: resource}
	}
}
