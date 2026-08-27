package sync

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

const (
	lockName = "platform-sync-lock"
	lockKey  = "heldBy"
)

type Lock struct {
	dynClient      dynamic.Interface
	namespace      string
	resourceVersion string
}

func acquireLock(ctx context.Context, logger *log.Logger, ttlSeconds int) (*Lock, error) {
	dynClient, ns, err := newDynamicClient()
	if err != nil {
		return nil, err
	}

	cm := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]interface{}{
				"name":      lockName,
				"namespace": ns,
				"annotations": map[string]interface{}{
					"platform-sync/locked-at": time.Now().UTC().Format(time.RFC3339),
					"platform-sync/lock-ttl":  fmt.Sprintf("%ds", ttlSeconds),
				},
			},
			"data": map[string]interface{}{
				lockKey: hostname(),
			},
		},
	}

	existing, err := dynClient.Resource(configMapResource).Namespace(ns).Get(ctx, lockName, metav1.GetOptions{})
	if err != nil {
		logger.Info("creating lock", "name", lockName)
		created, err := dynClient.Resource(configMapResource).Namespace(ns).Create(ctx, cm, metav1.CreateOptions{
			FieldManager: "platform-sync",
		})
		if err != nil {
			return nil, fmt.Errorf("create lock: %w", err)
		}
		return &Lock{
			dynClient:      dynClient,
			namespace:      ns,
			resourceVersion: created.GetResourceVersion(),
		}, nil
	}

	lockedAt := existing.GetAnnotations()["platform-sync/locked-at"]
	ttlStr := existing.GetAnnotations()["platform-sync/lock-ttl"]
	if lockedAt != "" && ttlStr != "" {
		lockedTime, err := time.Parse(time.RFC3339, lockedAt)
		if err == nil {
			var ttl time.Duration
			fmt.Sscanf(ttlStr, "%ds", &ttl)
			if time.Since(lockedTime) < ttl {
				holder, _, _ := unstructured.NestedString(existing.Object, "data", lockKey)
				if holder != hostname() {
					return nil, fmt.Errorf("lock held by %s", holder)
				}
			}
		}
	}

	cm.Object["metadata"].(map[string]interface{})["resourceVersion"] = existing.GetResourceVersion()
	updated, err := dynClient.Resource(configMapResource).Namespace(ns).Update(ctx, cm, metav1.UpdateOptions{
		FieldManager: "platform-sync",
	})
	if err != nil {
		return nil, fmt.Errorf("update lock: %w", err)
	}

	return &Lock{
		dynClient:      dynClient,
		namespace:      ns,
		resourceVersion: updated.GetResourceVersion(),
	}, nil
}

func releaseLock(ctx context.Context, logger *log.Logger, lock *Lock) {
	if lock == nil {
		return
	}

	existing, err := lock.dynClient.Resource(configMapResource).Namespace(lock.namespace).Get(ctx, lockName, metav1.GetOptions{})
	if err != nil {
		logger.Warn("failed to read lock for release", "error", err)
		return
	}

	if existing.GetResourceVersion() != lock.resourceVersion {
		logger.Warn("lock was modified since acquisition, skipping release")
		return
	}

	err = lock.dynClient.Resource(configMapResource).Namespace(lock.namespace).Delete(ctx, lockName, metav1.DeleteOptions{
		Preconditions: &metav1.Preconditions{
			ResourceVersion: &lock.resourceVersion,
		},
	})
	if err != nil {
		logger.Warn("failed to release lock", "error", err)
	}
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

var configMapResource = schema.GroupVersionResource{
	Group:    "",
	Version:  "v1",
	Resource: "configmaps",
}
