package sync

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/contract"
	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
)

const fieldManager = "platform-sync"

type objectClient interface {
	Get(context.Context, schema.GroupVersionResource, string, string, metav1.GetOptions) (*unstructured.Unstructured, error)
	Update(context.Context, schema.GroupVersionResource, string, *unstructured.Unstructured, metav1.UpdateOptions) (*unstructured.Unstructured, error)
}

type dynamicObjectClient struct {
	client dynamic.Interface
}

func (c dynamicObjectClient) Get(ctx context.Context, resource schema.GroupVersionResource, namespace, name string, options metav1.GetOptions) (*unstructured.Unstructured, error) {
	return c.client.Resource(resource).Namespace(namespace).Get(ctx, name, options)
}

func (c dynamicObjectClient) Update(ctx context.Context, resource schema.GroupVersionResource, namespace string, obj *unstructured.Unstructured, options metav1.UpdateOptions) (*unstructured.Unstructured, error) {
	return c.client.Resource(resource).Namespace(namespace).Update(ctx, obj, options)
}

// WriteAll performs a two-phase Kubernetes operation. Every declared object is
// fetched and accepted by server-side dry-run before any real object update.
// If a later update still fails because cluster state changed, already-applied
// objects are restored from the in-memory preflight snapshot.
func WriteAll(ctx context.Context, logger *log.Logger, c *contract.Contract, secretData map[string]map[string][]byte, lockTTL int, dryRun bool) error {
	client, err := newObjectClient()
	if err != nil {
		return fmt.Errorf("kubernetes client: %w", err)
	}
	return writeAllWithClient(ctx, logger, client, c, secretData, lockTTL, dryRun)
}

func writeAllWithClient(ctx context.Context, logger *log.Logger, client objectClient, c *contract.Contract, secretData map[string]map[string][]byte, lockTTL int, dryRun bool) error {
	lock, err := acquireLock(ctx, logger, client, c.Namespace, lockTTL, dryRun)
	if err != nil {
		return fmt.Errorf("acquire lock: %w", err)
	}
	if lock != nil {
		defer releaseLock(ctx, logger, client, lock)
	}

	desired, previous, err := prepareObjects(ctx, client, c, secretData)
	if err != nil {
		return err
	}

	for i, input := range c.Inputs {
		if _, err := client.Update(ctx, resourceForKind(input.Kind), c.Namespace, desired[i].DeepCopy(), metav1.UpdateOptions{
			DryRun:       []string{metav1.DryRunAll},
			FieldManager: fieldManager,
		}); err != nil {
			return fmt.Errorf("server-side dry-run %s/%s: %w", input.Kind, input.Name, err)
		}
		logger.Info("server-side dry-run accepted", "kind", input.Kind, "name", input.Name)
	}
	if dryRun {
		return nil
	}

	if err := saveSnapshot(logger, c.Inputs, previous); err != nil {
		return fmt.Errorf("save pre-write snapshot: %w", err)
	}

	applied := make([]int, 0, len(desired))
	for i, input := range c.Inputs {
		updated, updateErr := client.Update(ctx, resourceForKind(input.Kind), c.Namespace, desired[i], metav1.UpdateOptions{
			FieldManager: fieldManager,
		})
		if updateErr != nil {
			rollbackErr := rollbackObjects(ctx, logger, client, c, previous, applied)
			return errors.Join(fmt.Errorf("write %s/%s: %w", input.Kind, input.Name, updateErr), rollbackErr)
		}
		desired[i] = updated
		applied = append(applied, i)
		logger.Info("wrote object", "kind", input.Kind, "name", input.Name)
	}

	return nil
}

func prepareObjects(ctx context.Context, client objectClient, c *contract.Contract, secretData map[string]map[string][]byte) ([]*unstructured.Unstructured, []*unstructured.Unstructured, error) {
	desired := make([]*unstructured.Unstructured, 0, len(c.Inputs))
	previous := make([]*unstructured.Unstructured, 0, len(c.Inputs))
	for _, input := range c.Inputs {
		resource := resourceForKind(input.Kind)
		current, err := client.Get(ctx, resource, c.Namespace, input.Name, metav1.GetOptions{})
		if err != nil {
			return nil, nil, fmt.Errorf("read existing %s/%s: %w", input.Kind, input.Name, err)
		}
		data, ok := secretData[input.Name]
		if !ok {
			return nil, nil, fmt.Errorf("validated data missing for %s/%s", input.Kind, input.Name)
		}
		obj, err := desiredObject(current, input, data)
		if err != nil {
			return nil, nil, err
		}
		previous = append(previous, current.DeepCopy())
		desired = append(desired, obj)
	}
	return desired, previous, nil
}

func desiredObject(current *unstructured.Unstructured, input contract.Input, values map[string][]byte) (*unstructured.Unstructured, error) {
	declared := make(map[string]interface{}, len(input.Keys))
	for _, key := range input.Keys {
		value, ok := values[key]
		if !ok {
			return nil, fmt.Errorf("validated data for %s/%s missing declared key %s", input.Kind, input.Name, key)
		}
		if input.Kind == "Secret" {
			declared[key] = base64.StdEncoding.EncodeToString(value)
		} else {
			declared[key] = string(value)
		}
	}

	obj := current.DeepCopy()
	obj.SetAPIVersion("v1")
	obj.SetKind(input.Kind)
	if err := unstructured.SetNestedMap(obj.Object, declared, "data"); err != nil {
		return nil, fmt.Errorf("set data for %s/%s: %w", input.Kind, input.Name, err)
	}
	if input.Kind == "Secret" {
		obj.Object["type"] = input.Type
	}
	return obj, nil
}

func rollbackObjects(ctx context.Context, logger *log.Logger, client objectClient, c *contract.Contract, previous []*unstructured.Unstructured, applied []int) error {
	var rollbackErrors []error
	for n := len(applied) - 1; n >= 0; n-- {
		i := applied[n]
		input := c.Inputs[i]
		resource := resourceForKind(input.Kind)
		current, err := client.Get(ctx, resource, c.Namespace, input.Name, metav1.GetOptions{})
		if err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("read %s/%s for rollback: %w", input.Kind, input.Name, err))
			continue
		}
		restore := previous[i].DeepCopy()
		restore.SetResourceVersion(current.GetResourceVersion())
		if _, err := client.Update(ctx, resource, c.Namespace, restore, metav1.UpdateOptions{FieldManager: fieldManager}); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("restore %s/%s: %w", input.Kind, input.Name, err))
			continue
		}
		logger.Warn("restored object after partial sync failure", "kind", input.Kind, "name", input.Name)
	}
	if len(rollbackErrors) > 0 {
		return fmt.Errorf("rollback incomplete: %w", errors.Join(rollbackErrors...))
	}
	return nil
}

func newObjectClient() (objectClient, error) {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = "/run/platform-sync/kubeconfig"
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("build config: %w", err)
	}
	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("dynamic client: %w", err)
	}
	return dynamicObjectClient{client: dynClient}, nil
}

func resourceForKind(kind string) schema.GroupVersionResource {
	switch kind {
	case "Secret":
		return schema.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}
	case "ConfigMap":
		return configMapResource
	default:
		return schema.GroupVersionResource{Group: "", Version: "v1", Resource: "invalid"}
	}
}
