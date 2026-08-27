package sync

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/contract"
	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/log"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
)

func WriteAll(ctx context.Context, logger *log.Logger, c *contract.Contract, secretData map[string]map[string][]byte, lockTTL int) error {
	lock, err := acquireLock(ctx, logger, lockTTL)
	if err != nil {
		return fmt.Errorf("acquire lock: %w", err)
	}
	defer releaseLock(ctx, logger, lock)

	dynClient, ns, err := newDynamicClient()
	if err != nil {
		return fmt.Errorf("kubernetes client: %w", err)
	}

	for _, input := range c.Inputs {
		data := secretData[input.Name]
		if err := writeObject(ctx, logger, dynClient, ns, input, data); err != nil {
			return fmt.Errorf("write %s: %w", input.Name, err)
		}
		logger.Info("wrote object", "kind", input.Kind, "name", input.Name)
	}

	return nil
}

func writeObject(ctx context.Context, logger *log.Logger, dynClient dynamic.Interface, ns string, input contract.Input, data map[string][]byte) error {
	gvk := schema.GroupVersionKind{Group: "", Version: "v1", Kind: input.Kind}
	resource := gvkToResource(gvk)

	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(gvk)
	obj.SetName(input.Name)
	obj.SetNamespace(ns)

	if input.Kind == "Secret" {
		secret := &corev1.Secret{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Secret",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      input.Name,
				Namespace: ns,
			},
			Type: corev1.SecretType(input.Type),
			Data: make(map[string][]byte),
		}
		for k, v := range data {
			secret.Data[k] = v
		}
		obj.Object = secretToMap(secret)
	} else {
		cm := &corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "ConfigMap",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      input.Name,
				Namespace: ns,
			},
			Data: make(map[string]string),
		}
		for k, v := range data {
			cm.Data[k] = string(v)
		}
		obj.Object = configMapToMap(cm)
	}

	existing, err := dynClient.Resource(resource).Namespace(ns).Get(ctx, input.Name, metav1.GetOptions{})
	if err != nil {
		logger.Info("creating object", "kind", input.Kind, "name", input.Name)
		_, err = dynClient.Resource(resource).Namespace(ns).Create(ctx, obj, metav1.CreateOptions{
			FieldManager: "platform-sync",
		})
		return err
	}

	patchData, err := buildPatch(obj, existing)
	if err != nil {
		return fmt.Errorf("build patch: %w", err)
	}

	_, err = dynClient.Resource(resource).Namespace(ns).Patch(ctx, input.Name,
		types.ApplyPatchType, patchData, metav1.PatchOptions{
			FieldManager: "platform-sync",
		})
	return err
}

func newDynamicClient() (dynamic.Interface, string, error) {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = "/run/platform-sync/kubeconfig"
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, "", fmt.Errorf("build config: %w", err)
	}

	ns := os.Getenv("SYNC_NAMESPACE")
	if ns == "" {
		ns = "prod-ssl-proxy"
	}

	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, "", fmt.Errorf("dynamic client: %w", err)
	}

	return dynClient, ns, nil
}

func gvkToResource(gvk schema.GroupVersionKind) schema.GroupVersionResource {
	switch gvk.Kind {
	case "Secret":
		return schema.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}
	case "ConfigMap":
		return schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}
	default:
		return schema.GroupVersionResource{Group: "", Version: "v1", Resource: "unknown"}
	}
}

func secretToMap(s *corev1.Secret) map[string]interface{} {
	data := make(map[string]interface{})
	for k, v := range s.Data {
		data[k] = v
	}
	return map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]interface{}{
			"name":      s.Name,
			"namespace": s.Namespace,
		},
		"type": string(s.Type),
		"data": data,
	}
}

func configMapToMap(cm *corev1.ConfigMap) map[string]interface{} {
	data := make(map[string]interface{})
	for k, v := range cm.Data {
		data[k] = v
	}
	return map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]interface{}{
			"name":      cm.Name,
			"namespace": cm.Namespace,
		},
		"data": data,
	}
}

func buildPatch(desired, existing *unstructured.Unstructured) ([]byte, error) {
	desiredData := desired.Object
	existingData := existing.Object

	for key := range existingData {
		if key == "metadata" {
			continue
		}
		if _, ok := desiredData[key]; !ok {
			desiredData[key] = existingData[key]
		}
	}

	if meta, ok := desiredData["metadata"].(map[string]interface{}); ok {
		if existingMeta, ok := existingData["metadata"].(map[string]interface{}); ok {
			if existingMeta["resourceVersion"] != nil {
				meta["resourceVersion"] = existingMeta["resourceVersion"]
			}
		}
	}

	return json.Marshal(desiredData)
}
