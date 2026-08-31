package sync

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/contract"
	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type fakeObjectClient struct {
	objects  map[string]*unstructured.Unstructured
	updates  []fakeUpdate
	failName string
	failed   bool
	nextRV   int
}

type fakeUpdate struct {
	name   string
	dryRun bool
}

func (f *fakeObjectClient) Get(_ context.Context, resource schema.GroupVersionResource, _ string, name string, _ metav1.GetOptions) (*unstructured.Unstructured, error) {
	obj, ok := f.objects[resource.Resource+"/"+name]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return obj.DeepCopy(), nil
}

func (f *fakeObjectClient) Update(_ context.Context, resource schema.GroupVersionResource, _ string, obj *unstructured.Unstructured, options metav1.UpdateOptions) (*unstructured.Unstructured, error) {
	dryRun := len(options.DryRun) > 0
	f.updates = append(f.updates, fakeUpdate{name: obj.GetName(), dryRun: dryRun})
	if !dryRun && obj.GetName() == f.failName && !f.failed {
		f.failed = true
		return nil, errors.New("injected update failure")
	}
	result := obj.DeepCopy()
	if !dryRun {
		f.nextRV++
		result.SetResourceVersion(fmt.Sprint(f.nextRV))
		f.objects[resource.Resource+"/"+obj.GetName()] = result.DeepCopy()
	}
	return result, nil
}

func TestWriteAllDryRunPreflightsEveryObjectWithoutMutation(t *testing.T) {
	client, c, data := writerFixture()
	if err := writeAllWithClient(context.Background(), log.New(), client, c, data, 600, true, time.Unix(1234, 0)); err != nil {
		t.Fatal(err)
	}
	for _, update := range client.updates {
		if !update.dryRun {
			t.Fatalf("dry-run made a real update: %#v", client.updates)
		}
	}
	firstData, found, err := unstructured.NestedStringMap(client.objects["secrets/one"].Object, "data")
	if err != nil || !found {
		t.Fatalf("read test Secret data: found=%t err=%v", found, err)
	}
	if firstData["old"] != "b2xk" {
		t.Fatalf("dry-run mutated object: %#v", firstData)
	}
}

func TestWriteAllRollsBackEarlierUpdatesAfterApplyFailure(t *testing.T) {
	client, c, data := writerFixture()
	client.failName = "two"
	t.Setenv("SYNC_SNAPSHOT_PATH", filepath.Join(t.TempDir(), "snapshot.json"))
	if err := writeAllWithClient(context.Background(), log.New(), client, c, data, 600, false, time.Unix(1234, 0)); err == nil {
		t.Fatal("injected apply failure was not returned")
	}
	firstData, found, nestedErr := unstructured.NestedStringMap(client.objects["secrets/one"].Object, "data")
	if nestedErr != nil || !found {
		t.Fatalf("read restored Secret data: found=%t err=%v", found, nestedErr)
	}
	if firstData["old"] != "b2xk" || len(firstData) != 1 {
		t.Fatalf("first object was not restored: %#v", firstData)
	}
}

func TestDesiredObjectCopiesOnlyDeclaredKeys(t *testing.T) {
	current := object("Secret", "target", map[string]interface{}{"old": "b2xk"})
	desired, err := desiredObject(current, contract.Input{Kind: "Secret", Name: "target", Type: "Opaque", Keys: []string{"declared"}}, map[string][]byte{
		"declared": []byte("kept"), "undeclared": []byte("drop"),
	})
	if err != nil {
		t.Fatal(err)
	}
	values, found, nestedErr := unstructured.NestedStringMap(desired.Object, "data")
	if nestedErr != nil || !found {
		t.Fatalf("read desired Secret data: found=%t err=%v", found, nestedErr)
	}
	if len(values) != 1 || values["declared"] != "a2VwdA==" {
		t.Fatalf("unexpected desired data: %#v", values)
	}
}

func TestWriteAllPublishesReadinessLast(t *testing.T) {
	client, c, data := writerFixture()
	t.Setenv("SYNC_SNAPSHOT_PATH", filepath.Join(t.TempDir(), "snapshot.json"))
	if err := writeAllWithClient(context.Background(), log.New(), client, c, data, 600, false, time.Unix(1234, 0)); err != nil {
		t.Fatal(err)
	}
	if got := client.updates[len(client.updates)-1]; got.name != "platform-ready" || got.dryRun {
		t.Fatalf("readiness was not the final real update: %#v", client.updates)
	}
	values, found, err := unstructured.NestedStringMap(client.objects["configmaps/platform-ready"].Object, "data")
	if err != nil || !found {
		t.Fatalf("read readiness data: found=%t err=%v", found, err)
	}
	if values["ready"] != "true" || values["contract-sha256"] != "abc123" || values["last-success-unix"] != "1234" {
		t.Fatalf("unexpected readiness data: %#v", values)
	}
}

func TestActiveLockTreatsTTLAsSeconds(t *testing.T) {
	now := time.Now().UTC()
	lock := object("ConfigMap", lockName, map[string]interface{}{lockKey: "host:1"})
	lock.SetAnnotations(map[string]string{
		lockedAtKey: now.Add(-time.Second).Format(time.RFC3339Nano), lockTTLSecondsKey: strconv.Itoa(600),
	})
	active, _, err := activeLock(lock, now)
	if err != nil {
		t.Fatal(err)
	}
	if !active {
		t.Fatal("600-second lock expired after one second")
	}
	active, _, err = activeLock(lock, now.Add(601*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if active {
		t.Fatal("600-second lock remained active after 601 seconds")
	}
}

func writerFixture() (*fakeObjectClient, *contract.Contract, map[string]map[string][]byte) {
	client := &fakeObjectClient{objects: map[string]*unstructured.Unstructured{}, nextRV: 3}
	client.objects["configmaps/"+lockName] = object("ConfigMap", lockName, map[string]interface{}{lockKey: ""})
	client.objects["secrets/one"] = object("Secret", "one", map[string]interface{}{"old": "b2xk"})
	client.objects["configmaps/two"] = object("ConfigMap", "two", map[string]interface{}{"old": "old"})
	client.objects["configmaps/platform-ready"] = object("ConfigMap", "platform-ready", map[string]interface{}{})
	c := &contract.Contract{Namespace: "prod-ssl-proxy", Readiness: contract.Readiness{ConfigMapName: "platform-ready"}, SHA256: "abc123", Inputs: []contract.Input{
		{Kind: "Secret", Name: "one", Type: "Opaque", Keys: []string{"new"}},
		{Kind: "ConfigMap", Name: "two", Keys: []string{"new"}},
	}}
	data := map[string]map[string][]byte{"one": {"new": []byte("secret")}, "two": {"new": []byte("config")}}
	return client, c, data
}

func object(kind, name string, data map[string]interface{}) *unstructured.Unstructured {
	resourceVersion := "1"
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1", "kind": kind,
		"metadata": map[string]interface{}{"name": name, "namespace": "prod-ssl-proxy", "resourceVersion": resourceVersion},
		"data":     data,
	}}
}
