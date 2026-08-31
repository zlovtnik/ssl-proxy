package contract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadParsesAndValidatesContract(t *testing.T) {
	path := writeContract(t, validContractYAML)
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if loaded.Namespace != "prod-ssl-proxy" || loaded.Validation.Postgres.Port != 4000 {
		t.Fatalf("unexpected parsed contract: %#v", loaded)
	}
	if loaded.Readiness.ConfigMapName != "platform-ready" || len(loaded.SHA256) != 64 {
		t.Fatalf("readiness contract was not loaded: %#v", loaded.Readiness)
	}
}

func TestLoadRejectsDuplicateInputsAndWrongAPIVersion(t *testing.T) {
	duplicate := strings.Replace(validContractYAML, "  validation:", "    - kind: Secret\n      name: first\n      vaultPath: secret/first-again\n      keys: [password]\n  validation:", 1)
	if _, err := Load(writeContract(t, duplicate)); err == nil {
		t.Fatal("duplicate input was accepted")
	}
	wrongVersion := strings.Replace(validContractYAML, APIVersion, "platform.ssl-proxy.io/v9", 1)
	if _, err := Load(writeContract(t, wrongVersion)); err == nil {
		t.Fatal("wrong apiVersion was accepted")
	}
}

func writeContract(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "contract.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const validContractYAML = `apiVersion: platform.ssl-proxy.io/v1alpha1
kind: PlatformInputContract
spec:
  environment: prod
  namespace: prod-ssl-proxy
  readiness:
    configMapName: platform-ready
  bootstrap:
    postgres:
      endpoint:
        host: 192.168.1.242
        port: 4000
        tlsServerName: 192.168.1.242
  inputs:
    - kind: Secret
      name: first
      type: Opaque
      vaultPath: secret/first
      keys: [password]
  validation:
    postgres:
      endpointConfigMapName: endpoint
      database: sync
      transport: tls-verify-full
      tlsSecretName: postgres-tls
      pgbouncerListenerTLSSecretName: pgbouncer-listener-tls
      pgbouncerListenerTLSServerName: postgres-pgbouncer
      grantMatrixDocument: sql/postgres
      accounts:
        postgres-octopus: octopus_runtime
`
