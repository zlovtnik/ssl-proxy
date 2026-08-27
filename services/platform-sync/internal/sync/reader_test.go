package sync

import (
	"context"
	"testing"

	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/contract"
	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/log"
)

type fakeSecretReader struct {
	data map[string]map[string][]byte
}

func (f fakeSecretReader) ReadSecret(_ context.Context, path string) (map[string][]byte, error) {
	return f.data[path], nil
}

func TestReadAllVaultKeepsOnlyContractDeclaredKeys(t *testing.T) {
	c := &contract.Contract{Inputs: []contract.Input{{
		Kind: "Secret", Name: "runtime", VaultPath: "secret/ssl-proxy/prod/runtime", Keys: []string{"declared"},
	}}}
	data, err := ReadAllVault(context.Background(), log.New(), fakeSecretReader{data: map[string]map[string][]byte{
		"ssl-proxy/prod/runtime": {"declared": []byte("kept"), "undeclared": []byte("must-not-copy")},
	}}, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(data["runtime"]) != 1 || string(data["runtime"]["declared"]) != "kept" {
		t.Fatalf("unexpected filtered data: %#v", data)
	}
	if _, exists := data["runtime"]["undeclared"]; exists {
		t.Fatal("undeclared Vault key was retained")
	}
}
