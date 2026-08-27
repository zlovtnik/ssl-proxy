package vault

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRenewSelfUsesLoadedToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/auth/token/renew-self" {
			t.Fatalf("unexpected request path %s", request.URL.Path)
		}
		if request.Header.Get("X-Vault-Token") != "read-only-periodic-token" {
			t.Fatal("renewal request did not use the configured token")
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"auth":{"client_token":"read-only-periodic-token","renewable":true,"lease_duration":86400}}`)); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	defer server.Close()

	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "read-only-periodic-token")
	t.Setenv("VAULT_TOKEN_FILE", "")
	t.Setenv("VAULT_CACERT", "")
	client, err := NewClient()
	if err != nil {
		t.Fatal(err)
	}
	if err := client.RenewSelf(context.Background()); err != nil {
		t.Fatal(err)
	}
}
