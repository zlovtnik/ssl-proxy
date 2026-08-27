package main

import (
	"context"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/clientcmd"
)

func TestCreateSATokenUsesAPIServerDefaultAudience(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	clientset.PrependReactor("create", "serviceaccounts", func(action k8stesting.Action) (bool, runtime.Object, error) {
		request := action.(k8stesting.CreateAction).GetObject().(*authenticationv1.TokenRequest)
		if len(request.Spec.Audiences) != 0 {
			t.Fatalf("custom audience would make the token unusable by the Kubernetes API: %v", request.Spec.Audiences)
		}
		request.Status.Token = "api-server-token"
		return true, request, nil
	})

	token, err := createSAToken(context.Background(), clientset, "prod-ssl-proxy", "ssl-proxy-platform-sync", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if token != "api-server-token" {
		t.Fatalf("unexpected token %q", token)
	}
}

func TestGenerateKubeconfigPreservesTLSVerification(t *testing.T) {
	data, err := generateKubeconfig(&rest.Config{
		Host:            "https://192.0.2.10:6443",
		TLSClientConfig: rest.TLSClientConfig{CAData: []byte("test-ca"), ServerName: "kubernetes.internal"},
	}, "short-lived-token")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := clientcmd.Load(data)
	if err != nil {
		t.Fatal(err)
	}
	cluster := parsed.Clusters["default"]
	if cluster.InsecureSkipTLSVerify || string(cluster.CertificateAuthorityData) != "test-ca" || cluster.TLSServerName != "kubernetes.internal" {
		t.Fatalf("TLS settings were not preserved: %#v", cluster)
	}
	if parsed.AuthInfos["platform-sync"].Token != "short-lived-token" {
		t.Fatal("generated kubeconfig is missing token")
	}
}

func TestGenerateKubeconfigRejectsInsecureSource(t *testing.T) {
	_, err := generateKubeconfig(&rest.Config{Host: "https://example", TLSClientConfig: rest.TLSClientConfig{Insecure: true}}, "token")
	if err == nil {
		t.Fatal("insecure source config was accepted")
	}
}

func TestDefaultKubeconfigTargetsK3s(t *testing.T) {
	if defaultK3sKubeconfig != "/etc/rancher/k3s/k3s.yaml" {
		t.Fatalf("unexpected K3s kubeconfig default %q", defaultK3sKubeconfig)
	}
}
