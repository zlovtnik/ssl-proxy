package main

import (
	"testing"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

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
