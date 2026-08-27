package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

const (
	defaultK3sKubeconfig = "/etc/rancher/k3s/k3s.yaml"
	defaultRuntimeDir    = "/run/platform-sync"
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "credential generator failed: %v\n", err)
		return 1
	}
	return 0
}

func run(ctx context.Context) error {
	config, err := sourceKubernetesConfig()
	if err != nil {
		return err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("kubernetes client: %w", err)
	}

	namespace := envOrDefault("SYNC_NAMESPACE", "prod-ssl-proxy")
	serviceAccount := envOrDefault("SYNC_SERVICE_ACCOUNT", "ssl-proxy-platform-sync")
	token, err := createSAToken(ctx, clientset, namespace, serviceAccount, time.Hour)
	if err != nil {
		return fmt.Errorf("create service account token: %w", err)
	}
	kubeconfigData, err := generateKubeconfig(config, token)
	if err != nil {
		return err
	}

	runtimeDir := envOrDefault("SYNC_RUNTIME_DIR", defaultRuntimeDir)
	if err := writeCredential(filepath.Join(runtimeDir, "kubeconfig"), kubeconfigData); err != nil {
		return err
	}
	fmt.Println("short-lived Kubernetes credential refreshed")
	return nil
}

func sourceKubernetesConfig() (*rest.Config, error) {
	if config, err := rest.InClusterConfig(); err == nil {
		return config, nil
	}
	kubeconfig := envOrDefault("KUBECONFIG", defaultK3sKubeconfig)
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("kubernetes config %s: %w", kubeconfig, err)
	}
	return config, nil
}

func createSAToken(ctx context.Context, clientset kubernetes.Interface, namespace, serviceAccount string, lifetime time.Duration) (string, error) {
	expirationSeconds := int64(lifetime.Seconds())
	tokenRequest := &authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{
		ExpirationSeconds: &expirationSeconds,
	}}
	token, err := clientset.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, serviceAccount, tokenRequest, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("create token: %w", err)
	}
	if strings.TrimSpace(token.Status.Token) == "" {
		return "", fmt.Errorf("kubernetes TokenRequest returned an empty token")
	}
	return token.Status.Token, nil
}

func generateKubeconfig(config *rest.Config, token string) ([]byte, error) {
	if config.Insecure {
		return nil, fmt.Errorf("refusing to generate a kubeconfig with TLS verification disabled")
	}
	caData := append([]byte(nil), config.CAData...)
	if len(caData) == 0 && config.CAFile != "" {
		var err error
		caData, err = os.ReadFile(config.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read Kubernetes CA: %w", err)
		}
	}
	generated := clientcmdapi.NewConfig()
	generated.Clusters["default"] = &clientcmdapi.Cluster{
		Server:                   config.Host,
		CertificateAuthorityData: caData,
		TLSServerName:            config.ServerName,
	}
	generated.AuthInfos["platform-sync"] = &clientcmdapi.AuthInfo{Token: token}
	generated.Contexts["platform-sync"] = &clientcmdapi.Context{Cluster: "default", AuthInfo: "platform-sync"}
	generated.CurrentContext = "platform-sync"
	data, err := clientcmd.Write(*generated)
	if err != nil {
		return nil, fmt.Errorf("serialize kubeconfig: %w", err)
	}
	return data, nil
}

func writeCredential(path string, data []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".credential-*")
	if err != nil {
		return fmt.Errorf("create temporary credential for %s: %w", path, err)
	}
	tempName := temp.Name()
	defer func() {
		_ = os.Remove(tempName) //nolint:errcheck // Best-effort cleanup after rename.
	}()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close() //nolint:errcheck // Preserve the primary failure.
		return fmt.Errorf("set credential permissions: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close() //nolint:errcheck // Preserve the primary failure.
		return fmt.Errorf("write temporary credential: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close() //nolint:errcheck // Preserve the primary failure.
		return fmt.Errorf("sync temporary credential: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary credential: %w", err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("replace credential %s: %w", path, err)
	}
	return nil
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
