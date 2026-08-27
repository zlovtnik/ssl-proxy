package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	vault "github.com/hashicorp/vault/api"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "credential generator failed: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	config, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			kubeconfig = "/etc/kubernetes/admin.conf"
		}
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return fmt.Errorf("kubernetes config: %w", err)
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("kubernetes client: %w", err)
	}

	namespace := os.Getenv("SYNC_NAMESPACE")
	if namespace == "" {
		namespace = "prod-ssl-proxy"
	}

	saName := "ssl-proxy-platform-sync"

	token, err := createSAToken(ctx, clientset, namespace, saName, 1*time.Hour)
	if err != nil {
		return fmt.Errorf("create SA token: %w", err)
	}

	kubeconfigData := generateKubeconfig(config.Host, token)
	if err := os.WriteFile("/run/platform-sync/kubeconfig", []byte(kubeconfigData), 0600); err != nil {
		return fmt.Errorf("write kubeconfig: %w", err)
	}
	fmt.Println("kubeconfig written to /run/platform-sync/kubeconfig")

	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "https://127.0.0.1:8200"
	}

	vaultToken, err := getVaultToken(ctx, vaultAddr, token, namespace, saName)
	if err != nil {
		return fmt.Errorf("get vault token: %w", err)
	}

	if err := os.WriteFile("/run/platform-sync/vault-token", []byte(vaultToken), 0600); err != nil {
		return fmt.Errorf("write vault token: %w", err)
	}
	fmt.Println("vault token written to /run/platform-sync/vault-token")

	return nil
}

func createSAToken(ctx context.Context, clientset kubernetes.Interface, namespace, saName string, lifetime time.Duration) (string, error) {
	expirationSeconds := int64(lifetime.Seconds())
	tokenRequest := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences:         []string{"https://kubernetes.default.svc"},
			ExpirationSeconds: &expirationSeconds,
		},
	}

	token, err := clientset.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, saName, tokenRequest, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("create token: %w", err)
	}

	return token.Status.Token, nil
}

func generateKubeconfig(server, token string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- cluster:
    server: %s
    insecure-skip-tls-verify: true
  name: default
contexts:
- context:
    cluster: default
    user: platform-sync
  name: platform-sync
current-context: platform-sync
users:
- user:
    token: %s
  name: platform-sync
`, server, token)
}

func getVaultToken(ctx context.Context, vaultAddr, k8sToken, namespace, saName string) (string, error) {
	config := vault.DefaultConfig()
	config.Address = vaultAddr

	client, err := vault.NewClient(config)
	if err != nil {
		return "", fmt.Errorf("vault client: %w", err)
	}

	data := map[string]interface{}{
		"role":       "platform-sync",
		"kubernetes_token": k8sToken,
	}

	secret, err := client.Logical().WriteWithContext(ctx, "auth/kubernetes/login", data)
	if err != nil {
		return "", fmt.Errorf("vault login: %w", err)
	}

	return secret.Auth.ClientToken, nil
}
