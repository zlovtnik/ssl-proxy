package vault

import (
	"context"
	"fmt"
	"os"

	vault "github.com/hashicorp/vault/api"
)

type Client struct {
	api    *vault.Client
	mount  string
	prefix string
}

func NewClient() (*Client, error) {
	config := vault.DefaultConfig()
	if addr := os.Getenv("VAULT_ADDR"); addr != "" {
		config.Address = addr
	}

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("vault client: %w", err)
	}

	token := os.Getenv("VAULT_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("VAULT_TOKEN is required")
	}
	client.SetToken(token)

	mount := os.Getenv("VAULT_KV_MOUNT")
	if mount == "" {
		mount = "secret"
	}

	prefix := os.Getenv("VAULT_KV_PREFIX")
	if prefix == "" {
		prefix = "ssl-proxy/prod"
	}

	return &Client{api: client, mount: mount, prefix: prefix}, nil
}

func (c *Client) ReadSecret(ctx context.Context, path string) (map[string][]byte, error) {
	secret, err := c.api.KVv2(c.mount).Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("vault read %s: %w", path, err)
	}

	result := make(map[string][]byte)
	for k, v := range secret.Data {
		if s, ok := v.(string); ok {
			result[k] = []byte(s)
		}
	}
	return result, nil
}
