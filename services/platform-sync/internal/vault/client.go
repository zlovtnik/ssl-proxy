package vault

import (
	"context"
	"fmt"
	"os"
	"strings"

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
		tokenFile := os.Getenv("VAULT_TOKEN_FILE")
		if tokenFile != "" {
			data, err := os.ReadFile(tokenFile) // #nosec G304 -- VAULT_TOKEN_FILE is an explicit trusted service setting.
			if err != nil {
				return nil, fmt.Errorf("read VAULT_TOKEN_FILE: %w", err)
			}
			token = strings.TrimSpace(string(data))
		}
	}
	if token == "" {
		return nil, fmt.Errorf("VAULT_TOKEN or VAULT_TOKEN_FILE is required")
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

// RenewSelf extends the periodic read-only service token before each sync.
// The token is provisioned out-of-band and loaded through a systemd credential.
func (c *Client) RenewSelf(ctx context.Context) error {
	secret, err := c.api.Auth().Token().RenewSelfWithContext(ctx, 0)
	if err != nil {
		return fmt.Errorf("renew Vault token: %w", err)
	}
	if secret == nil || secret.Auth == nil || !secret.Auth.Renewable {
		return fmt.Errorf("Vault token did not renew as a renewable token")
	}
	return nil
}
