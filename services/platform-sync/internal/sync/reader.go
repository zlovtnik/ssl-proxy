package sync

import (
	"context"
	"fmt"
	"strings"

	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/contract"
	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/log"
	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/vault"
)

func ReadAllVault(ctx context.Context, logger *log.Logger, vaultClient *vault.Client, c *contract.Contract) (map[string]map[string][]byte, error) {
	secretData := make(map[string]map[string][]byte)

	for _, input := range c.Inputs {
		name := input.Name
		vaultPath := input.VaultPath

		parts := strings.SplitN(vaultPath, "/", 2)
		relativePath := parts[len(parts)-1]
		relativePath = strings.TrimPrefix(relativePath, "secret/ssl-proxy/prod/")

		logger.Info("reading vault secret", "name", name, "path", relativePath)
		data, err := vaultClient.ReadSecret(ctx, relativePath)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}

		for _, key := range input.Keys {
			if _, ok := data[key]; !ok {
				return nil, fmt.Errorf("secret %s missing key %s", name, key)
			}
		}

		secretData[name] = data
	}

	return secretData, nil
}
