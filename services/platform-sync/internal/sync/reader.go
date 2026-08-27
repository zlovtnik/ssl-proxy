package sync

import (
	"context"
	"fmt"
	"strings"

	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/contract"
	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/log"
)

type SecretReader interface {
	ReadSecret(context.Context, string) (map[string][]byte, error)
}

func ReadAllVault(ctx context.Context, logger *log.Logger, vaultClient SecretReader, c *contract.Contract) (map[string]map[string][]byte, error) {
	secretData := make(map[string]map[string][]byte)

	for _, input := range c.Inputs {
		name := input.Name
		vaultPath := input.VaultPath
		// The Vault client is already scoped to the configured KV-v2 mount, so
		// pass the logical path beneath that mount. Contract paths are absolute
		// logical paths such as secret/ssl-proxy/prod/runtime.
		relativePath := strings.TrimPrefix(vaultPath, "secret/")

		logger.Info("reading vault secret", "name", name, "path", relativePath)
		data, err := vaultClient.ReadSecret(ctx, relativePath)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}

		declared := make(map[string][]byte, len(input.Keys))
		for _, key := range input.Keys {
			value, ok := data[key]
			if !ok {
				return nil, fmt.Errorf("secret %s missing key %s", name, key)
			}
			declared[key] = append([]byte(nil), value...)
		}

		secretData[name] = declared
	}

	return secretData, nil
}
