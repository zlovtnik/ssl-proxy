package validate

import (
	"fmt"
	"strconv"

	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/contract"
)

func validatePostgres(c *contract.Contract, data map[string]map[string][]byte) error {
	cmName := c.Validation.Postgres.EndpointConfigMapName
	cmData, ok := data[cmName]
	if !ok {
		return fmt.Errorf("PostgreSQL endpoint ConfigMap %s not found", cmName)
	}

	requiredKeys := []string{"POSTGRES_HOST", "POSTGRES_PORT", "POSTGRES_DATABASE", "POSTGRES_SSL_MODE", "POSTGRES_SSL_SERVER_NAME"}
	for _, key := range requiredKeys {
		if _, ok := cmData[key]; !ok {
			return fmt.Errorf("PostgreSQL endpoint missing key %s", key)
		}
	}

	if port, ok := cmData["POSTGRES_PORT"]; ok {
		if _, err := strconv.Atoi(string(port)); err != nil {
			return fmt.Errorf("POSTGRES_PORT is not a valid integer: %s", port)
		}
	}

	tlsSecret, ok := data[c.Validation.Postgres.TLSSecretName]
	if !ok {
		return fmt.Errorf("PostgreSQL TLS secret %s not found", c.Validation.Postgres.TLSSecretName)
	}
	if _, ok := tlsSecret["ca.crt"]; !ok {
		return fmt.Errorf("PostgreSQL TLS secret missing ca.crt")
	}

	for secretName := range c.Validation.Postgres.Accounts {
		if _, ok := data[secretName]; !ok {
			return fmt.Errorf("PostgreSQL account secret %s not found", secretName)
		}
		if _, ok := data[secretName]["password"]; !ok {
			return fmt.Errorf("PostgreSQL account secret %s missing password", secretName)
		}
	}

	return nil
}
