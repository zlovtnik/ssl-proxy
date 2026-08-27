package validate

import (
	"fmt"

	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/contract"
)

func All(c *contract.Contract, data map[string]map[string][]byte) error {
	if err := validateTLS(c, data); err != nil {
		return fmt.Errorf("TLS validation: %w", err)
	}

	if err := validatePostgres(c, data); err != nil {
		return fmt.Errorf("PostgreSQL validation: %w", err)
	}

	if err := validateLoki(c, data); err != nil {
		return fmt.Errorf("Loki validation: %w", err)
	}

	if err := validatePgBouncer(c, data); err != nil {
		return fmt.Errorf("PgBouncer validation: %w", err)
	}

	if err := validateWireGuard(c, data); err != nil {
		return fmt.Errorf("WireGuard validation: %w", err)
	}

	return nil
}
