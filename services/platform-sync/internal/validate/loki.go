package validate

import (
	"fmt"
	"strings"

	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/contract"
	"golang.org/x/crypto/bcrypt"
)

func validateLoki(c *contract.Contract, data map[string]map[string][]byte) error {
	validation := c.Validation.LokiHtpasswd
	credentials, ok := data[validation.SecretName]
	if !ok {
		return fmt.Errorf("Loki credentials secret %s not found", validation.SecretName)
	}
	username, ok := credentials[validation.UsernameKey]
	if !ok || strings.TrimSpace(string(username)) == "" {
		return fmt.Errorf("Loki secret missing non-empty %s", validation.UsernameKey)
	}
	password, ok := credentials[validation.PasswordKey]
	if !ok || len(password) == 0 {
		return fmt.Errorf("Loki secret missing non-empty %s", validation.PasswordKey)
	}
	htpasswd, ok := credentials[validation.HtpasswdKey]
	if !ok {
		return fmt.Errorf("Loki secret missing %s", validation.HtpasswdKey)
	}

	wantedUser := string(username)
	for lineNumber, line := range strings.Split(strings.TrimSpace(string(htpasswd)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		user, hash, found := strings.Cut(line, ":")
		if !found || user == "" || hash == "" {
			return fmt.Errorf("Loki htpasswd line %d has invalid format", lineNumber+1)
		}
		if user != wantedUser {
			continue
		}
		if err := bcrypt.CompareHashAndPassword([]byte(hash), password); err != nil {
			return fmt.Errorf("Loki htpasswd hash does not match declared password: %w", err)
		}
		return nil
	}
	return fmt.Errorf("Loki htpasswd does not contain declared username")
}
