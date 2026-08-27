package validate

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/contract"
)

func validateLoki(c *contract.Contract, data map[string]map[string][]byte) error {
	lh := c.Validation.LokiHtpasswd
	obsCreds, ok := data[lh.SecretName]
	if !ok {
		return fmt.Errorf("Loki credentials secret %s not found", lh.SecretName)
	}

	username, ok := obsCreds[lh.UsernameKey]
	if !ok {
		return fmt.Errorf("Loki secret missing %s", lh.UsernameKey)
	}

	password, ok := obsCreds[lh.PasswordKey]
	if !ok {
		return fmt.Errorf("Loki secret missing %s", lh.PasswordKey)
	}

	htpasswd, ok := obsCreds[lh.HtpasswdKey]
	if !ok {
		return fmt.Errorf("Loki secret missing %s", lh.HtpasswdKey)
	}

	htpasswdStr := string(htpasswd)
	usernameStr := string(username)

	if len(htpasswdStr) == 0 {
		return fmt.Errorf("Loki htpasswd is empty")
	}

	if htpasswdStr[0] == '$' {
		if err := bcrypt.CompareHashAndPassword(htpasswd, password); err != nil {
			return fmt.Errorf("Loki htpasswd does not match password: %w", err)
		}
	} else {
		for _, line := range splitLines(htpasswdStr) {
			if len(line) == 0 {
				continue
			}
			parts := splitN(line, ":", 2)
			if len(parts) == 2 && parts[0] == usernameStr {
				return nil
			}
		}
		return fmt.Errorf("Loki htpasswd does not contain username %s", usernameStr)
	}

	return nil
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func splitN(s, sep string, n int) []string {
	var result []string
	start := 0
	for i := 0; i < n-1; i++ {
		idx := indexOf(s[start:], sep)
		if idx == -1 {
			break
		}
		result = append(result, s[start:start+idx])
		start += idx + len(sep)
	}
	result = append(result, s[start:])
	return result
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
