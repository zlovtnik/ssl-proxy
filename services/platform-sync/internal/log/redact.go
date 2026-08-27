package log

import (
	"os"
	"strings"
	"sync"

	"github.com/rs/zerolog"
)

type Logger struct {
	zl       zerolog.Logger
	redacted map[string]bool
	mu       sync.RWMutex
}

func New() *Logger {
	redacted := map[string]bool{
		"cloudflared-tunnel-credentials": true,
		"minio-credentials":              true,
		"observability-credentials":      true,
		"proxy-admin-key":                true,
		"proxy-runtime-secrets":          true,
		"redis-runtime":                  true,
		"schema-migrator-backend":        true,
		"schema-migrator-bootstrap":      true,
		"schema-migrator-keycloak":       true,
		"ssl-proxy-identity-tls":         true,
		"postgres-atheros-search":        true,
		"postgres-keycloak":              true,
		"postgres-octopus":               true,
		"postgres-schema-migrator":       true,
		"postgres-schema-owner":          true,
		"postgres-runtime-tls":           true,
		"pgbouncer-runtime-users":        true,
		"wireguard-config":               true,
		"ssl-proxy-prod-postgres-endpoint": true,
	}

	return &Logger{
		zl:       zerolog.New(os.Stdout).With().Timestamp().Logger(),
		redacted: redacted,
	}
}

func (l *Logger) redact(msg string) string {
	l.mu.RLock()
	defer l.mu.RUnlock()

	result := msg
	for name := range l.redacted {
		if strings.Contains(result, name) {
			result = strings.ReplaceAll(result, name, "[REDACTED]")
		}
	}
	return result
}

func (l *Logger) Info(msg string, args ...interface{}) {
	l.zl.Info().Msg(l.redact(msg))
}

func (l *Logger) Error(msg string, args ...interface{}) {
	l.zl.Error().Msg(l.redact(msg))
}

func (l *Logger) Warn(msg string, args ...interface{}) {
	l.zl.Warn().Msg(l.redact(msg))
}

func (l *Logger) Debug(msg string, args ...interface{}) {
	l.zl.Debug().Msg(l.redact(msg))
}
