package log

import (
	"fmt"
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
		"cloudflared-tunnel-credentials":   true,
		"minio-credentials":                true,
		"observability-credentials":        true,
		"proxy-admin-key":                  true,
		"proxy-runtime-secrets":            true,
		"redis-runtime":                    true,
		"schema-migrator-backend":          true,
		"schema-migrator-bootstrap":        true,
		"schema-migrator-keycloak":         true,
		"ssl-proxy-identity-tls":           true,
		"postgres-atheros-search":          true,
		"postgres-keycloak":                true,
		"postgres-octopus":                 true,
		"postgres-schema-migrator":         true,
		"postgres-schema-owner":            true,
		"postgres-runtime-tls":             true,
		"pgbouncer-runtime-users":          true,
		"wireguard-config":                 true,
		"ssl-proxy-prod-postgres-endpoint": true,
	}

	level, err := zerolog.ParseLevel(strings.TrimSpace(os.Getenv("LOG_LEVEL")))
	if err != nil || level == zerolog.NoLevel {
		level = zerolog.InfoLevel
	}
	return &Logger{
		zl:       zerolog.New(os.Stdout).Level(level).With().Timestamp().Logger(),
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
	l.write(l.zl.Info(), msg, args...)
}

func (l *Logger) Error(msg string, args ...interface{}) {
	l.write(l.zl.Error(), msg, args...)
}

func (l *Logger) Warn(msg string, args ...interface{}) {
	l.write(l.zl.Warn(), msg, args...)
}

func (l *Logger) Debug(msg string, args ...interface{}) {
	l.write(l.zl.Debug(), msg, args...)
}

func (l *Logger) write(event *zerolog.Event, msg string, args ...interface{}) {
	for i := 0; i+1 < len(args); i += 2 {
		key, ok := args[i].(string)
		if !ok || key == "" {
			key = fmt.Sprintf("field_%d", i/2)
		}
		event.Str(l.redact(key), l.redact(fmt.Sprint(args[i+1])))
	}
	if len(args)%2 != 0 {
		event.Str("unpaired_field", l.redact(fmt.Sprint(args[len(args)-1])))
	}
	event.Msg(l.redact(msg))
}
