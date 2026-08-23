package db

import (
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestValidateDriverConfigRequiresDedicatedExternalAtherosSearchDatabase(t *testing.T) {
	for _, test := range []struct {
		dsn  string
		want string
	}{
		{"postgresql://search:secret@localhost:5432/sync", "external non-loopback"},
		{"postgresql://search:secret@127.0.0.1:5432/sync", "external non-loopback"},
		{"postgresql://postgres:secret@db.example.test:5432/sync", "non-superuser"},
		{"postgresql://search@db.example.test:5432/sync", "non-empty credential"},
		{"postgresql://search:secret@db.example.test:5432/other", "sync"},
	} {
		t.Run(test.dsn, func(t *testing.T) {
			cfg, err := pgx.ParseConfig(test.dsn)
			require.NoError(t, err)
			require.ErrorContains(t, validateDriverConfig(cfg), test.want)
		})
	}
	cfg, err := pgx.ParseConfig("postgresql://search:secret@db.example.test:5432/sync")
	require.NoError(t, err)
	require.NoError(t, validateDriverConfig(cfg))
}

func TestValidatePostgresVersion(t *testing.T) {
	require.NoError(t, validatePostgresVersion(160004))
	require.NoError(t, validatePostgresVersion(170001))
	require.ErrorContains(t, validatePostgresVersion(150008), "16 or newer")
}

func TestConfigureTLSAllowsExplicitPlaintext(t *testing.T) {
	cfg, err := pgx.ParseConfig("postgresql://search:secret@db.example.test:5432/sync?sslmode=disable")
	require.NoError(t, err)
	require.NoError(t, configureTLS(cfg, Options{}))

	err = configureTLS(cfg, Options{TLSServerName: "postgres.example.test"})
	require.ErrorContains(t, err, "CA file")
}
