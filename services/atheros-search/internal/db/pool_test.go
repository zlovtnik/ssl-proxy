package db

import (
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"
)

func TestValidateDriverConfigRequiresDedicatedExternalAtherosSearchDatabase(t *testing.T) {
	for _, test := range []struct {
		dsn  string
		want string
	}{
		{"search:secret@unix(/tmp/tidb.sock)/atheros_search", "tcp networking"},
		{"search:secret@tcp(localhost:4000)/atheros_search", "external non-loopback"},
		{"search:secret@tcp(127.0.0.1:4000)/atheros_search", "external non-loopback"},
		{"root:secret@tcp(tidb.example.test:4000)/atheros_search", "non-root"},
		{"search@tcp(tidb.example.test:4000)/atheros_search", "non-empty credential"},
		{"search:secret@tcp(tidb.example.test:4000)/octopus_core", "atheros_search"},
	} {
		t.Run(test.dsn, func(t *testing.T) {
			cfg, err := mysql.ParseDSN(test.dsn)
			require.NoError(t, err)
			require.ErrorContains(t, validateDriverConfig(cfg), test.want)
		})
	}
	cfg, err := mysql.ParseDSN("search:secret@tcp(tidb.example.test:4000)/atheros_search")
	require.NoError(t, err)
	require.NoError(t, validateDriverConfig(cfg))
}

func TestValidateTiDBVersion(t *testing.T) {
	require.NoError(t, validateTiDBVersion("5.7.25-TiDB-v8.5.2"))
	require.NoError(t, validateTiDBVersion("TiDB v9.0.0"))
	require.ErrorContains(t, validateTiDBVersion("5.7.25-TiDB-v8.4.0"), "v8.5")
	require.ErrorContains(t, validateTiDBVersion("8.5.0 MySQL Community Server"), "not identifiable")
}

func TestRegisterTLSConfigAllowsExplicitPlaintext(t *testing.T) {
	name, err := registerTLSConfig(Options{})
	require.NoError(t, err)
	require.Empty(t, name)

	_, err = registerTLSConfig(Options{TLSServerName: "tidb.example.test"})
	require.ErrorContains(t, err, "CA file")
}
