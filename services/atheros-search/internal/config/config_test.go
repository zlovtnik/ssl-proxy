package config

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLoadValidatesDimensionsAndAuthDigest(t *testing.T) {
	clearWorkerAndAlertEnv(t)
	t.Setenv("ATHSEARCH_POSTGRES_DSN", "postgres://sync:sync@localhost:5432/sync")
	t.Setenv("ATHSEARCH_EMBEDDING_DIMENSIONS", "384")
	_, err := Load()
	require.ErrorContains(t, err, "ATHSEARCH_EMBEDDING_DIMENSIONS")

	t.Setenv("ATHSEARCH_EMBEDDING_DIMENSIONS", "768")
	t.Setenv("ATHSEARCH_API_TOKEN_SHA256", "not-hex")
	_, err = Load()
	require.ErrorContains(t, err, "ATHSEARCH_API_TOKEN_SHA256")

	sum := sha256.Sum256([]byte("token"))
	t.Setenv("ATHSEARCH_API_TOKEN_SHA256", hex.EncodeToString(sum[:]))
	cfg, err := Load()
	require.NoError(t, err)
	require.Equal(t, DefaultEmbeddingDimensions, cfg.EmbeddingDimensions)
}

func TestClampTopK(t *testing.T) {
	require.Equal(t, 10, ClampTopK(0))
	require.Equal(t, 42, ClampTopK(42))
	require.Equal(t, 100, ClampTopK(101))
}

func TestDBKindMapsAPIWordsToSchemaValues(t *testing.T) {
	got, ok := DBKind("behaviour")
	require.True(t, ok)
	require.Equal(t, "behaviour_window", got)
	got, ok = DBKind("sequence")
	require.True(t, ok)
	require.Equal(t, "frame_sequence", got)
}

func TestLoadWorkerAndAlertDefaults(t *testing.T) {
	clearWorkerAndAlertEnv(t)
	t.Setenv("ATHSEARCH_POSTGRES_DSN", "postgres://sync:sync@localhost:5432/sync")
	t.Setenv("ATHSEARCH_EMBEDDING_BACKEND", "")

	cfg, err := Load()

	require.NoError(t, err)
	require.False(t, cfg.WorkerEnabled)
	require.NotEmpty(t, cfg.WorkerName)
	require.Equal(t, 64, cfg.WorkerBatchSize)
	require.Equal(t, 64, cfg.WorkerRequestBatchSize)
	require.Equal(t, 128, cfg.WorkerRequestBatchMax)
	require.Equal(t, 1800, cfg.WorkerLeaseSeconds)
	require.Equal(t, 5*time.Second, cfg.WorkerPollInterval)
	require.Equal(t, 0, cfg.WorkerMaxDrainBatches)
	require.Equal(t, 512, cfg.WorkerMaxInputTokens)
	require.Equal(t, 30*time.Second, cfg.WorkerDBCallTimeout)
	require.Equal(t, 4, cfg.WorkerMaxConcurrentEmbed)
	require.Equal(t, 16, cfg.WorkerMaxConcurrentComplete)
	require.False(t, cfg.AlertEnabled)
	require.Equal(t, 10, cfg.AlertSweepInterval)
	require.Equal(t, int64(10), cfg.AlertNearDupThreshold)
	require.Equal(t, 0.75, cfg.AlertAPRiskThreshold)
	require.Equal(t, 3, cfg.AlertGraphMaxDepth)
	require.Equal(t, -15.0, cfg.AlertSeqThreshold)
	require.Equal(t, 50.0, cfg.AlertTravelMaxSpeedMPS)
	require.Equal(t, 15, cfg.AlertDNSLookbackMinutes)
}

func TestLoadWorkerConfigFromEnv(t *testing.T) {
	clearWorkerAndAlertEnv(t)
	t.Setenv("ATHSEARCH_POSTGRES_DSN", "postgres://sync:sync@localhost:5432/sync")
	t.Setenv("ATHSEARCH_EMBEDDING_BACKEND", "")
	t.Setenv("ATHSEARCH_WORKER_ENABLED", "true")
	t.Setenv("ATHSEARCH_WORKER_NAME", "worker-a")
	t.Setenv("ATHSEARCH_WORKER_BATCH_SIZE", "200")
	t.Setenv("ATHSEARCH_WORKER_REQUEST_BATCH_MAX", "96")
	t.Setenv("ATHSEARCH_WORKER_LEASE_SECONDS", "60")
	t.Setenv("ATHSEARCH_WORKER_POLL_INTERVAL_MS", "250")
	t.Setenv("ATHSEARCH_WORKER_MAX_DRAIN_BATCHES", "7")
	t.Setenv("ATHSEARCH_WORKER_MAX_INPUT_TOKENS", "384")
	t.Setenv("ATHSEARCH_WORKER_DB_CALL_TIMEOUT_MS", "1500")
	t.Setenv("ATHSEARCH_WORKER_MAX_CONCURRENT_EMBED", "3")
	t.Setenv("ATHSEARCH_WORKER_MAX_CONCURRENT_COMPLETE", "5")
	t.Setenv("ATHSEARCH_ALERT_ENABLED", "true")
	t.Setenv("ATHSEARCH_ALERT_SWEEP_INTERVAL", "4")
	t.Setenv("ATHSEARCH_ALERT_NEAR_DUP_THRESHOLD", "12")
	t.Setenv("ATHSEARCH_ALERT_AP_RISK_THRESHOLD", "0.9")
	t.Setenv("ATHSEARCH_ALERT_GRAPH_MAX_DEPTH", "5")
	t.Setenv("ATHSEARCH_ALERT_SEQ_THRESHOLD", "-21.5")
	t.Setenv("ATHSEARCH_ALERT_TRAVEL_MAX_SPEED_MPS", "33.25")
	t.Setenv("ATHSEARCH_ALERT_DNS_LOOKBACK_MINUTES", "30")

	cfg, err := Load()

	require.NoError(t, err)
	require.True(t, cfg.WorkerEnabled)
	require.Equal(t, "worker-a", cfg.WorkerName)
	require.Equal(t, 200, cfg.WorkerBatchSize)
	require.Equal(t, 96, cfg.WorkerRequestBatchSize)
	require.Equal(t, 96, cfg.WorkerRequestBatchMax)
	require.Equal(t, 60, cfg.WorkerLeaseSeconds)
	require.Equal(t, 250*time.Millisecond, cfg.WorkerPollInterval)
	require.Equal(t, 7, cfg.WorkerMaxDrainBatches)
	require.Equal(t, 384, cfg.WorkerMaxInputTokens)
	require.Equal(t, 1500*time.Millisecond, cfg.WorkerDBCallTimeout)
	require.Equal(t, 3, cfg.WorkerMaxConcurrentEmbed)
	require.Equal(t, 5, cfg.WorkerMaxConcurrentComplete)
	require.True(t, cfg.AlertEnabled)
	require.Equal(t, 4, cfg.AlertSweepInterval)
	require.Equal(t, int64(12), cfg.AlertNearDupThreshold)
	require.Equal(t, 0.9, cfg.AlertAPRiskThreshold)
	require.Equal(t, 5, cfg.AlertGraphMaxDepth)
	require.Equal(t, -21.5, cfg.AlertSeqThreshold)
	require.Equal(t, 33.25, cfg.AlertTravelMaxSpeedMPS)
	require.Equal(t, 30, cfg.AlertDNSLookbackMinutes)
}

func TestLoadValidatesWorkerConfig(t *testing.T) {
	cases := []struct {
		name    string
		envKey  string
		value   string
		wantErr string
	}{
		{
			name:    "batch size low",
			envKey:  "ATHSEARCH_WORKER_BATCH_SIZE",
			value:   "0",
			wantErr: "ATHSEARCH_WORKER_BATCH_SIZE",
		},
		{
			name:    "batch size high",
			envKey:  "ATHSEARCH_WORKER_BATCH_SIZE",
			value:   "1025",
			wantErr: "ATHSEARCH_WORKER_BATCH_SIZE",
		},
		{
			name:    "request batch max low",
			envKey:  "ATHSEARCH_WORKER_REQUEST_BATCH_MAX",
			value:   "0",
			wantErr: "ATHSEARCH_WORKER_REQUEST_BATCH_MAX",
		},
		{
			name:    "request batch size low",
			envKey:  "ATHSEARCH_WORKER_REQUEST_BATCH_SIZE",
			value:   "0",
			wantErr: "ATHSEARCH_WORKER_REQUEST_BATCH_SIZE",
		},
		{
			name:    "max input tokens",
			envKey:  "ATHSEARCH_WORKER_MAX_INPUT_TOKENS",
			value:   "0",
			wantErr: "ATHSEARCH_WORKER_MAX_INPUT_TOKENS",
		},
		{
			name:    "db timeout",
			envKey:  "ATHSEARCH_WORKER_DB_CALL_TIMEOUT_MS",
			value:   "0",
			wantErr: "ATHSEARCH_WORKER_DB_CALL_TIMEOUT_MS",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearWorkerAndAlertEnv(t)
			t.Setenv("ATHSEARCH_POSTGRES_DSN", "postgres://sync:sync@localhost:5432/sync")
			t.Setenv("ATHSEARCH_EMBEDDING_BACKEND", "")
			t.Setenv(tc.envKey, tc.value)

			_, err := Load()

			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestLoadValidatesWorkerRequestBatchBounds(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			name: "request size above max",
			env: map[string]string{
				"ATHSEARCH_WORKER_REQUEST_BATCH_MAX":  "10",
				"ATHSEARCH_WORKER_REQUEST_BATCH_SIZE": "11",
			},
			want: "ATHSEARCH_WORKER_REQUEST_BATCH_MAX",
		},
		{
			name: "request size above worker batch",
			env: map[string]string{
				"ATHSEARCH_WORKER_BATCH_SIZE":         "10",
				"ATHSEARCH_WORKER_REQUEST_BATCH_MAX":  "20",
				"ATHSEARCH_WORKER_REQUEST_BATCH_SIZE": "11",
			},
			want: "ATHSEARCH_WORKER_BATCH_SIZE",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clearWorkerAndAlertEnv(t)
			t.Setenv("ATHSEARCH_POSTGRES_DSN", "postgres://sync:sync@localhost:5432/sync")
			t.Setenv("ATHSEARCH_EMBEDDING_BACKEND", "")
			for key, value := range tc.env {
				t.Setenv(key, value)
			}

			_, err := Load()

			require.ErrorContains(t, err, tc.want)
		})
	}
}

func clearWorkerAndAlertEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"ATHSEARCH_WORKER_ENABLED",
		"ATHSEARCH_WORKER_NAME",
		"ATHSEARCH_WORKER_BATCH_SIZE",
		"ATHSEARCH_WORKER_REQUEST_BATCH_SIZE",
		"ATHSEARCH_WORKER_REQUEST_BATCH_MAX",
		"ATHSEARCH_WORKER_LEASE_SECONDS",
		"ATHSEARCH_WORKER_POLL_INTERVAL_MS",
		"ATHSEARCH_WORKER_MAX_DRAIN_BATCHES",
		"ATHSEARCH_WORKER_MAX_INPUT_TOKENS",
		"ATHSEARCH_WORKER_DB_CALL_TIMEOUT_MS",
		"ATHSEARCH_WORKER_MAX_CONCURRENT_EMBED",
		"ATHSEARCH_WORKER_MAX_CONCURRENT_COMPLETE",
		"ATHSEARCH_ALERT_ENABLED",
		"ATHSEARCH_ALERT_SWEEP_INTERVAL",
		"ATHSEARCH_ALERT_NEAR_DUP_THRESHOLD",
		"ATHSEARCH_ALERT_AP_RISK_THRESHOLD",
		"ATHSEARCH_ALERT_GRAPH_MAX_DEPTH",
		"ATHSEARCH_ALERT_SEQ_THRESHOLD",
		"ATHSEARCH_ALERT_TRAVEL_MAX_SPEED_MPS",
		"ATHSEARCH_ALERT_DNS_LOOKBACK_MINUTES",
	} {
		t.Setenv(key, "")
	}
}
