package alerts

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/config"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/metrics"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/seqscore"
)

type Config struct {
	NearDupThreshold   int64
	APRiskThreshold    float64
	GraphMaxDepth      int32
	SeqThreshold       float64
	TravelMaxSpeedMPS  float64
	DNSLookbackMinutes int32
}

func ConfigFromEnv() Config {
	defaults := defaultConfig()
	return Config{
		NearDupThreshold:   envInt64("ATHSEARCH_ALERT_NEAR_DUP_THRESHOLD", defaults.NearDupThreshold),
		APRiskThreshold:    envFloat64("ATHSEARCH_ALERT_AP_RISK_THRESHOLD", defaults.APRiskThreshold),
		GraphMaxDepth:      int32(envInt64("ATHSEARCH_ALERT_GRAPH_MAX_DEPTH", int64(defaults.GraphMaxDepth))),
		SeqThreshold:       envFloat64("ATHSEARCH_ALERT_SEQ_THRESHOLD", defaults.SeqThreshold),
		TravelMaxSpeedMPS:  envFloat64("ATHSEARCH_ALERT_TRAVEL_MAX_SPEED_MPS", defaults.TravelMaxSpeedMPS),
		DNSLookbackMinutes: int32(envInt64("ATHSEARCH_ALERT_DNS_LOOKBACK_MINUTES", int64(defaults.DNSLookbackMinutes))),
	}
}

func ConfigFromSearchConfig(cfg config.Config) Config {
	return Config{
		NearDupThreshold:   cfg.AlertNearDupThreshold,
		APRiskThreshold:    cfg.AlertAPRiskThreshold,
		GraphMaxDepth:      int32(cfg.AlertGraphMaxDepth),
		SeqThreshold:       cfg.AlertSeqThreshold,
		TravelMaxSpeedMPS:  cfg.AlertTravelMaxSpeedMPS,
		DNSLookbackMinutes: int32(cfg.AlertDNSLookbackMinutes),
	}
}

func RunSweep(ctx context.Context, pool *pgxpool.Pool, scorer *seqscore.Scorer, cfg Config, logger zerolog.Logger) error {
	return RunSweepWithMetrics(ctx, pool, scorer, cfg, logger, nil)
}

func RunSweepWithMetrics(ctx context.Context, pool *pgxpool.Pool, scorer *seqscore.Scorer, cfg Config, logger zerolog.Logger, m *metrics.Metrics) error {
	refreshMaterializedViews(ctx, pool, logger)
	checks := []struct {
		alertType string
		fn        func(context.Context) (int, error)
	}{
		{"near_duplicate_cluster", func(ctx context.Context) (int, error) { return CheckNearDuplicates(ctx, pool, cfg) }},
		{"rogue_cluster", func(ctx context.Context) (int, error) { return CheckRogueClusters(ctx, pool) }},
		{"deauth_precursor", func(ctx context.Context) (int, error) { return CheckDeauthPrecursors(ctx, pool, scorer, cfg) }},
		{"high_risk_ap", func(ctx context.Context) (int, error) { return CheckHighRiskAPs(ctx, pool, cfg.APRiskThreshold) }},
		{"embedding_drift", func(ctx context.Context) (int, error) { return CheckEmbeddingDrift(ctx, pool) }},
		{"zero_trust_overlay_risk", func(ctx context.Context) (int, error) { return CheckZeroTrustOverlayRisk(ctx, pool, cfg) }},
		{"dns_privacy_leak", func(ctx context.Context) (int, error) { return CheckDNSPrivacyLeaks(ctx, pool, cfg) }},
		{"rf_impossible_travel", func(ctx context.Context) (int, error) { return CheckRFImpossibleTravel(ctx, pool, cfg) }},
		{"rogue_rf_path", func(ctx context.Context) (int, error) { return CheckRogueRFPaths(ctx, pool, cfg) }},
	}
	successfulChecks := 0
	var lastErr error
	for _, check := range checks {
		inserted, err := check.fn(ctx)
		if err != nil {
			lastErr = err
			logger.Warn().Err(err).Str("alert_type", check.alertType).Msg("alert check failed")
			continue
		}
		successfulChecks++
		if m != nil && inserted > 0 {
			m.AlertsInserted.WithLabelValues(check.alertType).Add(float64(inserted))
		}
	}
	if successfulChecks == 0 {
		if lastErr != nil {
			return fmt.Errorf("all alert checks failed: %w", lastErr)
		}
		return fmt.Errorf("all alert checks failed")
	}
	return nil
}

func refreshMaterializedViews(ctx context.Context, pool *pgxpool.Pool, logger zerolog.Logger) {
	statements := map[string]string{
		"v_device_repetition_score": "REFRESH MATERIALIZED VIEW CONCURRENTLY v_device_repetition_score",
		"mv_ap_risk_score":          "REFRESH MATERIALIZED VIEW CONCURRENTLY mv_ap_risk_score",
	}
	var wg sync.WaitGroup
	for name, statement := range statements {
		wg.Add(1)
		go func(name, statement string) {
			defer wg.Done()
			refreshCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			if _, err := pool.Exec(refreshCtx, statement); err != nil {
				logger.Warn().Err(err).Str("view", name).Msg("materialized view refresh failed")
			}
		}(name, statement)
	}
	wg.Wait()
}

func defaultConfig() Config {
	return Config{
		NearDupThreshold:   10,
		APRiskThreshold:    0.75,
		GraphMaxDepth:      3,
		SeqThreshold:       -15.0,
		TravelMaxSpeedMPS:  50.0,
		DNSLookbackMinutes: 15,
	}
}

func envInt64(key string, fallback int64) int64 {
	if raw := os.Getenv(key); raw != "" {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil {
			return parsed
		} else {
			log.Warn().Err(err).Str("env", key).Str("value", raw).Int64("fallback", fallback).Msg("invalid integer env; using fallback")
		}
	}
	return fallback
}

func envFloat64(key string, fallback float64) float64 {
	if raw := os.Getenv(key); raw != "" {
		if parsed, err := strconv.ParseFloat(raw, 64); err == nil {
			return parsed
		} else {
			log.Warn().Err(err).Str("env", key).Str("value", raw).Float64("fallback", fallback).Msg("invalid float env; using fallback")
		}
	}
	return fallback
}
