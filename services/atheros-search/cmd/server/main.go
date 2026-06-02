package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/api"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/auth"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/config"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/db"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/embed"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/health"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/ingest"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/metrics"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/search"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		if err := runHealthcheck(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatal().Err(err).Msg("load config")
	}
	level, err := zerolog.ParseLevel(cfg.LogLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)
	logger := log.With().Str("service", "atheros-search").Logger()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := db.NewPool(ctx, cfg.PostgresDSN)
	if err != nil {
		logger.Fatal().Err(err).Msg("connect postgres")
	}
	defer pool.Close()

	tokenAuth, err := auth.NewTokenAuth(cfg.APIKeySHA256)
	if err != nil {
		logger.Fatal().Err(err).Msg("configure auth")
	}

	var embedder embed.Client
	if cfg.EmbeddingBackend == "" {
		embedder = embed.NoopClient{Dimensions: cfg.EmbeddingDimensions}
		logger.Warn().Msg("embedding backend not configured; using zero-vector embedder")
	} else {
		embedder = embed.NewCircuitClient(embed.NewHTTPClient(cfg.EmbeddingBackend, cfg.EmbeddingModel, cfg.EmbeddingDimensions))
	}
	m := metrics.New()
	embedder = embed.CachedClient{
		Inner: embedder,
		Cache: embed.NewQueryCache(4096, 60*time.Second),
		Hits:  m.EmbeddingCacheHits.Inc,
		Miss:  m.EmbeddingCacheMiss.Inc,
	}

	svc := search.NewService(pool.Pool, embedder, cfg, m, logger)
	readiness := &health.Readiness{DB: pool, Embedder: embedder}
	ingest.StartFreshnessConsumer(ctx, pool.Pool, cfg, logger)
	ingest.StartEmbedder(ctx, pool.Pool, cfg, embedder, logger)

	if _, err := metrics.StartServer(ctx, cfg.MetricsPort); err != nil {
		logger.Fatal().Err(err).Msg("start metrics server")
	}
	if _, err := api.StartGRPC(ctx, cfg.GRPCPort, svc, tokenAuth, logger); err != nil {
		logger.Fatal().Err(err).Msg("start grpc server")
	}
	if _, err := api.StartHTTP(ctx, cfg.HTTPPort, svc, readiness, tokenAuth, logger); err != nil {
		logger.Fatal().Err(err).Msg("start http gateway")
	}

	<-ctx.Done()
	logger.Info().Msg("shutdown requested")
	time.Sleep(250 * time.Millisecond)
	os.Exit(0)
}

func runHealthcheck() error {
	port := 8080
	if raw := os.Getenv("ATHSEARCH_HTTP_PORT"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("invalid ATHSEARCH_HTTP_PORT: %w", err)
		}
		port = parsed
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", port))
	if err != nil {
		return fmt.Errorf("healthz request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("healthz returned %s", resp.Status)
	}
	return nil
}
