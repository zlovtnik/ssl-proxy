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
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/metrics"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/search"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/worker"
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
	zerolog.TimestampFieldName = "timestamp"
	zerolog.MessageFieldName = "event"
	zerolog.SetGlobalLevel(level)
	logger := log.With().Str("service", "atheros-search").Logger()
	logStartupConfig(logger, cfg)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := db.NewPool(ctx, db.Options{
		DSN:                  cfg.TiDBDSN,
		TLSCAFile:            cfg.TiDBTLSCAFile,
		TLSCertFile:          cfg.TiDBTLSCertFile,
		TLSKeyFile:           cfg.TiDBTLSKeyFile,
		TLSServerName:        cfg.TiDBTLSServerName,
		SchemaManifestSHA256: cfg.TiDBSchemaManifestSHA256,
		MaxOpenConns:         cfg.TiDBMaxOpenConns,
		MaxIdleConns:         cfg.TiDBMaxIdleConns,
		ConnMaxLifetime:      cfg.TiDBConnMaxLifetime,
		ConnMaxIdleTime:      cfg.TiDBConnMaxIdleTime,
	})
	if err != nil {
		logger.Fatal().Err(err).Msg("connect TiDB")
	}
	defer pool.Close()
	if cfg.SchemaReadyRequired {
		if err := health.WaitForSchemaReady(ctx, pool, cfg.SchemaReadyTimeout, cfg.SchemaReadyPollInterval, logger); err != nil {
			logger.Fatal().Err(err).Msg("schema readiness gate failed")
		}
	} else {
		logger.Warn().Msg("schema readiness gate disabled")
	}

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

	healthMon := worker.NewHealthMonitor(pool.DB)

	var workerPool *worker.Pool
	if cfg.WorkerEnabled {
		workerPool = worker.NewPool(pool.DB, &workerEmbedderAdapter{embedder: embedder}, worker.PoolConfig{
			WorkerCount:       cfg.WorkerCount,
			LeaseSeconds:      cfg.LeaseSeconds,
			PollInterval:      cfg.WorkerPollInterval,
			BatchSize:         cfg.EmbeddingBatchSize,
			WorkerID:          cfg.WorkerID,
			HealthPollEnabled: true,
		}, logger)
		workerPool.Start(ctx)
	} else {
		logger.Info().Msg("worker pool disabled (ATHSEARCH_WORKER_ENABLED=false)")
	}

	svc := search.NewService(pool.DB, embedder, cfg, m, logger)
	readiness := &health.Readiness{DB: pool, Embedder: embedder, SchemaReadyRequired: cfg.SchemaReadyRequired}

	metricsServer, err := metrics.StartServer(ctx, cfg.MetricsPort)
	if err != nil {
		logger.Fatal().Err(err).Msg("start metrics server")
	}
	grpcServer, err := api.StartGRPC(ctx, cfg.GRPCPort, svc, tokenAuth, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("start grpc server")
	}
	httpServer, err := api.StartHTTP(ctx, cfg.HTTPPort, cfg.CORSAllowedOrigins, svc, readiness, tokenAuth, healthMon, cfg.WSEnabled, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("start http gateway")
	}

	<-ctx.Done()
	logger.Info().Msg("shutdown requested")
	if workerPool != nil {
		workerPool.Stop()
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Warn().Err(err).Msg("http gateway shutdown failed")
	}
	if err := metricsServer.Shutdown(shutdownCtx); err != nil {
		logger.Warn().Err(err).Msg("metrics server shutdown failed")
	}
	grpcStopped := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(grpcStopped)
	}()
	select {
	case <-grpcStopped:
	case <-shutdownCtx.Done():
		grpcServer.Stop()
		logger.Warn().Err(shutdownCtx.Err()).Msg("grpc graceful shutdown timed out")
	}
}

func logStartupConfig(logger zerolog.Logger, cfg config.Config) {
	logger.Info().
		Bool("embedding_backend_configured", cfg.EmbeddingBackend != "").
		Str("embedding_model", cfg.EmbeddingModel).
		Int("dense_overfetch_factor", cfg.DenseOverfetchFactor).
		Bool("worker_enabled", cfg.WorkerEnabled).
		Int("worker_count", cfg.WorkerCount).
		Msg("atheros-search TiDB query facade configured")
}

type workerEmbedderAdapter struct {
	embedder embed.Client
}

func (a *workerEmbedderAdapter) Embed(ctx context.Context, texts []string, kind string) ([][]float32, error) {
	return a.embedder.Embed(ctx, texts, embed.Kind(kind))
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
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/readyz", port))
	if err != nil {
		return fmt.Errorf("readyz request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("readyz returned %s", resp.Status)
	}
	return nil
}
