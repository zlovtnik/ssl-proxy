package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/contract"
	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/health"
	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/log"
	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/metrics"
	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/sync"
	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/validate"
	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/vault"
)

func main() {
	dryRun := flag.Bool("dry-run", false, "validate and dry-run without writing")
	contractPath := flag.String("contract", "cyber-stack/platform-input-contract.yaml", "path to platform-input-contract.yaml")
	lockTTL := flag.Int("lock-ttl", 600, "lock TTL in seconds")
	flag.Parse()

	logger := log.New()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	metricsServer := metrics.NewServer()
	go metricsServer.ListenAndServe()

	healthServer := health.NewServer()
	go healthServer.ListenAndServe()

	exitCode := run(ctx, logger, *dryRun, *contractPath, *lockTTL, metricsServer, healthServer)
	cancel()
	time.Sleep(100 * time.Millisecond)
	os.Exit(exitCode)
}

func run(ctx context.Context, logger *log.Logger, dryRun bool, contractPath string, lockTTL int, metricsServer *metrics.Server, healthServer *health.Server) int {
	start := time.Now()
	metrics.SetRunStart(start)

	c, err := contract.Load(contractPath)
	if err != nil {
		logger.Error("failed to load contract", "error", err)
		metrics.RecordRun("contract_error")
		healthServer.SetStatus("error", "contract load failed")
		return 1
	}
	logger.Info("contract loaded", "inputs", len(c.Inputs))

	vaultClient, err := vault.NewClient()
	if err != nil {
		logger.Error("failed to create vault client", "error", err)
		metrics.RecordRun("vault_error")
		healthServer.SetStatus("error", "vault client failed")
		return 1
	}

	secretData, err := sync.ReadAllVault(ctx, logger, vaultClient, c)
	if err != nil {
		logger.Error("failed to read vault secrets", "error", err)
		metrics.RecordRun("vault_read_error")
		healthServer.SetStatus("error", "vault read failed")
		return 1
	}
	logger.Info("all vault secrets read successfully", "count", len(secretData))

	if err := validate.All(c, secretData); err != nil {
		logger.Error("validation failed", "error", err)
		metrics.RecordRun("validation_error")
		healthServer.SetStatus("error", "validation failed")
		return 1
	}
	logger.Info("all validations passed")

	if dryRun {
		logger.Info("dry run complete")
		metrics.RecordRun("dry_run")
		healthServer.SetStatus("ok", "dry run complete")
		return 0
	}

	if err := sync.WriteAll(ctx, logger, c, secretData, lockTTL); err != nil {
		logger.Error("sync failed", "error", err)
		metrics.RecordRun("sync_error")
		healthServer.SetStatus("error", "sync failed")
		return 1
	}

	logger.Info("sync complete", "duration", time.Since(start))
	metrics.RecordRun("success")
	metrics.RecordInputsWritten(len(c.Inputs))
	healthServer.SetStatus("ok", fmt.Sprintf("sync complete at %s", time.Now().Format(time.RFC3339)))
	return 0
}
