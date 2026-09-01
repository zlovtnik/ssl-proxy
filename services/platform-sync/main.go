package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
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

type options struct {
	dryRun       bool
	contractPath string
	lockTTL      int
	namespace    string
}

func main() {
	os.Exit(realMain())
}

func realMain() int {
	logger := log.New()
	options, err := parseOptions(os.Args[1:], os.Getenv)
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	recorder := metrics.NewRecorder()
	healthRecorder := health.NewRecorder()
	return run(ctx, logger, options, recorder, healthRecorder)
}

func parseOptions(args []string, getenv func(string) string) (options, error) {
	configured := options{
		contractPath: envOr(getenv, "CONTRACT_PATH", "cyber-stack/platform-input-contract.yaml"),
		namespace:    envOr(getenv, "SYNC_NAMESPACE", "prod-ssl-proxy"),
		lockTTL:      600,
	}
	if value := strings.TrimSpace(getenv("SYNC_DRY_RUN")); value != "" {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return options{}, fmt.Errorf("SYNC_DRY_RUN: %w", err)
		}
		configured.dryRun = parsed
	}
	if value := strings.TrimSpace(getenv("SYNC_LOCK_TTL_SECONDS")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return options{}, fmt.Errorf("SYNC_LOCK_TTL_SECONDS: %w", err)
		}
		configured.lockTTL = parsed
	}

	flags := flag.NewFlagSet("platform-sync", flag.ContinueOnError)
	flags.BoolVar(&configured.dryRun, "dry-run", configured.dryRun, "validate and perform Kubernetes server-side dry-runs without applying")
	flags.StringVar(&configured.contractPath, "contract", configured.contractPath, "path to platform-input-contract.yaml")
	flags.IntVar(&configured.lockTTL, "lock-ttl", configured.lockTTL, "lock TTL in seconds")
	flags.StringVar(&configured.namespace, "namespace", configured.namespace, "target Kubernetes namespace")
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	if configured.contractPath == "" || configured.namespace == "" {
		return options{}, fmt.Errorf("contract path and namespace must be non-empty")
	}
	if configured.lockTTL <= 0 {
		return options{}, fmt.Errorf("lock TTL must be positive")
	}
	return configured, nil
}

func envOr(getenv func(string) string, name, fallback string) string {
	if value := strings.TrimSpace(getenv(name)); value != "" {
		return value
	}
	return fallback
}

func run(ctx context.Context, logger *log.Logger, configured options, recorder *metrics.Recorder, healthRecorder *health.Recorder) int {
	start := time.Now()
	recorder.SetRunStart(start)

	c, err := contract.Load(configured.contractPath)
	if err != nil {
		return fail(logger, recorder, healthRecorder, "contract_error", "contract load failed", err)
	}
	if c.Namespace != configured.namespace {
		return fail(logger, recorder, healthRecorder, "contract_error", "namespace mismatch", fmt.Errorf("contract namespace %s does not match configured namespace %s", c.Namespace, configured.namespace))
	}
	logger.Info("contract loaded", "inputs", len(c.Inputs), "namespace", c.Namespace)

	vaultClient, err := vault.NewClient()
	if err != nil {
		return fail(logger, recorder, healthRecorder, "vault_error", "Vault client failed", err)
	}
	if err := vaultClient.RenewSelf(ctx); err != nil {
		return fail(logger, recorder, healthRecorder, "vault_error", "Vault token renewal failed", err)
	}
	secretData, err := sync.ReadAllVault(ctx, logger, vaultClient, c)
	if err != nil {
		return fail(logger, recorder, healthRecorder, "vault_read_error", "Vault read failed", err)
	}
	logger.Info("all declared Vault inputs read", "count", len(secretData))

	if err := validate.All(ctx, c, secretData); err != nil {
		return fail(logger, recorder, healthRecorder, "validation_error", "validation failed", err)
	}
	logger.Info("all validations passed")

	objectsChanged, err := sync.WriteAll(ctx, logger, c, secretData, configured.lockTTL, configured.dryRun)
	if err != nil {
		return fail(logger, recorder, healthRecorder, "sync_error", "Kubernetes sync failed", err)
	}
	if configured.dryRun {
		logger.Info("dry run complete", "duration", time.Since(start))
		recordRun(logger, recorder, "dry_run", 0, 0)
		recordHealth(logger, healthRecorder, "ok", "validation and Kubernetes server-side dry-run complete")
		return 0
	}

	duration := time.Since(start)
	logger.Info("sync complete", "duration", duration)
	recordRun(logger, recorder, "success", len(c.Inputs), objectsChanged)
	recordHealth(logger, healthRecorder, "ok", fmt.Sprintf("sync complete at %s", time.Now().UTC().Format(time.RFC3339)))
	return 0
}

func fail(logger *log.Logger, recorder *metrics.Recorder, healthRecorder *health.Recorder, result, message string, err error) int {
	logger.Error(message, "error", err)
	recordRun(logger, recorder, result, 0, 0)
	recordHealth(logger, healthRecorder, "error", message)
	return 1
}

func recordRun(logger *log.Logger, recorder *metrics.Recorder, result string, inputs, objectsChanged int) {
	if err := recorder.RecordRun(result, inputs, objectsChanged); err != nil {
		logger.Error("failed to persist metrics", "error", err)
	}
}

func recordHealth(logger *log.Logger, recorder *health.Recorder, status, message string) {
	if err := recorder.SetStatus(status, message); err != nil {
		logger.Error("failed to persist health status", "error", err)
	}
}
