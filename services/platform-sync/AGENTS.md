# AGENTS.md

## Scope
This file governs `services/platform-sync` relative to the repository root.

## Project Shape
- Go module: `github.com/zlovtnik/ssl-proxy/services/platform-sync`.
- `cmd/cred-gen/` creates a short-lived Kubernetes ServiceAccount token.
- `internal/contract/` loads and validates the platform input contract.
- `internal/vault/` reads secrets from Vault KV-v2.
- `internal/validate/` validates TLS chains, PostgreSQL, Loki, PgBouncer, and WireGuard.
- `internal/sync/` writes secrets and ConfigMaps to Kubernetes with locking and snapshots.
- `internal/log/` provides structured logging with secret redaction.
- `internal/metrics/` exposes Prometheus metrics on localhost:9105.
- `internal/health/` exposes health status on localhost:9106.

## Guardrails
- Never log secret values. The redacting logger replaces all 18 secret names with `[REDACTED]`.
- Read every Vault path before writing anything to Kubernetes.
- Perform server-side dry runs before real writes.
- Use optimistic concurrency (resourceVersion) for distributed locking.
- Keep the sync program as a platform-only identity; it must not share credentials with application workloads.
- The credential generator is host-only; never commit kubeconfig or Vault tokens to Git.
- Load the renewable read-only Vault token and Vault CA through systemd credentials; do not derive Vault access from the Kubernetes writer token.

## Commands
- Run tests: `go test ./...`
- Run tests with race detector: `go test -race ./...`
- Lint: `golangci-lint run`
- Build: `go build -o platform-sync .`
- Build cred-gen: `go build -o cred-gen ./cmd/cred-gen`

## Verification
- Run `go test ./...` for unit tests.
- Run `go test -tags=integration ./...` for integration tests (requires kind/k3d cluster).
- Run `golangci-lint run` for linting.
- Run `gosec ./...` for security checks.
