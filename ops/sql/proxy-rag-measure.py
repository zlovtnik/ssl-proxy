#!/usr/bin/env python3
"""Bounded, read-only proxy RAG audit. Uses libpq environment/service credentials."""
import argparse
import datetime as dt
import hashlib
import json
import math
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
MODEL = "nomic-embed-text-v2-moe"
SAFE_ENV = {
    "OCTOPUS_ENABLED_PROCESSORS", "OCTOPUS_CONSUMERS_ENABLED",
    "ATHSEARCH_WORKER_ENABLED", "ATHSEARCH_WORKER_COUNT", "ATHSEARCH_WORKER_SOURCE_KINDS",
    "ATHSEARCH_EMBEDDING_BATCH_SIZE", "ATHSEARCH_EMBEDDING_REQUEST_CONCURRENCY",
    "ATHSEARCH_EMBEDDING_QUERY_RESERVED_SLOTS", "ATHSEARCH_EMBEDDING_MAX_TOKENS",
    "ATHSEARCH_EMBEDDING_MAX_CHUNKS_PER_INPUT", "ATHSEARCH_EMBEDDING_INPUT_REVISION",
    "ATHSEARCH_EMBEDDING_PREFIX_OWNER",
    "ATHSEARCH_EMBEDDING_MODEL", "ATHSEARCH_EMBEDDING_DIMENSIONS",
}


def run(command, cwd=ROOT, timeout=30):
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True,
                          timeout=timeout, check=True).stdout.strip()


def timestamp(value):
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamps require a timezone")
    return parsed.astimezone(dt.timezone.utc)


def capacity(values):
    """Fail closed until measured capacity and operator budgets are supplied."""
    if not isinstance(values, dict):
        raise ValueError("capacity sheet must be a JSON object")
    required = (
        "interactive_p95_ms", "interactive_p99_ms", "current_ingest_lag_seconds",
        "jobs_per_second", "tokens_per_second", "backend_error_rate", "db_wait_ms",
        "db_lock_waits", "wal_bytes_per_second", "memory_bytes", "queue_growth_per_second",
        "pending_jobs", "current_reserve_jobs_per_second", "queue_headroom_jobs",
        "max_scan_rows", "max_transaction_ms", "pause_p99_ms", "pause_ingest_lag_seconds",
        "pause_backend_error_rate", "pause_memory_bytes", "measured_duration_seconds",
    )
    missing = [key for key in required if values.get(key) is None]
    if missing:
        return {"status": "blocked_unmeasured", "missing": missing, "drain_seconds": None}
    if any(isinstance(values[k], bool) or not isinstance(values[k], (int, float)) or
           not math.isfinite(values[k]) or values[k] < 0 for k in required):
        raise ValueError("capacity values must be finite nonnegative measurements")
    if values["backend_error_rate"] > 1 or values["pause_backend_error_rate"] > 1:
        raise ValueError("error rates must be fractions")
    if any(values[k] <= 0 for k in ("measured_duration_seconds", "max_scan_rows", "max_transaction_ms",
                                   "pause_p99_ms", "pause_memory_bytes", "queue_headroom_jobs")):
        raise ValueError("measurement duration and operational limits must be positive")
    available = values["jobs_per_second"] - values["current_reserve_jobs_per_second"]
    paused = (available <= 0 or values["interactive_p99_ms"] >= values["pause_p99_ms"] or
              values["current_ingest_lag_seconds"] >= values["pause_ingest_lag_seconds"] or
              values["backend_error_rate"] >= values["pause_backend_error_rate"] or
              values["memory_bytes"] >= values["pause_memory_bytes"] or
              values["queue_growth_per_second"] > 0)
    return {"status": "pause" if paused else "measured_candidate_requires_review",
            "backfill_jobs_per_second": max(0, available),
            "drain_seconds": None if paused else values["pending_jobs"] / available,
            "inputs": values, "limitation": "steady-state estimate; not recovery authorization"}


def metadata(live=False, namespace="prod-ssl-proxy"):
    result = {"measured_at": dt.datetime.now(dt.timezone.utc).isoformat(),
              "audit_version": "proxy-rag-measure-v1", "revisions": {},
              "schema_files": {}, "live": {"status": "unavailable_not_requested"},
              "live_image_ids": "unavailable_requires_live_inspection",
              "worker_settings": "unavailable_requires_live_inspection",
              "actual_processor_enablement": "unavailable_requires_runtime_attestation",
              "installed_vector_extension": "unavailable_requires_database_audit",
              "model": MODEL, "embedding_dimensions": 768,
              "preprocessing_identity": "unknown_legacy_unmeasured",
              "desired_images": "unavailable_not_rendered",
              "retained_source_range": "unavailable_requires_database_audit",
              "processor_dependency_closure": "unavailable_requires_runtime_attestation",
              "backend_artifact_preprocessing": "unmeasured", "historical_175519": "unverified_historical_input"}
    for name, path in (("parent", ROOT), ("octopus", ROOT / "services/octopus"),
                       ("integration_console", ROOT / "apps/integration-console")):
        try:
            checkout_root = pathlib.Path(run(["git", "rev-parse", "--show-toplevel"], path)).resolve()
        except (OSError, subprocess.SubprocessError):
            checkout_root = None
        if checkout_root != path.resolve():
            result["revisions"][name] = {"status": "unavailable_not_checked_out"}
            continue
        result["revisions"][name] = {"head": run(["git", "rev-parse", "HEAD"], path),
                                     "dirty": bool(run(["git", "status", "--porcelain"], path))}
    for domain in ("octopus_core", "atheros_search"):
        path = ROOT / "sql/postgres" / domain / "manifest.yaml"
        result["schema_files"][domain] = {"manifest_file_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                           "live_attestation": "unavailable_without_database"}
    # Desired file hashes do not assert effective rendered configuration or live state.
    result["desired_files"] = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in (
        ROOT / "cyber-stack/base/atheros-search/deployment.yaml",
        ROOT / "cyber-stack/matrix/prod/patches/java-coordinator-broker-drain.yaml",
        ROOT / "cyber-stack/matrix/prod/patches/atheros-search.yaml")}
    if live:
        try:
            data = json.loads(run(["kubectl", "get", "pods", "-n", namespace, "-o", "json"], timeout=15))
            workloads = []
            for pod in data["items"]:
                if not any(k in pod["metadata"]["name"] for k in ("java-coordinator", "atheros-search")):
                    continue
                for container in pod["spec"]["containers"]:
                    settings = {e["name"]: e.get("value", "unavailable_valueFrom")
                                for e in container.get("env", []) if e["name"] in SAFE_ENV}
                    statuses = pod.get("status", {}).get("containerStatuses", [])
                    image_ids = [s.get("imageID", "unavailable") for s in statuses if s["name"] == container["name"]]
                    workloads.append({"container": container["name"], "image": container["image"],
                                      "image_ids": image_ids, "settings": settings,
                                      "envFrom": "unresolved" if container.get("envFrom") else "absent"})
            result["live"] = {"status": "observed_pod_specs_only", "workloads": workloads,
                              "limitation": "spec settings are not runtime enablement or dependency closure"}
            result["live_image_ids"] = [w["image_ids"] for w in workloads]
            result["worker_settings"] = [{k: v for k, v in w["settings"].items() if k.startswith("ATHSEARCH_")}
                                         for w in workloads]
        except (OSError, subprocess.SubprocessError, ValueError, KeyError) as error:
            result["live"] = {"status": "unavailable_read_failed", "reason": type(error).__name__}
    return result


def psql(script, variables, timeout):
    command = ["psql", "-X", "-w", "-qAt", "--set=ON_ERROR_STOP=1"]
    for key, value in variables.items():
        command.append(f"--set={key}={value}")
    command.extend(["--file", str(ROOT / "ops/sql" / script)])
    return json.loads(run(command, timeout=timeout))


def measure(args):
    if not args.window_start or not args.window_end:
        raise ValueError("database audits require explicit window bounds")
    start, end = timestamp(args.window_start), timestamp(args.window_end)
    if not dt.timedelta(0) < end - start <= dt.timedelta(days=1):
        raise ValueError("audit windows must be positive and at most one day")
    if not 1 <= args.page_size <= 1000 or not 1 <= args.max_pages <= 100 or not 1 <= args.statement_timeout_ms <= 30000:
        raise ValueError("limits: page size 1..1000, pages 1..100, timeout 1..30000 ms")
    variables = {"window_start": start.isoformat(), "window_end": end.isoformat(),
                 "after_time": start.isoformat(), "after_id": "", "document_after_time": start.isoformat(),
                 "document_after_id": "00000000-0000-0000-0000-000000000000", "page_size": args.page_size,
                 "model": MODEL, "statement_timeout_ms": args.statement_timeout_ms}
    pages = []
    for _ in range(args.max_pages):
        page = psql("proxy-rag-coverage.sql", variables, args.statement_timeout_ms / 1000 + 10)
        for field, time_key, id_key in (("source_cursor", "after_time", "after_id"),
                                        ("document_cursor", "document_after_time", "document_after_id")):
            cursor = page.pop(field)
            if cursor is not None:
                cursor_time, previous_time = timestamp(cursor[0]), timestamp(variables[time_key])
                if cursor_time < previous_time or (cursor_time == previous_time and cursor[1] == variables[id_key]):
                    raise ValueError("nonadvancing audit cursor")
                variables[time_key], variables[id_key] = cursor
        pages.append(page)
        if page["source_rows"] < args.page_size and page["document_rows"] < args.page_size:
            return {"status": "window_pages_exhausted", "pages": pages,
                    "snapshot": "repeatable read per page; concurrent mutations require a frozen replica/cutoff for exact campaign totals"}
    return {"status": "page_budget_exhausted", "pages": pages, "complete": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--namespace", default="prod-ssl-proxy")
    parser.add_argument("--database", action="store_true", help="use libpq environment/service, never a command-line credential")
    parser.add_argument("--window-start")
    parser.add_argument("--window-end")
    parser.add_argument("--page-size", type=int, default=500)
    parser.add_argument("--max-pages", type=int, default=1)
    parser.add_argument("--statement-timeout-ms", type=int, default=5000)
    parser.add_argument("--capacity", type=pathlib.Path, help="JSON measurements and reviewed budgets")
    parser.add_argument("--blocked-windows", action="store_true", help="also audit up to max-pages closed UTC hours")
    args = parser.parse_args()
    try:
        result = metadata(args.live, args.namespace)
        result["capacity"] = capacity(json.loads(args.capacity.read_text()) if args.capacity else {})
        result["coverage"] = measure(args) if args.database else {"status": "unavailable_not_requested"}
        if args.database:
            result["database_baseline"] = psql("proxy-rag-baseline.sql", {}, 15)
            result["installed_vector_extension"] = result["database_baseline"]["vector_extension"]
            result["retained_source_range"] = {k: result["database_baseline"][k] for k in ("source_first", "source_last")}
            if args.blocked_windows:
                start, end = timestamp(args.window_start), timestamp(args.window_end)
                if start.minute or start.second or start.microsecond or end.minute or end.second or end.microsecond:
                    raise ValueError("blocked window audits require whole UTC hours")
                windows = []
                cursor = start
                while cursor < end and len(windows) < args.max_pages:
                    next_hour = cursor + dt.timedelta(hours=1)
                    windows.append(psql("proxy-rag-window-coverage.sql", {
                        "window_start": cursor.isoformat(), "window_end": next_hour.isoformat(),
                        "page_size": args.page_size, "statement_timeout_ms": args.statement_timeout_ms,
                    }, args.statement_timeout_ms / 1000 + 10))
                    cursor = next_hour
                result["blocked_windows"] = {"hours": windows, "hour_budget_exhausted": cursor < end}
        print(json.dumps(result, indent=2, sort_keys=True))
    except (OSError, subprocess.SubprocessError, ValueError, TypeError) as error:
        # Never print subprocess stderr: database errors can contain raw evidence or connection secrets.
        print(json.dumps({"status": "audit_failed", "error_type": type(error).__name__}), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
