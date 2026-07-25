"""Wave-based deployment execution for stackctl."""

from __future__ import annotations

import asyncio
import contextlib
import copy
import json
import os
import re
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from .core import (
    Component,
    StackConfig,
    generate_effective_values,
    resolve_dependencies,
    staged_waves,
)
from .gates import parse_timeout_seconds, wait_for_gates
from .shell import ShellError, helm, kubectl

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

REDACTED_KEY_PATTERNS = re.compile(
    r"password|secret|token|privatekey|apikey|credentials",
    re.IGNORECASE,
)


@dataclass
class DeployOptions:
    namespace: str
    context: str | None = None
    kubeconfig: str | None = None
    root_dir: str | Path | None = None
    umbrella_values: list[dict[str, Any]] = field(default_factory=list)
    target_component: str | None = None
    from_wave: int | None = None
    dry_run: bool = False
    verbose: bool = False
    keep_artifacts: bool = False
    work_dir: str | Path | None = None
    artifact_dir: str | Path | None = None
    max_parallel: int = 4
    include_descendants: bool = False
    runtime_overrides: dict[str, Any] = field(default_factory=dict)


@dataclass
class ComponentResult:
    component: str
    success: bool
    error: str | None = None
    duration: float = 0.0
    skipped: bool = False


@dataclass
class DeployResult:
    success: bool
    waves_completed: int
    total_waves: int
    component_results: list[ComponentResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Run directory management
# ---------------------------------------------------------------------------


def _create_run_dir(base: str | Path | None = None) -> Path:
    """Create a timestamped run directory for artifacts."""
    run_base = Path(base) if base else Path("stackctl-artifacts")
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
    run_id = os.urandom(4).hex()
    run_dir = run_base / f"{ts}-{run_id}"
    run_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    (run_dir / "effective-values").mkdir(mode=0o700)
    (run_dir / "logs").mkdir(mode=0o700)
    (run_dir / "rendered").mkdir(mode=0o700)
    return run_dir


def _redact_value(key: str, value: Any) -> Any:
    """Redact sensitive values in a dict for diagnostic output."""
    if isinstance(value, dict):
        return {k: _redact_value(k, v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(key, item) for item in value]
    if isinstance(value, str) and REDACTED_KEY_PATTERNS.search(key):
        return "[REDACTED]"
    return value


def _redact_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Redact all sensitive keys in a dict."""
    return {k: _redact_value(k, v) for k, v in data.items()}


def _redact_text(value: str) -> str:
    """Conservatively remove diagnostic lines that may contain credentials."""

    return "\n".join(
        "[REDACTED LINE]" if REDACTED_KEY_PATTERNS.search(line) else line
        for line in value.splitlines()
    ) + ("\n" if value.endswith("\n") else "")


def _redact_manifest(value: str) -> str:
    """Redact Secret bodies and sensitive keys in a retained Helm manifest."""

    documents: list[str] = []
    for raw in yaml.safe_load_all(value):
        if not isinstance(raw, dict):
            continue
        if raw.get("kind") == "Secret":
            raw["data"] = {"redacted": "[REDACTED]"}
            raw.pop("stringData", None)
        raw = _redact_dict(raw)
        documents.append(yaml.safe_dump(raw, sort_keys=False).rstrip())
    return "\n---\n".join(documents) + ("\n" if documents else "")


def _save_effective_values(run_dir: Path, component_name: str, values: dict[str, Any]) -> None:
    """Save effective values to the run directory."""
    values_file = run_dir / "effective-values" / f"{component_name}.redacted.yaml"
    values_file.parent.mkdir(parents=True, exist_ok=True)
    with open(values_file, "w") as f:
        yaml.safe_dump(_redact_dict(values), f, default_flow_style=False)
    os.chmod(values_file, 0o600)


def _cleanup_run_dir(run_dir: Path) -> None:
    """Remove the run directory."""
    if run_dir.exists():
        shutil.rmtree(run_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Chart preparation
# ---------------------------------------------------------------------------


def _chart_has_dependencies(chart_path: Path) -> bool:
    """Check if a chart has a dependencies section in Chart.yaml."""
    chart_yaml = chart_path / "Chart.yaml"
    if not chart_yaml.exists():
        return False
    with open(chart_yaml) as f:
        data = yaml.safe_load(f)
    deps = data.get("dependencies") if isinstance(data, dict) else None
    return bool(deps)


_prepared_charts: set[Path] = set()


def prepare_chart(chart_path: Path) -> None:
    """Build dependencies once for explicit compatibility callers.

    Production render/deploy paths use :func:`prepared_chart_copy` instead.
    """
    resolved = chart_path.resolve()
    if resolved in _prepared_charts:
        return
    if not (resolved / "Chart.yaml").is_file():
        return
    if _chart_has_dependencies(resolved):
        helm("dependency", "build", str(resolved))
    _prepared_charts.add(resolved)


@contextlib.contextmanager
def prepared_chart_copy(chart_path: Path):
    """Yield a chart whose dependency build cannot rewrite the worktree."""

    with tempfile.TemporaryDirectory(prefix=f"stackctl-{chart_path.name}-") as temp:
        if not chart_path.is_dir():
            yield chart_path
            return
        temp_root = Path(temp)
        destination = temp_root / chart_path.name
        shutil.copytree(chart_path, destination, symlinks=False)
        common = chart_path.parent / "_common"
        if common.is_dir() and common.resolve() != chart_path.resolve():
            shutil.copytree(common, temp_root / "_common", symlinks=False)
        if _chart_has_dependencies(destination):
            helm("dependency", "build", str(destination))
        yield destination


def reset_prepared_charts() -> None:
    """Reset the set of prepared charts (for testing)."""
    _prepared_charts.clear()


# ---------------------------------------------------------------------------
# Helm operations
# ---------------------------------------------------------------------------


def _get_job_uid(
    name: str, namespace: str, context: str | None, kubeconfig: str | None
) -> str | None:
    """Get the UID of a Job, or None if it does not exist."""
    result = kubectl(
        "get",
        "job",
        name,
        "-n",
        namespace,
        "-o",
        "jsonpath={.metadata.uid}",
        "--ignore-not-found",
        context=context,
        kubeconfig=kubeconfig,
        check=False,
    )
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()
    return None


def _replace_job(
    name: str,
    namespace: str,
    context: str | None,
    kubeconfig: str | None,
    expected_release: str | None = None,
) -> str | None:
    """Replace a Job by recording its UID, deleting it, and returning the old UID.

    Returns the old UID if the Job existed, or None if it did not.
    """
    old_uid = _get_job_uid(name, namespace, context, kubeconfig)
    if old_uid is not None:
        if expected_release:
            owner = kubectl(
                "get",
                "job",
                name,
                "-n",
                namespace,
                "-o",
                "jsonpath={.metadata.annotations.meta\\.helm\\.sh/release-name}",
                context=context,
                kubeconfig=kubeconfig,
                check=False,
            )
            if owner.returncode != 0 or owner.stdout.strip() != expected_release:
                raise RuntimeError(
                    f"Refusing to replace Job {name!r}: expected Helm owner "
                    f"{expected_release!r}, found {owner.stdout.strip() or 'none'!r}"
                )
        kubectl(
            "delete",
            "job",
            name,
            "-n",
            namespace,
            "--wait=true",
            context=context,
            kubeconfig=kubeconfig,
        )
    return old_uid


def _wait_for_job_with_new_uid(
    name: str,
    namespace: str,
    old_uid: str | None,
    timeout_seconds: int,
    context: str | None,
    kubeconfig: str | None,
) -> str:
    """Poll until a Job exists with a UID different from old_uid.

    Returns the new UID.
    Raises RuntimeError on timeout.
    """
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        new_uid = _get_job_uid(name, namespace, context, kubeconfig)
        if new_uid is not None and new_uid != old_uid:
            return new_uid
        time.sleep(1)
    raise RuntimeError(
        f"Timed out waiting for Job {name!r} to appear with a new UID (old_uid={old_uid})"
    )


def _wait_for_job_complete_or_fail(
    name: str,
    namespace: str,
    timeout_seconds: int,
    context: str | None,
    kubeconfig: str | None,
) -> Any:
    """Wait for a Job to reach Complete or Failed condition.

    Raises RuntimeError on Failed condition or timeout.
    """
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        result = kubectl(
            "get",
            "job",
            name,
            "-n",
            namespace,
            "-o",
            'jsonpath={.status.conditions[?(@.type=="Complete"||@.type=="Failed")].type}',
            context=context,
            kubeconfig=kubeconfig,
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            conditions = result.stdout.strip().split()
            if "Failed" in conditions:
                raise RuntimeError(f"Job {name!r} reached Failed condition")
            if "Complete" in conditions:
                return
        time.sleep(2)
    raise RuntimeError(f"Timed out waiting for Job {name!r} to complete")


def _capture_job_logs(
    name: str,
    namespace: str,
    run_dir: Path,
    context: str | None,
    kubeconfig: str | None,
) -> None:
    """Capture Job logs to the run directory on failure."""
    log_file = run_dir / f"{name}.log"
    try:
        result = kubectl(
            "logs",
            "job/" + name,
            "-n",
            namespace,
            context=context,
            kubeconfig=kubeconfig,
            check=False,
        )
        if result.stdout:
            log_file.write_text(_redact_text(result.stdout))
            os.chmod(log_file, 0o600)
    except Exception:
        pass


def _helm_release_status(
    release: str, namespace: str, context: str | None, kubeconfig: str | None
) -> str | None:
    """Get the current Helm release status, or None if not found."""
    result = helm(
        "status",
        release,
        "-n",
        namespace,
        "--output",
        "json",
        context=context,
        kubeconfig=kubeconfig,
        check=False,
    )
    if result.returncode != 0:
        return None
    try:
        payload = json.loads(result.stdout or "{}")
        return payload.get("info", {}).get("status")
    except (json.JSONDecodeError, AttributeError, TypeError):
        return None


def _helm_upgrade(
    component: Component,
    effective_values: dict[str, Any],
    values_file: Path,
    namespace: str,
    context: str | None,
    kubeconfig: str | None,
    dry_run: bool = False,
    wait_for_jobs: bool = True,
) -> None:
    """Run helm upgrade --install for a component."""
    release = component.release
    chart = component.chart
    if not chart:
        raise ValueError(f"Helm release {release!r} has no chart")

    args: list[str] = ["upgrade", "--install", release, chart]
    args.extend(["-n", namespace, "--create-namespace"])
    args.extend(["-f", str(values_file)])
    args.extend(["--server-side=true", "--wait=watcher"])
    if wait_for_jobs:
        args.append("--wait-for-jobs")

    timeout = component.timeout or "10m"
    args.extend(["--timeout", timeout])

    if dry_run:
        args.append("--dry-run=server")

    if component.rollback_on_failure:
        args.extend(["--rollback-on-failure", "--history-max", "5"])

    return helm(*args, context=context, kubeconfig=kubeconfig)


def _helm_rollback(
    release: str,
    namespace: str,
    context: str | None,
    kubeconfig: str | None,
) -> None:
    """Rollback a Helm release to revision 0 (last successful)."""
    helm(
        "rollback",
        release,
        "0",
        "-n",
        namespace,
        "--wait",
        context=context,
        kubeconfig=kubeconfig,
    )


def _capture_failure_diagnostics(
    config: StackConfig,
    failed_names: list[str],
    options: DeployOptions,
    run_dir: Path,
    run_started: datetime,
) -> None:
    """Capture bounded, redacted diagnostics for failed components."""

    diagnostics_dir = run_dir / "diagnostics"
    diagnostics_dir.mkdir(exist_ok=True, mode=0o700)

    events = kubectl(
        "get",
        "events",
        "-n",
        options.namespace,
        "-o",
        "json",
        context=options.context,
        kubeconfig=options.kubeconfig,
        check=False,
    )
    if events.returncode == 0:
        try:
            payload = json.loads(events.stdout or "{}")
            payload["items"] = [
                item
                for item in payload.get("items", [])
                if datetime.fromisoformat(
                    item.get("eventTime")
                    or item.get("lastTimestamp")
                    or item.get("metadata", {}).get("creationTimestamp")
                    or "1970-01-01T00:00:00+00:00"
                )
                >= run_started
            ]
            path = diagnostics_dir / "events.json"
            path.write_text(json.dumps(_redact_dict(payload), indent=2) + "\n")
            os.chmod(path, 0o600)
        except (ValueError, TypeError):
            pass

    pvc = kubectl(
        "get",
        "pvc",
        "-n",
        options.namespace,
        "-o",
        "yaml",
        context=options.context,
        kubeconfig=options.kubeconfig,
        check=False,
    )
    if pvc.returncode == 0:
        path = diagnostics_dir / "pvcs.yaml"
        path.write_text(_redact_text(pvc.stdout or ""))
        os.chmod(path, 0o600)

    for name in failed_names:
        component = config.components[name]
        release = getattr(component, "release", None)
        if component.type in ("helm", "helm-job") and release:
            for command, suffix in (
                (("status", release, "-n", options.namespace, "-o", "json"), "status.json"),
                (("get", "manifest", release, "-n", options.namespace), "manifest.yaml"),
                (("get", "values", release, "-n", options.namespace, "-o", "yaml"), "values.yaml"),
            ):
                result = helm(
                    *command,
                    context=options.context,
                    kubeconfig=options.kubeconfig,
                    check=False,
                )
                if result.returncode != 0:
                    continue
                content = result.stdout or ""
                if suffix == "manifest.yaml":
                    content = _redact_manifest(content)
                elif suffix == "values.yaml":
                    parsed = yaml.safe_load(content)
                    content = yaml.safe_dump(
                        _redact_dict(parsed if isinstance(parsed, dict) else {}),
                        sort_keys=False,
                    )
                else:
                    content = _redact_text(content)
                path = diagnostics_dir / f"{name}.{suffix}"
                path.write_text(content)
                os.chmod(path, 0o600)

        selector = f"app.kubernetes.io/instance={release or name}"
        described = kubectl(
            "describe",
            "all",
            "-n",
            options.namespace,
            "-l",
            selector,
            context=options.context,
            kubeconfig=options.kubeconfig,
            check=False,
        )
        if described.stdout:
            path = diagnostics_dir / f"{name}.describe.txt"
            path.write_text(_redact_text(described.stdout))
            os.chmod(path, 0o600)

        logs = kubectl(
            "logs",
            "-n",
            options.namespace,
            "-l",
            selector,
            "--all-containers=true",
            "--tail=200",
            "--prefix=true",
            context=options.context,
            kubeconfig=options.kubeconfig,
            check=False,
        )
        if logs.stdout:
            path = diagnostics_dir / f"{name}.pods.log"
            path.write_text(_redact_text(logs.stdout))
            os.chmod(path, 0o600)


def _cluster_mutation_snapshot(options: DeployOptions) -> dict[str, Any]:
    """Capture release names and resource UIDs for dry-run mutation proof."""

    releases = helm(
        "list",
        "-A",
        "--all",
        "-o",
        "json",
        context=options.context,
        kubeconfig=options.kubeconfig,
        check=False,
    )
    inventory = kubectl(
        "get",
        "all,configmap,serviceaccount,pvc,ingress,networkpolicy",
        "-A",
        "-o",
        "json",
        context=options.context,
        kubeconfig=options.kubeconfig,
        check=False,
    )
    if releases.returncode != 0 or inventory.returncode != 0:
        raise RuntimeError("unable to capture server dry-run mutation baseline")
    release_payload = json.loads(releases.stdout or "[]")
    resource_payload = json.loads(inventory.stdout or "{}")
    return {
        "releases": sorted(
            (
                item.get("namespace", ""),
                item.get("name", ""),
                item.get("revision", ""),
                item.get("status", ""),
            )
            for item in release_payload
        ),
        "resources": sorted(
            (
                item.get("apiVersion", ""),
                item.get("kind", ""),
                item.get("metadata", {}).get("namespace", ""),
                item.get("metadata", {}).get("name", ""),
                item.get("metadata", {}).get("uid", ""),
            )
            for item in resource_payload.get("items", [])
        ),
    }


# ---------------------------------------------------------------------------
# Per-component deployment
# ---------------------------------------------------------------------------


def _repository_manifest_paths(
    component_name: str,
    paths: list[str],
    root_dir: str | Path | None,
) -> list[Path]:
    """Resolve manifest files without permitting traversal or symlink targets."""

    root = Path(root_dir or ".").resolve()
    if not paths:
        raise ValueError(f"Manifest component {component_name!r} has no paths")
    resolved: list[Path] = []
    for configured in paths:
        raw = Path(configured)
        candidate = raw if raw.is_absolute() else root / raw
        if candidate.is_symlink():
            raise ValueError(
                f"Manifest component {component_name!r} path cannot be a symlink: {configured}"
            )
        path = candidate.resolve()
        if root not in (path, *path.parents):
            raise ValueError(
                f"Manifest component {component_name!r} path leaves repository root: {configured}"
            )
        if not path.is_file() or path.suffix.lower() not in {".yaml", ".yml"}:
            raise ValueError(
                f"Manifest component {component_name!r} path is not a YAML file: {configured}"
            )
        resolved.append(path)
    return resolved


def _deploy_manifest(
    component_name: str,
    component: Any,
    options: DeployOptions,
    run_dir: Path,
) -> None:
    """Apply repository-owned manifests with a stable field manager."""

    output: list[str] = []
    for path in _repository_manifest_paths(
        component_name, getattr(component, "paths", []), options.root_dir
    ):
        args = [
            "apply",
            "--server-side=true",
            "--field-manager",
            getattr(component, "field_manager", "stackctl"),
            "-n",
            options.namespace,
            "-f",
            str(path),
        ]
        if options.dry_run:
            args.extend(["--dry-run=server", "-o", "yaml"])
        result = kubectl(
            *args,
            context=options.context,
            kubeconfig=options.kubeconfig,
        )
        output.extend([result.stdout or "", result.stderr or ""])
    log_path = run_dir / "logs" / f"{component_name}.kubectl.log"
    log_path.write_text("".join(output))
    os.chmod(log_path, 0o600)


def _run_external_checks(
    component_name: str,
    config: StackConfig,
    options: DeployOptions,
) -> None:
    """Execute an external-check component without creating cluster resources."""

    if options.dry_run:
        return
    from .cluster import smoke_component

    results = smoke_component(
        component_name,
        config,
        options.namespace,
        options.context,
        options.kubeconfig,
    )
    failures = [f"{item.subject}: {item.detail}" for item in results if not item.healthy]
    if failures:
        raise RuntimeError("; ".join(failures))


def deploy_component(
    component_name: str,
    config: StackConfig,
    options: DeployOptions,
    run_dir: Path,
) -> ComponentResult:
    """Deploy a single component through the full lifecycle.

    prepare effective values → helm dependency build → delete job (if helm-job)
    → helm upgrade --install → wait for gates → return result
    """
    start = time.monotonic()
    component = config.components[component_name]

    try:
        if component.type == "manifest":
            _deploy_manifest(component_name, component, options, run_dir)
            if not options.dry_run:
                wait_for_gates(
                    component.gates,
                    component_name,
                    options.namespace,
                    timeout=component.timeout,
                    context=options.context,
                    kubeconfig=options.kubeconfig,
                )
            return ComponentResult(
                component=component_name,
                success=True,
                duration=time.monotonic() - start,
            )
        if component.type == "external-check":
            _run_external_checks(component_name, config, options)
            return ComponentResult(
                component=component_name,
                success=True,
                duration=time.monotonic() - start,
            )

        chart_path = Path(options.root_dir or ".") / component.chart if component.chart else None
        if not chart_path:
            raise ValueError(f"Component {component_name!r} has no chart path")

        # 1. Generate effective values.
        effective = generate_effective_values(
            config,
            component_name,
            options.umbrella_values,
            runtime_overrides=options.runtime_overrides,
            root_dir=options.root_dir,
        )
        _save_effective_values(run_dir, component_name, effective)

        with tempfile.TemporaryDirectory(prefix=f"stackctl-values-{component_name}-") as temp:
            values_file = Path(temp) / "values.yaml"
            with open(values_file, "w") as f:
                yaml.safe_dump(effective, f, default_flow_style=False)
            os.chmod(values_file, 0o600)

            # 3. Replace a managed Job only after checking its Helm owner.
            old_job_uid: str | None = None
            job_name = component.release
            if component.type == "helm-job":
                assert component.job is not None
                job_name = getattr(component.job, "name", None) or component.release
                if component.job.rerun == "replace" and not options.dry_run:
                    old_job_uid = _replace_job(
                        job_name,
                        options.namespace,
                        options.context,
                        options.kubeconfig,
                        expected_release=component.release,
                    )

            # 4. Build and invoke Helm in an isolated chart copy.
            is_helm_job = component.type == "helm-job"
            with prepared_chart_copy(chart_path) as built_chart:
                if hasattr(component, "model_copy"):
                    deployable = component.model_copy(update={"chart": str(built_chart)})
                else:
                    deployable = copy.copy(component)
                    deployable.chart = str(built_chart)
                helm_result = _helm_upgrade(
                    deployable,
                    effective,
                    values_file,
                    options.namespace,
                    options.context,
                    options.kubeconfig,
                    dry_run=options.dry_run,
                    wait_for_jobs=not is_helm_job,
                )
            log_path = run_dir / "logs" / f"{component_name}.helm.log"
            log_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            stdout = helm_result.stdout if isinstance(helm_result.stdout, str) else ""
            stderr = helm_result.stderr if isinstance(helm_result.stderr, str) else ""
            log_path.write_text(stdout + stderr)
            os.chmod(log_path, 0o600)

        # 6. For helm-job: wait for new UID, then wait for Complete/Fail
        if is_helm_job and not options.dry_run:
            timeout_seconds = int(parse_timeout_seconds(component.timeout or "10m").rstrip("s"))
            _wait_for_job_with_new_uid(
                job_name,
                options.namespace,
                old_job_uid,
                timeout_seconds,
                options.context,
                options.kubeconfig,
            )
            try:
                _wait_for_job_complete_or_fail(
                    job_name,
                    options.namespace,
                    timeout_seconds,
                    options.context,
                    options.kubeconfig,
                )
            except RuntimeError:
                _capture_job_logs(
                    job_name,
                    options.namespace,
                    run_dir,
                    options.context,
                    options.kubeconfig,
                )
                raise

        # 7. Wait for gates (skip in dry-run)
        if not options.dry_run:
            wait_for_gates(
                component.gates,
                component.release,
                options.namespace,
                timeout=component.timeout,
                context=options.context,
                kubeconfig=options.kubeconfig,
            )

        duration = time.monotonic() - start
        return ComponentResult(
            component=component_name,
            success=True,
            duration=duration,
        )

    except (ShellError, RuntimeError, ValueError, OSError) as exc:
        duration = time.monotonic() - start

        # Rollback if configured
        if (
            component.type in ("helm", "helm-job")
            and component.rollback_on_failure
            and not options.dry_run
        ):
            with contextlib.suppress(ShellError):
                _helm_rollback(
                    component.release,
                    options.namespace,
                    options.context,
                    options.kubeconfig,
                )

        return ComponentResult(
            component=component_name,
            success=False,
            error=str(exc),
            duration=duration,
        )


# ---------------------------------------------------------------------------
# Wave deployment
# ---------------------------------------------------------------------------


async def _deploy_wave(
    wave: list[str],
    config: StackConfig,
    options: DeployOptions,
    run_dir: Path,
) -> list[ComponentResult]:
    """Deploy siblings concurrently in a bounded thread pool."""

    semaphore = asyncio.Semaphore(options.max_parallel)

    async def run(component_name: str) -> ComponentResult:
        async with semaphore:
            return await asyncio.to_thread(
                deploy_component, component_name, config, options, run_dir
            )

    results = await asyncio.gather(*(run(c) for c in wave), return_exceptions=True)
    converted: list[ComponentResult] = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            converted.append(
                ComponentResult(
                    component=wave[i],
                    success=False,
                    error=str(result),
                )
            )
        else:
            converted.append(result)
    return converted


async def deploy_stack(
    config: StackConfig,
    options: DeployOptions,
) -> DeployResult:
    """Deploy all components in wave order.

    - Each wave runs concurrently (asyncio.gather)
    - If one sibling fails: finish collecting, mark wave failed, stop
    - No next wave starts after a failure
    - Successful sibling upgrades are retained
    - No stateful data is deleted on failure
    """
    run_started = datetime.now(UTC)
    dry_run_baseline = (
        await asyncio.to_thread(_cluster_mutation_snapshot, options) if options.dry_run else None
    )
    waves = resolve_dependencies(
        config,
        target_component=options.target_component,
        from_wave=options.from_wave,
        include_descendants=options.include_descendants,
    )
    if hasattr(config, "model_copy") and (options.target_component or options.from_wave):
        from .cluster import component_health

        if options.from_wave:
            bootstrap, numbered = staged_waves(config)
            earlier = set(bootstrap)
            for wave in numbered[: options.from_wave - 1]:
                earlier.update(wave)
            health = component_health(
                config,
                earlier,
                options.namespace,
                options.context,
                options.kubeconfig,
            )
            degraded = sorted(name for name, healthy in health.items() if not healthy)
            if degraded:
                raise RuntimeError(
                    "--from-wave requires every earlier wave to be healthy; degraded: "
                    + ", ".join(degraded)
                )

        if options.target_component:
            dependencies: set[str] = set()
            pending = list(config.components[options.target_component].depends_on)
            while pending:
                name = pending.pop()
                if name in dependencies:
                    continue
                dependencies.add(name)
                pending.extend(config.components[name].depends_on)
            health = component_health(
                config,
                dependencies,
                options.namespace,
                options.context,
                options.kubeconfig,
            )
            selected = {
                name
                for wave in waves
                for name in wave
                if name not in dependencies or not health.get(name, False)
            }
            waves = [[name for name in wave if name in selected] for wave in waves]
            waves = [wave for wave in waves if wave]

    # Determine run directory
    if options.work_dir:
        run_dir = Path(options.work_dir)
        run_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        (run_dir / "effective-values").mkdir(exist_ok=True, mode=0o700)
        (run_dir / "logs").mkdir(exist_ok=True, mode=0o700)
        (run_dir / "rendered").mkdir(exist_ok=True, mode=0o700)
    else:
        run_dir = _create_run_dir(options.artifact_dir)
    plan_path = run_dir / "plan.json"
    plan_path.write_text(
        json.dumps(
            {
                "started_at": run_started.isoformat(),
                "namespace": options.namespace,
                "context": options.context,
                "dry_run": options.dry_run,
                "waves": waves,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    os.chmod(plan_path, 0o600)

    all_results: list[ComponentResult] = []
    waves_completed = 0
    overall_success = False

    try:
        for wave_index, wave in enumerate(waves):
            wave_num = wave_index + 1
            print(f"\n--- Wave {wave_num}/{len(waves)}: {', '.join(wave)} ---")

            wave_results = await _deploy_wave(wave, config, options, run_dir)
            all_results.extend(wave_results)

            wave_failed = any(not r.success for r in wave_results)
            if wave_failed:
                failed_names = [r.component for r in wave_results if not r.success]
                if not options.dry_run:
                    try:
                        await asyncio.to_thread(
                            _capture_failure_diagnostics,
                            config,
                            failed_names,
                            options,
                            run_dir,
                            run_started,
                        )
                    except Exception as exc:
                        diagnostic_error = run_dir / "diagnostics-error.txt"
                        diagnostic_error.write_text(_redact_text(str(exc)) + "\n")
                        os.chmod(diagnostic_error, 0o600)
                print(
                    f"\nWave {wave_num} FAILED: {', '.join(failed_names)}. "
                    f"Stopping deployment. Successful upgrades retained."
                )
                break

            waves_completed = wave_num
            print(f"Wave {wave_num} OK")

        overall_success = waves_completed == len(waves)
        if overall_success and dry_run_baseline is not None:
            after = await asyncio.to_thread(_cluster_mutation_snapshot, options)
            if after != dry_run_baseline:
                overall_success = False
                all_results.append(
                    ComponentResult(
                        component="dry-run-mutation-proof",
                        success=False,
                        error=("server dry-run changed Helm releases or Kubernetes resource UIDs"),
                    )
                )
        return DeployResult(
            success=overall_success,
            waves_completed=waves_completed,
            total_waves=len(waves),
            component_results=all_results,
        )

    finally:
        summary = {
            "success": overall_success,
            "waves_completed": waves_completed,
            "total_waves": len(waves),
            "components": [
                {
                    "component": result.component,
                    "success": result.success,
                    "error": result.error,
                    "duration": result.duration,
                }
                for result in all_results
            ],
        }
        summary_path = run_dir / "summary.json"
        summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
        os.chmod(summary_path, 0o600)
