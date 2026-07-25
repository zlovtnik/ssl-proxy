"""Wave-based deployment execution for stackctl."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from gates import parse_timeout_seconds, wait_for_gates
from shell import ShellError, helm, kubectl

try:
    from stackctl import (
        Component,
        Gate,
        StackConfig,
        generate_effective_values,
        resolve_dependencies,
    )
except ImportError:
    from __main__ import (
        Component,
        Gate,
        StackConfig,
        generate_effective_values,
        resolve_dependencies,
    )


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
    if base:
        run_base = Path(base)
    else:
        run_base = Path(".stackctl/runs")
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    run_id = os.urandom(4).hex()
    run_dir = run_base / f"{ts}-{run_id}"
    run_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    (run_dir / "effective-values").mkdir(mode=0o700)
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


def _save_effective_values(
    run_dir: Path, component_name: str, values: dict[str, Any]
) -> None:
    """Save effective values to the run directory."""
    values_file = run_dir / "effective-values" / f"{component_name}.yaml"
    values_file.parent.mkdir(parents=True, exist_ok=True)
    with open(values_file, "w") as f:
        yaml.dump(values, f, default_flow_style=False)
    os.chmod(values_file, 0o600)

    redacted_file = run_dir / "rendered" / f"{component_name}.redacted.yaml"
    redacted_file.parent.mkdir(parents=True, exist_ok=True)
    with open(redacted_file, "w") as f:
        yaml.dump(_redact_dict(values), f, default_flow_style=False)
    os.chmod(redacted_file, 0o600)


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
    """Run helm dependency build once per unique resolved chart path."""
    resolved = chart_path.resolve()
    if resolved in _prepared_charts:
        return
    if _chart_has_dependencies(resolved):
        helm("dependency", "build", str(resolved))
    _prepared_charts.add(resolved)


def reset_prepared_charts() -> None:
    """Reset the set of prepared charts (for testing)."""
    _prepared_charts.clear()


# ---------------------------------------------------------------------------
# Helm operations
# ---------------------------------------------------------------------------


def _delete_job_if_exists(
    release: str, namespace: str, context: str | None, kubeconfig: str | None
) -> None:
    """Delete a Job by release name before helm upgrade (for helm-job rerun=replace)."""
    result = kubectl(
        "get",
        "job",
        release,
        "-n",
        namespace,
        "--ignore-not-found",
        context=context,
        kubeconfig=kubeconfig,
        check=False,
    )
    if result.returncode == 0 and result.stdout.strip():
        kubectl(
            "delete",
            "job",
            release,
            "-n",
            namespace,
            "--wait=true",
            context=context,
            kubeconfig=kubeconfig,
        )


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
) -> None:
    """Run helm upgrade --install for a component."""
    release = component.release
    chart = component.chart
    if not chart:
        raise ValueError(f"Component {component.name!r} has no chart")

    status = _helm_release_status(release, namespace, context, kubeconfig)
    is_upgrade = status == "deployed"
    operation = "upgrade" if is_upgrade else "install"

    args: list[str] = [operation, release, chart]
    args.extend(["-n", namespace, "--create-namespace"])
    args.extend(["-f", str(values_file)])
    args.extend(["--wait", "--wait-for-jobs"])

    timeout = component.timeout or "10m"
    args.extend(["--timeout", timeout])

    if dry_run:
        args.append("--dry-run")

    if is_upgrade and component.rollback_on_failure:
        args.extend(["--history-max", "5"])

    helm(*args, context=context, kubeconfig=kubeconfig, stream=True)


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


# ---------------------------------------------------------------------------
# Per-component deployment
# ---------------------------------------------------------------------------


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
        if component.type not in ("helm", "helm-job"):
            raise ValueError(
                f"Component {component_name!r} uses unsupported type {component.type!r}. "
                "Only 'helm' and 'helm-job' are implemented."
            )

        chart_path = Path(component.chart) if component.chart else None
        if not chart_path:
            raise ValueError(f"Component {component_name!r} has no chart path")

        # 1. Prepare chart dependencies
        prepare_chart(chart_path)

        # 2. Generate effective values
        effective = generate_effective_values(
            config,
            component_name,
            options.umbrella_values,
            root_dir=options.root_dir,
        )
        _save_effective_values(run_dir, component_name, effective)

        # 3. Write temporary values file
        values_file = run_dir / "effective-values" / f"{component_name}.yaml"
        with open(values_file, "w") as f:
            yaml.dump(effective, f, default_flow_style=False)
        os.chmod(values_file, 0o600)

        # 4. Delete existing Job for helm-job rerun=replace
        if component.type == "helm-job" and component.job:
            if component.job.rerun == "replace":
                _delete_job_if_exists(
                    component.release,
                    options.namespace,
                    options.context,
                    options.kubeconfig,
                )

        # 5. Helm upgrade --install
        _helm_upgrade(
            component,
            effective,
            values_file,
            options.namespace,
            options.context,
            options.kubeconfig,
            dry_run=options.dry_run,
        )

        # 6. Wait for gates (skip in dry-run)
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

    except (ShellError, RuntimeError, ValueError) as exc:
        duration = time.monotonic() - start

        # Rollback if configured
        if component.rollback_on_failure and not options.dry_run:
            try:
                _helm_rollback(
                    component.release,
                    options.namespace,
                    options.context,
                    options.kubeconfig,
                )
            except ShellError:
                pass

        return ComponentResult(
            component=component_name,
            success=False,
            error=str(exc),
            duration=duration,
        )


# ---------------------------------------------------------------------------
# Wave deployment
# ---------------------------------------------------------------------------


def _deploy_wave_sync(
    wave: list[str],
    config: StackConfig,
    options: DeployOptions,
    run_dir: Path,
) -> list[ComponentResult]:
    """Deploy all components in a wave concurrently using asyncio.gather."""
    results = asyncio.gather(
        *(deploy_component(c, config, options, run_dir) for c in wave),
        return_exceptions=True,
    )
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


def deploy_stack(
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
    waves = resolve_dependencies(
        config,
        target_component=options.target_component,
        from_wave=options.from_wave,
    )

    # Determine run directory
    if options.work_dir:
        run_dir = Path(options.work_dir)
        run_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        (run_dir / "effective-values").mkdir(exist_ok=True, mode=0o700)
        (run_dir / "rendered").mkdir(exist_ok=True, mode=0o700)
    else:
        run_dir = _create_run_dir()

    all_results: list[ComponentResult] = []
    waves_completed = 0
    overall_success = False

    try:
        for wave_index, wave in enumerate(waves):
            wave_num = wave_index + 1
            print(f"\n--- Wave {wave_num}/{len(waves)}: {', '.join(wave)} ---")

            wave_results = _deploy_wave_sync(wave, config, options, run_dir)
            all_results.extend(wave_results)

            wave_failed = any(not r.success for r in wave_results)
            if wave_failed:
                failed_names = [r.component for r in wave_results if not r.success]
                print(
                    f"\nWave {wave_num} FAILED: {', '.join(failed_names)}. "
                    f"Stopping deployment. Successful upgrades retained."
                )
                break

            waves_completed = wave_num
            print(f"Wave {wave_num} OK")

        overall_success = waves_completed == len(waves)
        return DeployResult(
            success=overall_success,
            waves_completed=waves_completed,
            total_waves=len(waves),
            component_results=all_results,
        )

    finally:
        if not options.keep_artifacts:
            if overall_success or not all_results:
                _cleanup_run_dir(run_dir)
        # On failure, run_dir is retained for diagnostics
