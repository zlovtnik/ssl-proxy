"""Digest-guarded kustomize ownership cutover without umbrella uninstall."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from .cluster import smoke, status
from .core import StackConfig, load_umbrella_values, staged_waves
from .deploy import _redact_manifest
from .rendering import (
    OVERLAY_MAP,
    parity_diff,
    render_component,
    render_umbrella,
    resource_identity,
    safe_artifact_dir,
)
from .shell import kubectl, kustomize_apply, kustomize_build


def _canonical_digest(payload: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in payload.items() if key != "digest"}
    encoded = json.dumps(unsigned, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def _write_private(path: Path, text: str) -> None:
    path.write_text(text)
    os.chmod(path, 0o600)


def _current_context(kubeconfig: str | None) -> str:
    result = kubectl(
        "config",
        "current-context",
        kubeconfig=kubeconfig,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise RuntimeError("unable to resolve current Kubernetes context")
    return result.stdout.strip()


def _live_uid(
    identity: tuple[str, str, str, str],
    namespace: str,
    context: str,
    kubeconfig: str | None,
) -> tuple[str, str, str | None]:
    _, kind, resource_namespace, name = identity
    args = ["get", kind, name]
    if resource_namespace or namespace:
        args.extend(["-n", resource_namespace or namespace])
    args.extend(["-o", "json"])
    result = kubectl(
        *args,
        context=context,
        kubeconfig=kubeconfig,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"required live resource missing: {kind}/{name}")
    payload = json.loads(result.stdout)
    metadata = payload.get("metadata", {})
    annotations = metadata.get("annotations", {})
    labels = metadata.get("labels", {})
    owner_source = "meta.helm.sh/release-name"
    owner_value = annotations.get("meta.helm.sh/release-name")
    if owner_value is None:
        owner_value = labels.get("app.kubernetes.io/instance")
        if owner_value is not None:
            owner_source = "app.kubernetes.io/instance"
        else:
            owner_value = labels.get("app.kubernetes.io/managed-by")
            owner_source = (
                "app.kubernetes.io/managed-by" if owner_value is not None else "unowned"
            )
    return (
        str(metadata.get("uid", "")),
        owner_source,
        owner_value,
    )


def create_plan(
    config: StackConfig,
    root_dir: Path,
    artifact_dir: str,
    namespace: str,
    context: str | None,
    kubeconfig: str | None,
    runtime_overrides: dict[str, Any],
    umbrella_release: str = "ssl-proxy",
) -> Path:
    """Create a parity-checked, UID-bound cutover artifact."""

    if not context:
        raise ValueError("cutover plan requires --kube-context")
    current = _current_context(kubeconfig)
    if current != context:
        raise RuntimeError(f"current context {current!r} does not match {context!r}")
    base = safe_artifact_dir(root_dir, artifact_dir)
    run_dir = base / (
        datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + os.urandom(4).hex() + "-cutover"
    )
    run_dir.mkdir(mode=0o700)

    values = load_umbrella_values(config, root_dir)
    rendered = [
        render_component(
            name,
            config,
            root_dir,
            values,
            runtime_overrides,
            namespace,
        )
        for name, component in config.components.items()
        if component.type in ("helm", "helm-job")
    ]
    split_resources = [resource for item in rendered for resource in item.resources]
    umbrella_resources = render_umbrella(
        namespace,
    )
    differences = parity_diff(umbrella_resources, split_resources)
    if differences:
        raise RuntimeError("manifest parity failed: " + "; ".join(differences))

    split_owner: dict[tuple[str, str, str, str], str] = {}
    for item in rendered:
        release = config.components[item.name].release
        for resource in item.resources:
            split_owner[resource_identity(resource)] = release

    matrix: list[dict[str, Any]] = []
    for resource in umbrella_resources:
        identity = resource_identity(resource)
        # The lifecycle-managed schema Job intentionally has no stable umbrella identity.
        if identity not in split_owner:
            continue
        uid, owner_source, owner_value = _live_uid(identity, namespace, context, kubeconfig)
        if owner_value == umbrella_release and owner_source in {
            "meta.helm.sh/release-name",
            "app.kubernetes.io/instance",
        }:
            pass
        elif owner_source == "app.kubernetes.io/managed-by":
            raise RuntimeError(
                f"{identity} is managed by {owner_value!r}, not owned by a Helm release"
            )
        else:
            raise RuntimeError(
                f"{identity} is owned by {owner_value!r}, expected {umbrella_release!r}"
            )
        matrix.append(
            {
                "group": identity[0],
                "kind": identity[1],
                "namespace": identity[2] or namespace,
                "name": identity[3],
                "uid": uid,
                "from_release": umbrella_release,
                "to_release": split_owner[identity],
            }
        )

    backups = run_dir / "backups"
    backups.mkdir(mode=0o700)
    live_state = kubectl(
        "get",
        "deploy,sts,ds,job",
        "-n",
        namespace,
        "-o",
        "json",
        context=context,
        kubeconfig=kubeconfig,
    )
    kustomize_overlay = OVERLAY_MAP.get(namespace)
    if kustomize_overlay is None:
        raise ValueError(
            f"namespace {namespace!r} has no configured kustomize overlay; "
            f"known overlays: {', '.join(sorted(OVERLAY_MAP))}"
        )
    manifest = kustomize_build(
        kustomize_overlay,
        context=context,
        kubeconfig=kubeconfig,
    )
    _write_private(backups / "live-state.json", live_state.stdout)
    _write_private(
        backups / "overlay.yaml",
        yaml.safe_dump({"kustomize_overlay": kustomize_overlay}, sort_keys=True),
    )
    _write_private(backups / "manifest.redacted.yaml", _redact_manifest(manifest.stdout))
    pvcs = kubectl(
        "get",
        "pvc",
        "-n",
        namespace,
        "-o",
        "json",
        context=context,
        kubeconfig=kubeconfig,
    )
    _write_private(backups / "pvcs.json", pvcs.stdout)

    payload: dict[str, Any] = {
        "version": 1,
        "created_at": datetime.now(UTC).isoformat(),
        "context": context,
        "namespace": namespace,
        "umbrella_release": umbrella_release,
        "kustomize_overlay": kustomize_overlay,
        "matrix": matrix,
        "parity": {"passed": True, "differences": []},
        "finalized": False,
        "rollback": {
            "before_finalize": "run cutover rollback with this plan",
            "after_finalize": (
                "run cutover rollback; overlay is reapplied from the plan-captured "
                "kustomize_overlay"
            ),
        },
    }
    payload["digest"] = _canonical_digest(payload)
    _write_private(run_dir / "plan.json", json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return run_dir / "plan.json"


def load_verified_plan(path: Path, digest: str) -> dict[str, Any]:
    if path.is_symlink() or path.parent.is_symlink():
        raise RuntimeError("cutover plan path cannot be a symlink")
    if path.name != "plan.json" or not path.is_file():
        raise RuntimeError("cutover plan must reference a regular plan.json")
    if path.stat().st_mode & 0o077:
        raise RuntimeError("cutover plan permissions must be mode 0600")
    payload = json.loads(path.read_text())
    actual = _canonical_digest(payload)
    if payload.get("digest") != actual or digest != actual:
        raise RuntimeError("cutover plan digest mismatch")
    return payload


def _verify_confirmations(
    plan: dict[str, Any],
    context: str,
    release: str,
    drain_complete: bool,
    kubeconfig: str | None,
) -> None:
    if context != plan["context"] or _current_context(kubeconfig) != context:
        raise RuntimeError("Kubernetes context confirmation mismatch")
    if release != plan["umbrella_release"]:
        raise RuntimeError("umbrella release confirmation mismatch")
    if not drain_complete:
        raise RuntimeError("--traffic-drained is required")


def _verify_uids(plan: dict[str, Any], context: str, kubeconfig: str | None) -> None:
    for item in plan["matrix"]:
        identity = (item["group"], item["kind"], item["namespace"], item["name"])
        uid, owner_source, owner_value = _live_uid(identity, item["namespace"], context, kubeconfig)
        if owner_source == "app.kubernetes.io/managed-by":
            raise RuntimeError(
                f"resource {identity} is managed by kustomize, not a Helm release"
            )
        if uid != item["uid"] or owner_value != item["from_release"]:
            raise RuntimeError(f"resource changed since plan: {identity}")


def _validated_overlay_path(
    plan: dict[str, Any],
    root_dir: Path,
) -> Path:
    kustomize_overlay = OVERLAY_MAP.get(plan["namespace"])
    if kustomize_overlay is None:
        raise ValueError(
            f"namespace {plan['namespace']!r} has no configured kustomize overlay; "
            f"known overlays: {', '.join(sorted(OVERLAY_MAP))}"
        )
    overlay_path = (root_dir / kustomize_overlay).resolve()
    root_resolved = root_dir.resolve()
    if overlay_path != root_resolved and root_resolved not in overlay_path.parents:
        raise RuntimeError("overlay path escapes root directory")
    return overlay_path


def apply_plan(
    config: StackConfig,
    root_dir: Path,
    plan_path: Path,
    digest: str,
    context: str,
    release: str,
    drain_complete: bool,
    kubeconfig: str | None,
    runtime_overrides: dict[str, Any],
) -> None:
    """Adopt resources stage-by-stage and retain the stale umbrella record."""

    plan = load_verified_plan(plan_path, digest)
    _verify_confirmations(plan, context, release, drain_complete, kubeconfig)
    required_backups = (
        "live-state.json",
        "overlay.yaml",
        "manifest.redacted.yaml",
        "pvcs.json",
    )
    missing_backups = [
        name for name in required_backups if not (plan_path.parent / "backups" / name).is_file()
    ]
    if missing_backups:
        raise RuntimeError("cutover backups are incomplete: " + ", ".join(missing_backups))
    _verify_uids(plan, context, kubeconfig)
    values = load_umbrella_values(config, root_dir)
    overlay_path = _validated_overlay_path(plan, root_dir)
    kustomize_apply(
        str(overlay_path),
        context=context,
        kubeconfig=kubeconfig,
        namespace=plan["namespace"],
    )
    bootstrap, waves = staged_waves(config)
    for wave in ([bootstrap] if bootstrap else []) + waves:
        for name in wave:
            component = config.components[name]
            if component.type not in ("helm", "helm-job"):
                continue
            render_component(
                name,
                config,
                root_dir,
                values,
                runtime_overrides,
                plan["namespace"],
            )
    checks = status(config, plan["namespace"], context, kubeconfig)
    checks.extend(smoke(config, plan["namespace"], context, kubeconfig))
    degraded = [item for item in checks if not item.healthy]
    if degraded:
        raise RuntimeError(
            "post-adoption status degraded: " + ", ".join(item.subject for item in degraded)
        )


def _helm_storage_records(
    release: str,
    namespace: str,
    context: str,
    kubeconfig: str | None,
) -> list[str]:
    result = kubectl(
        "get",
        "secret",
        "-n",
        namespace,
        "-l",
        f"owner=helm,name={release}",
        "-o",
        "json",
        context=context,
        kubeconfig=kubeconfig,
    )
    payload = json.loads(result.stdout)
    return [item["metadata"]["name"] for item in payload.get("items", [])]


def finalize_plan(
    config: StackConfig,
    plan_path: Path,
    digest: str,
    context: str,
    release: str,
    kubeconfig: str | None,
) -> None:
    """Remove only stale umbrella Helm storage records after ownership proof."""

    plan = load_verified_plan(plan_path, digest)
    _verify_confirmations(plan, context, release, True, kubeconfig)
    planned_releases = {
        component.release
        for component in config.components.values()
        if component.type in ("helm", "helm-job")
    }
    for item in plan["matrix"]:
        identity = (item["group"], item["kind"], item["namespace"], item["name"])
        uid, owner_source, owner_value = _live_uid(identity, item["namespace"], context, kubeconfig)
        if uid != item["uid"]:
            raise RuntimeError(f"split ownership proof failed: {identity} uid changed")
        if owner_source == "meta.helm.sh/release-name":
            if owner_value not in planned_releases:
                raise RuntimeError(
                    f"split ownership proof failed: {identity} release-name "
                    f"{owner_value!r} not in planned releases"
                )
        elif owner_source == "app.kubernetes.io/instance":
            if owner_value not in planned_releases:
                raise RuntimeError(
                    f"split ownership proof failed: {identity} instance "
                    f"{owner_value!r} not in planned releases"
                )
        elif owner_source == "app.kubernetes.io/managed-by":
            raise RuntimeError(
                f"split ownership proof failed: {identity} is managed by "
                f"{owner_value!r}, not a Helm release"
            )
        else:
            raise RuntimeError(
                f"split ownership proof failed: {identity} has no helm release-name annotation"
            )
    degraded = [
        item for item in status(config, plan["namespace"], context, kubeconfig) if not item.healthy
    ]
    if degraded:
        raise RuntimeError("cannot finalize degraded split releases")
    records = _helm_storage_records(release, plan["namespace"], context, kubeconfig)
    _write_private(
        plan_path.parent / "finalize-records.json",
        json.dumps(records, indent=2) + "\n",
    )
    for record in records:
        kubectl(
            "delete",
            "secret",
            record,
            "-n",
            plan["namespace"],
            context=context,
            kubeconfig=kubeconfig,
        )
    plan["finalized"] = True
    plan["digest"] = _canonical_digest(plan)
    _write_private(plan_path, json.dumps(plan, indent=2, sort_keys=True) + "\n")


def rollback_plan(
    root_dir: Path,
    plan_path: Path,
    digest: str,
    context: str,
    release: str,
    kubeconfig: str | None,
) -> None:
    """Restore umbrella ownership without deleting workloads or PVCs."""

    plan = load_verified_plan(plan_path, digest)
    _verify_confirmations(plan, context, release, True, kubeconfig)
    overlay_path = _validated_overlay_path(plan, root_dir)
    kustomize_apply(
        str(overlay_path),
        context=context,
        kubeconfig=kubeconfig,
        namespace=plan["namespace"],
    )
    split_releases = sorted({item["to_release"] for item in plan["matrix"]})
    for split_release in split_releases:
        for record in _helm_storage_records(split_release, plan["namespace"], context, kubeconfig):
            kubectl(
                "delete",
                "secret",
                record,
                "-n",
                plan["namespace"],
                context=context,
                kubeconfig=kubeconfig,
            )
