#!/usr/bin/env python3
"""Validate the canonical Kustomize and Argo CD delivery surfaces."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path


CANONICAL_KUSTOMIZATIONS = (
    "cyber-stack/argocd",
    "cyber-stack/matrix/dev/bootstrap",
    "cyber-stack/matrix/dev/data-plane",
    "cyber-stack/matrix/dev/app-stack",
    "cyber-stack/matrix/prod/bootstrap",
    "cyber-stack/matrix/prod/data-plane",
    "cyber-stack/matrix/prod/app-stack",
)

APPLICATIONS = {
    "application-bootstrap.yaml": "cyber-stack/matrix/dev/bootstrap",
    "application-data-plane.yaml": "cyber-stack/matrix/dev/data-plane",
    "application-app-stack.yaml": "cyber-stack/matrix/dev/app-stack",
    "application-prod-bootstrap.yaml": "cyber-stack/matrix/prod/bootstrap",
    "application-prod-data-plane.yaml": "cyber-stack/matrix/prod/data-plane",
    "application-prod-app-stack.yaml": "cyber-stack/matrix/prod/app-stack",
}

FIRST_PARTY_IMAGES = (
    "ssl-proxy",
    "java-coordinator",
    "atheros-sensor",
    "atheros-search",
    "atheros-search-ui",
    "schema-migrator-backend",
    "schema-migrator-ui",
    "tidb-runtime-schema",
)

REDPANDA_MEMORY_RE = re.compile(r"--memory\s+(?:-\s+)?(\d+)([GMT])?")
REDPANDA_COMBINED_RE = re.compile(
    r"--memory\n\s*-\s+(\d+)([GMT]).*?memory:\s*(\d+)([GMTi]*)", re.DOTALL
)


def _parse_bytes(value: str, unit: str) -> int:
    multipliers = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
    return int(value) * multipliers.get(unit.upper().rstrip("I"), 1)


def _check_otel_endpoint(rendered: str, relative: str) -> list[str]:
    if "ssl-proxy-otel-collector" in rendered:
        return [
            f"{relative}: rendered output contains nonexistent "
            "ssl-proxy-otel-collector service reference"
        ]
    return []


def _check_redpanda_memory(rendered: str, relative: str) -> list[str]:
    if "ssl-proxy-redpanda" not in rendered or "kind: StatefulSet" not in rendered:
        return []
    match = REDPANDA_COMBINED_RE.search(rendered)
    if not match:
        return []
    heap_bytes = _parse_bytes(match.group(1), match.group(2))
    limit_bytes = _parse_bytes(match.group(3), match.group(4))
    headroom = limit_bytes - heap_bytes
    if headroom < 512 * 1024**2:
        return [
            f"{relative}: Redpanda memory limit must provide at least "
            f"512 MiB headroom over --memory (got {headroom // 1024**2} MiB)"
        ]
    return []


def _check_proxy_probes(rendered: str, relative: str) -> list[str]:
    if "name: ssl-proxy-proxy" not in rendered:
        return []
    errors = []
    for probe in ("livenessProbe", "readinessProbe"):
        pattern = re.compile(
            rf"({probe}:.*?)httpGet:",
            re.DOTALL,
        )
        match = pattern.search(rendered)
        if match:
            errors.append(
                f"{relative}: proxy {probe} must use exec probe "
                "on loopback, not httpGet"
            )
    return errors


def _check_traefik_redirect(rendered: str, relative: str) -> list[str]:
    if "entrypoints.web.http.redirections.entrypoint.port" in rendered:
        return [
            f"{relative}: Traefik entrypoint.port is not a supported "
            "redirection field"
        ]
    return []


def _check_tidb_waves(rendered: str, relative: str) -> list[str]:
    wave_re = re.compile(
        r"name:\s+ssl-proxy-tidb-init(?!-grants).*?"
        r"argocd\.argoproj\.io/sync-wave:\s*\"?(\d+)\"?",
        re.DOTALL,
    )
    schema_re = re.compile(
        r"name:\s+ssl-proxy-tidb-schema-executor.*?"
        r"argocd\.argoproj\.io/sync-wave:\s*\"?(\d+)\"?",
        re.DOTALL,
    )
    grants_re = re.compile(
        r"name:\s+ssl-proxy-tidb-init-grants.*?"
        r"argocd\.argoproj\.io/sync-wave:\s*\"?(\d+)\"?",
        re.DOTALL,
    )
    wave_matches = wave_re.findall(rendered)
    schema_matches = schema_re.findall(rendered)
    grants_matches = grants_re.findall(rendered)
    if not wave_matches or not schema_matches or not grants_matches:
        return []
    init_wave = max(int(w) for w in wave_matches)
    schema_wave = max(int(w) for w in schema_matches)
    grants_wave = max(int(w) for w in grants_matches)
    errors = []
    if init_wave >= schema_wave:
        errors.append(
            f"{relative}: TiDB init wave ({init_wave}) must be less "
            f"than schema executor wave ({schema_wave})"
        )
    if schema_wave >= grants_wave:
        errors.append(
            f"{relative}: schema executor wave ({schema_wave}) must be "
            f"less than grants wave ({grants_wave})"
        )
    return errors


def render(root: Path, executable: str, relative: str) -> tuple[str, str | None]:
    if Path(executable).name == "kubectl":
        command = [
            executable,
            "kustomize",
            str(root / relative),
            "--load-restrictor",
            "LoadRestrictionsNone",
        ]
    else:
        command = [
            executable,
            "build",
            "--load-restrictor",
            "LoadRestrictionsNone",
            str(root / relative),
        ]
    result = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        return "", f"{relative}: Kustomize render failed: {detail}"
    return result.stdout, None


def check_repository(root: Path, executable: str) -> list[str]:
    errors: list[str] = []

    for relative in CANONICAL_KUSTOMIZATIONS:
        rendered, error = render(root, executable, relative)
        if error:
            errors.append(error)
            continue
        if re.search(r"(?m)^\s*image:\s+\S+:latest\s*$", rendered):
            errors.append(f"{relative}: rendered workload uses a mutable latest tag")
        for image in FIRST_PARTY_IMAGES:
            if re.search(rf"(?m)^\s*image:\s+{re.escape(image)}(?::\S+)?\s*$", rendered):
                errors.append(
                    f"{relative}: rendered workload retains logical image name {image}"
                )
        errors.extend(_check_otel_endpoint(rendered, relative))
        errors.extend(_check_redpanda_memory(rendered, relative))
        errors.extend(_check_proxy_probes(rendered, relative))
        errors.extend(_check_traefik_redirect(rendered, relative))
        errors.extend(_check_tidb_waves(rendered, relative))

    argocd_root = root / "cyber-stack/argocd"
    for filename, source_path in APPLICATIONS.items():
        path = argocd_root / filename
        text = path.read_text(encoding="utf-8")
        required = (
            "targetRevision: main",
            f"path: {source_path}",
            "automated:",
            "prune: true",
            "selfHeal: true",
            "allowEmpty: false",
        )
        for value in required:
            if value not in text:
                errors.append(f"{path.relative_to(root)}: missing {value!r}")
        if "CreateNamespace=true" in text:
            errors.append(
                f"{path.relative_to(root)}: namespace creation must come from Git"
            )

    updater = (argocd_root / "image-updater-dev.yaml").read_text(encoding="utf-8")
    updater_requirements = (
        "method: git:secret:argocd/ssl-proxy-image-updater-git",
        "branch: main",
        "writeBackTarget: kustomization",
        "pullRequest:",
        "namePattern: ssl-proxy-data-plane",
        "namePattern: ssl-proxy-app-stack",
        "updateStrategy: digest",
    )
    for value in updater_requirements:
        if value not in updater:
            errors.append(f"cyber-stack/argocd/image-updater-dev.yaml: missing {value!r}")
    if "ssl-proxy-prod-" in updater:
        errors.append("Image Updater must not automate production promotion")

    for environment in ("dev", "prod"):
        for component in ("data-plane", "app-stack"):
            relative = Path("cyber-stack/matrix") / environment / component / "kustomization.yaml"
            text = (root / relative).read_text(encoding="utf-8")
            if "newTag:" in text:
                errors.append(f"{relative}: first-party images must be digest pinned")
            image_entries = text.count("  - name:")
            digest_entries = text.count("    digest: sha256:")
            if image_entries != digest_entries:
                errors.append(
                    f"{relative}: expected one digest for each of {image_entries} image entries, found {digest_entries}"
                )

    for environment in ("dev", "prod"):
        relative = Path("cyber-stack/matrix") / environment / "namespace.yaml"
        text = (root / relative).read_text(encoding="utf-8")
        if "argocd.argoproj.io/sync-options: Prune=confirm" not in text:
            errors.append(f"{relative}: namespace prune confirmation is required")

    makefile = (root / "Makefile").read_text(encoding="utf-8")
    for forbidden in ("argocd-update", "release-all", "kubectl patch application"):
        if forbidden in makefile:
            errors.append(f"Makefile: live-cluster promotion surface remains: {forbidden}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository root",
    )
    parser.add_argument("--kustomize", default=None)
    args = parser.parse_args()

    executable = args.kustomize or shutil.which("kustomize")
    if not executable:
        print("gitops-check: kustomize executable was not found", file=sys.stderr)
        return 1

    errors = check_repository(args.root.resolve(), executable)
    if errors:
        for error in errors:
            print(f"gitops-check: {error}", file=sys.stderr)
        return 1
    print("gitops-check: canonical Kustomize and Argo CD surfaces are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
