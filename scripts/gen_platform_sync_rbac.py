#!/usr/bin/env python3
"""Generate or verify platform-sync target RBAC from the input contract."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml

from platform_input_contract import load_platform_input_contract


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    Path("cyber-stack/base/platform-sync/role.yaml"): "ssl-proxy-postgres-endpoint",
    Path("cyber-stack/matrix/prod/patches/platform-sync-target.yaml"): (
        "ssl-proxy-prod-postgres-endpoint"
    ),
    Path("cyber-stack/matrix/staging/patches/platform-sync-target.yaml"): (
        "ssl-proxy-staging-postgres-endpoint"
    ),
}


def expected_role(
    secret_names: list[str], config_map_names: list[str], *, base: bool
) -> dict[str, Any]:
    metadata: dict[str, Any] = {"name": "ssl-proxy-platform-sync"}
    if base:
        metadata["labels"] = {
            "app.kubernetes.io/name": "ssl-proxy",
            "app.kubernetes.io/component": "platform-sync",
            "app.kubernetes.io/managed-by": "kustomize",
        }
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": metadata,
        "rules": [
            {
                "apiGroups": [""],
                "resources": ["secrets"],
                "resourceNames": secret_names,
                "verbs": ["get", "update"],
            },
            {
                "apiGroups": [""],
                "resources": ["configmaps"],
                "resourceNames": [
                    "platform-sync-lock",
                    "platform-ready",
                    *config_map_names,
                ],
                "verbs": ["get", "update"],
            },
        ],
    }


def expected_documents(root: Path) -> dict[Path, dict[str, Any]]:
    contract = load_platform_input_contract(root)
    secret_names = sorted(entry.name for entry in contract.inputs if entry.kind == "Secret")
    contract_config_maps = sorted(
        entry.name for entry in contract.inputs if entry.kind == "ConfigMap"
    )
    documents: dict[Path, dict[str, Any]] = {}
    for path, endpoint in TARGETS.items():
        config_map_names = [
            endpoint if name == "ssl-proxy-prod-postgres-endpoint" else name
            for name in contract_config_maps
        ]
        documents[path] = expected_role(
            secret_names, config_map_names, base=path.parts[1] == "base"
        )
    return documents


def write_documents(root: Path, documents: dict[Path, dict[str, Any]]) -> None:
    for relative, document in documents.items():
        (root / relative).write_text(
            yaml.safe_dump(document, sort_keys=False), encoding="utf-8"
        )


def check_documents(root: Path, documents: dict[Path, dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    for relative, expected in documents.items():
        try:
            actual = yaml.safe_load((root / relative).read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as error:
            errors.append(f"{relative}: {error}")
            continue
        if actual != expected:
            errors.append(f"{relative}: generated RBAC is stale")
    return errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    parser.add_argument("--root", type=Path, default=REPOSITORY_ROOT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    try:
        documents = expected_documents(root)
        if args.write:
            write_documents(root, documents)
            for relative in documents:
                print(f"updated {relative}")
            return 0
        errors = check_documents(root, documents)
    except (OSError, ValueError, yaml.YAMLError) as error:
        print(f"platform-sync-rbac: {error}", file=sys.stderr)
        return 1
    for error in errors:
        print(f"platform-sync-rbac: {error}", file=sys.stderr)
    if errors:
        return 1
    print("platform-sync-rbac: generated RBAC matches the contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
