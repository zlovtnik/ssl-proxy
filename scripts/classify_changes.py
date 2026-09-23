#!/usr/bin/env python3
"""Classify a superproject commit for Jenkins validation and image publication."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from image_contract import FIRST_PARTY_SERVICES


SUBMODULE_IMAGES = {
    "apps/integration-console": ("atheros-search", "atheros-search-ui"),
    "apps/schema-migrator": ("schema-migrator-backend", "schema-migrator-ui"),
    "apps/wg-key-rotator": (),
    "services/octopus": ("java-coordinator",),
}
RUST_INPUTS = ("Cargo.toml", "Cargo.lock", "Dockerfile", "crates/")
ALL_IMAGE_INPUTS = ("Makefile", ".dockerignore")


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ("git", "-C", str(root), *args),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout.strip()


def is_path(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix.rstrip("/") + "/")


def classify_paths(paths: set[str], bumped: dict[str, bool], *, full: bool) -> dict:
    main_paths = sorted(
        path for path in paths
        if not any(is_path(path, mount) for mount in SUBMODULE_IMAGES)
    )
    services: set[str] = set(FIRST_PARTY_SERVICES) if full else set()

    def changed(*prefixes: str) -> bool:
        return full or any(is_path(path, prefix) for path in main_paths for prefix in prefixes)

    if changed(*ALL_IMAGE_INPUTS):
        services.update(FIRST_PARTY_SERVICES)
    if changed(*RUST_INPUTS):
        services.update(("ssl-proxy", "atheros-sensor"))
    if changed("src/", "benches/", "static/", "config/client/", "config/peer1/", "docker/entrypoint.sh"):
        services.add("ssl-proxy")
    if changed("services/atheros-sensor/"):
        services.add("atheros-sensor")
    if changed("sql/postgres/", "k8s/postgres-schema-executor/"):
        services.add("postgres-runtime-schema")
    if changed("docker/redpanda/", "scripts/octopus_image_contract.py"):
        services.add("java-coordinator")
    for path, images in SUBMODULE_IMAGES.items():
        if bumped[path]:
            services.update(images)

    tests = {
        "platform_sync": changed("services/platform-sync/"),
        "atheros_search": bumped["apps/integration-console"],
        "schema_migrator": bumped["apps/schema-migrator"],
        "octopus": bumped["services/octopus"],
        "sensor": changed("services/atheros-sensor/", *RUST_INPUTS),
    }
    return {
        "fullBuild": full,
        "changedMainPaths": main_paths,
        "submoduleBumped": bumped,
        "changedServices": [service for service in FIRST_PARTY_SERVICES if service in services],
        "publishRedpandaMaint": changed("cyber-stack/base/redpanda-maintenance/"),
        "tests": tests,
    }


def classify_repository(root: Path, *, base: str = "HEAD^", force_full: bool = False) -> dict:
    head = git(root, "rev-parse", "--verify", "HEAD")
    parent = subprocess.run(
        ("git", "-C", str(root), "rev-parse", "--verify", f"{base}^{{commit}}"),
        capture_output=True,
        text=True,
        check=False,
    )
    full = force_full or parent.returncode != 0
    paths = (
        set(git(root, "ls-tree", "-r", "--name-only", head).splitlines())
        if full else set(git(root, "diff", "--name-only", base, head).splitlines())
    )
    bumped = {
        path: full or (
            git(root, "ls-tree", base, "--", path)
            != git(root, "ls-tree", "HEAD", "--", path)
        )
        for path in SUBMODULE_IMAGES
    }
    result = classify_paths(paths, bumped, full=full)
    result["baseRevision"] = None if full else parent.stdout.strip()
    result["headRevision"] = head
    return result


def env_lines(result: dict) -> str:
    lines = [f"CHANGED_SERVICES={','.join(result['changedServices'])}"]
    for name, value in result["tests"].items():
        lines.append(f"SHOULD_RUN_{name.upper()}={str(value).lower()}")
    lines.append(f"SHOULD_PUBLISH_REDPANDA_MAINT={str(result['publishRedpandaMaint']).lower()}")
    for path, bumped in result["submoduleBumped"].items():
        key = path.upper().replace("/", "_").replace("-", "_")
        lines.append(f"SUBMODULE_BUMPED_{key}={str(bumped).lower()}")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--base", default="HEAD^", help="last successfully built commit")
    parser.add_argument("--full", action="store_true", help="select everything on the first build")
    parser.add_argument("--json-out", type=Path, required=True)
    parser.add_argument("--env-out", type=Path, required=True)
    args = parser.parse_args()
    result = classify_repository(args.repository_root.resolve(), base=args.base, force_full=args.full)
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.env_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.env_out.write_text(env_lines(result), encoding="ascii")
    print(f"changed services: {', '.join(result['changedServices']) or '(none)'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
