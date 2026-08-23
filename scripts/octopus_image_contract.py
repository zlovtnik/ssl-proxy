#!/usr/bin/env python3
"""Validate Octopus source identity and java-coordinator image contents."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Mapping, Sequence


PARENT_REVISION_LABEL = "org.opencontainers.image.revision"
OCTOPUS_REVISION_LABEL = "io.ssl-proxy.octopus.revision"
OCTOPUS_PATH = Path("services/octopus")

FORBIDDEN_ENTRY_FRAGMENTS = (
    "com/sslproxy/coordinator/config/CutoverConfig",
    "com/sslproxy/coordinator/cutover/",
    "CutoverVerifier",
)
FORBIDDEN_BYTECODE_MARKERS = (
    b"kafka.topic-replication-factor must be between 3 and 32767",
    b"postgres.ssl-mode must be VERIFY_IDENTITY",
    b"postgres.local-dev-allow-public-key-retrieval requires development cutover bypass",
)


class ContractError(RuntimeError):
    """Raised when source or image state violates the recovery contract."""


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "git command failed"
        raise ContractError(f"{repository}: {detail}")
    return result.stdout.strip()


def source_revisions(repository_root: Path) -> tuple[str, str]:
    root = repository_root.resolve()
    octopus = root / OCTOPUS_PATH
    parent_commit = _git(root, "rev-parse", "--verify", "HEAD")
    tree_entry = _git(root, "ls-tree", "HEAD", "--", OCTOPUS_PATH.as_posix())
    fields = tree_entry.split(None, 3)
    if len(fields) != 4 or fields[0] != "160000" or fields[1] != "commit":
        raise ContractError(
            f"{OCTOPUS_PATH.as_posix()} is not a pinned submodule in parent commit {parent_commit}"
        )

    pinned_commit = fields[2]
    octopus_commit = _git(octopus, "rev-parse", "--verify", "HEAD")
    if octopus_commit != pinned_commit:
        raise ContractError(
            "Octopus checkout does not match the parent submodule pin: "
            f"parent={pinned_commit} checkout={octopus_commit}"
        )

    parent_status = _git(
        root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignore-submodules=none",
    )
    octopus_status = _git(
        octopus,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    )
    dirty: list[str] = []
    if parent_status:
        dirty.append(f"parent worktree is not clean:\n{parent_status}")
    if octopus_status:
        dirty.append(f"Octopus worktree is not clean:\n{octopus_status}")
    if dirty:
        raise ContractError("\n".join(dirty))

    return parent_commit, octopus_commit


def check_jar(jar_path: Path) -> None:
    path = jar_path.resolve()
    if not path.is_file():
        raise ContractError(f"Octopus JAR does not exist: {path}")

    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            forbidden_entries = sorted(
                name
                for name in names
                if any(fragment in name for fragment in FORBIDDEN_ENTRY_FRAGMENTS)
            )
            if forbidden_entries:
                raise ContractError(
                    "Octopus JAR contains obsolete cutover classes: "
                    + ", ".join(forbidden_entries[:10])
                )

            marker_hits: list[str] = []
            for name in names:
                if not name.endswith((".class", ".conf", ".properties")):
                    continue
                payload = archive.read(name)
                for marker in FORBIDDEN_BYTECODE_MARKERS:
                    if marker in payload:
                        marker_hits.append(f"{name}: {marker.decode('ascii')}")
            if marker_hits:
                raise ContractError(
                    "Octopus JAR contains obsolete replication/TLS validation: "
                    + "; ".join(marker_hits)
                )
    except zipfile.BadZipFile as error:
        raise ContractError(f"Octopus JAR is not a readable ZIP archive: {path}") from error


def check_labels(
    labels: Mapping[str, str] | None,
    expected_parent_commit: str,
    expected_octopus_commit: str,
) -> None:
    actual = labels or {}
    expected = {
        PARENT_REVISION_LABEL: expected_parent_commit,
        OCTOPUS_REVISION_LABEL: expected_octopus_commit,
    }
    errors = [
        f"{key}: expected {value}, got {actual.get(key, '<missing>')}"
        for key, value in expected.items()
        if actual.get(key) != value
    ]
    if errors:
        raise ContractError("java-coordinator OCI label mismatch: " + "; ".join(errors))


def _docker(*arguments: str, capture: bool = True) -> str:
    result = subprocess.run(
        ["docker", *arguments],
        check=False,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or "docker command failed"
        raise ContractError(detail)
    return result.stdout.strip() if capture else ""


def check_image(image: str, repository_root: Path) -> tuple[str, str]:
    parent_commit, octopus_commit = source_revisions(repository_root)
    inspect_payload = _docker("image", "inspect", image)
    inspected = json.loads(inspect_payload)
    if not isinstance(inspected, list) or len(inspected) != 1:
        raise ContractError(f"docker returned an unexpected inspection result for {image}")
    labels = inspected[0].get("Config", {}).get("Labels")
    check_labels(labels, parent_commit, octopus_commit)

    container_id = _docker("create", image)
    try:
        with tempfile.TemporaryDirectory(prefix="octopus-image-contract-") as directory:
            jar_path = Path(directory) / "octopus.jar"
            _docker("cp", f"{container_id}:/app/octopus.jar", str(jar_path), capture=False)
            check_jar(jar_path)
    finally:
        _docker("rm", "-f", container_id, capture=False)
    return parent_commit, octopus_commit


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    source = subparsers.add_parser("source", help="validate parent/submodule identity")
    source.add_argument(
        "--repository-root", type=Path, default=Path(__file__).resolve().parents[1]
    )

    jar = subparsers.add_parser("jar", help="inspect an assembled Octopus JAR")
    jar.add_argument("jar_path", type=Path)

    image = subparsers.add_parser("image", help="inspect a local java-coordinator image")
    image.add_argument("image")
    image.add_argument(
        "--repository-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "source":
            parent, octopus = source_revisions(arguments.repository_root)
            print(f"Octopus source integrity verified: parent={parent} octopus={octopus}")
        elif arguments.command == "jar":
            check_jar(arguments.jar_path)
            print(f"Octopus JAR contract verified: {arguments.jar_path}")
        else:
            parent, octopus = check_image(arguments.image, arguments.repository_root)
            print(
                f"java-coordinator image contract verified: {arguments.image} "
                f"parent={parent} octopus={octopus}"
            )
    except (ContractError, json.JSONDecodeError) as error:
        print(f"Octopus image contract error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
