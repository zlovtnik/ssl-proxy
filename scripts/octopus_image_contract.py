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
NATIVE_PATH = Path("services/octopus-rs")

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


def source_revisions(repository_root: Path, path: Path = OCTOPUS_PATH) -> tuple[str, str]:
    root = repository_root.resolve()
    octopus = root / path
    parent_commit = _git(root, "rev-parse", "--verify", "HEAD")
    tree_entry = _git(root, "ls-tree", "HEAD", "--", path.as_posix())
    fields = tree_entry.split(None, 3)
    if len(fields) != 4 or fields[0] != "160000" or fields[1] != "commit":
        raise ContractError(
            f"{path} is not a pinned submodule in parent commit {parent_commit}"
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


def check_image(image: str, repository_root: Path, native: bool = False) -> tuple[str, str]:
    parent_commit, octopus_commit = source_revisions(repository_root, NATIVE_PATH if native else OCTOPUS_PATH)
    inspect_payload = _docker("image", "inspect", image)
    inspected = json.loads(inspect_payload)
    if not isinstance(inspected, list) or len(inspected) != 1:
        raise ContractError(f"docker returned an unexpected inspection result for {image}")
    labels = inspected[0].get("Config", {}).get("Labels")
    check_labels(labels, parent_commit, octopus_commit)

    image_id = inspected[0]["Id"]
    if native:
        config = inspected[0]["Config"]
        if (inspected[0].get("Os"), inspected[0].get("Architecture"), config.get("Entrypoint")) != (
            "linux", "amd64", ["/app/octopus"]
        ):
            raise ContractError("expected linux/amd64 image with /app/octopus entrypoint")
    container_id = _docker("create", image_id)
    try:
        with tempfile.TemporaryDirectory(prefix="octopus-image-contract-") as directory:
            name = "octopus" if native else "octopus.jar"
            artifact = Path(directory) / name
            _docker("cp", f"{container_id}:/app/{name}", str(artifact), capture=False)
            if native:
                with artifact.open("rb") as stream:
                    header = stream.read(20)
                if header[:7] != b"\x7fELF\x02\x01\x01" or header[18:20] != b"\x3e\x00":
                    raise ContractError("expected an x86-64 ELF executable")
            else:
                check_jar(artifact)
    finally:
        _docker("rm", "-f", container_id, capture=False)
    if native:
        output = _docker("run", "--rm", "--network", "none", "--platform", "linux/amd64",
                         "-e", "POSTGRES_ENABLED=false", "-e", "POSTGRES_SSL_MODE=disable",
                         "-e", "SYNC_REDPANDA_TOPIC_REPLICATION_FACTOR=1", image_id)
        if output != "PostgreSQL sink disabled (set POSTGRES_ENABLED=true to enable)":
            raise ContractError("unexpected native coordinator startup response")
        # Exercise enabled-Postgres configuration without opening a database.
        # The deliberate checksum error must be the only rejected setting.
        result = subprocess.run(
            ["docker", "run", "--rm", "--network", "none", "--platform", "linux/amd64",
             "-e", "POSTGRES_ENABLED=true", "-e", "POSTGRES_HOST=test-db",
             "-e", "POSTGRES_PASSWORD=fixture", "-e", "POSTGRES_SSL_MODE=disable",
             "-e", "POSTGRES_SCHEMA_MANIFEST_SHA256=invalid", "-e", "OCTOPUS_ENVIRONMENT=development",
             "-e", "POSTGRES_LOCAL_DEV_ALLOW_PUBLIC_KEY_RETRIEVAL=true",
             "-e", "SYNC_REDPANDA_TOPIC_REPLICATION_FACTOR=1", image_id],
            capture_output=True, text=True, timeout=60, check=False,
        )
        expected = "Octopus: Invalid Octopus configuration: postgres.manifest-sha-256 must be 64 lowercase hexadecimal characters"
        if result.returncode != 1 or result.stderr.strip() != expected:
            raise ContractError(f"native configuration probe failed (exit {result.returncode}): {result.stderr.strip()}")
    return parent_commit, octopus_commit


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    source = subparsers.add_parser("source", help="validate parent/submodule identity")
    source.add_argument("--native", action="store_true")
    source.add_argument(
        "--repository-root", type=Path, default=Path(__file__).resolve().parents[1]
    )

    jar = subparsers.add_parser("jar", help="inspect an assembled Octopus JAR")
    jar.add_argument("jar_path", type=Path)

    image = subparsers.add_parser("image", help="inspect a local java-coordinator image")
    image.add_argument("image")
    image.add_argument("--native", action="store_true")
    image.add_argument(
        "--repository-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "source":
            parent, octopus = source_revisions(arguments.repository_root, NATIVE_PATH if arguments.native else OCTOPUS_PATH)
            print(f"Octopus source integrity verified: parent={parent} octopus={octopus}")
        elif arguments.command == "jar":
            check_jar(arguments.jar_path)
            print(f"Octopus JAR contract verified: {arguments.jar_path}")
        else:
            parent, octopus = check_image(arguments.image, arguments.repository_root, arguments.native)
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
