#!/usr/bin/env python3
"""Validate Octopus source identity and java-coordinator image contents."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Mapping, Sequence


PARENT_REVISION_LABEL = "org.opencontainers.image.revision"
OCTOPUS_REVISION_LABEL = "io.ssl-proxy.octopus.revision"
OCTOPUS_PATH = Path("services/octopus")
PROMOTION_RECORD_SCHEMA = 1
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")

FORBIDDEN_ENTRY_FRAGMENTS = (
    "com/sslproxy/coordinator/config/CutoverConfig",
    "com/sslproxy/coordinator/cutover/",
    "CutoverVerifier",
)
FORBIDDEN_BYTECODE_MARKERS = (
    b"kafka.topic-replication-factor must be between 3 and 32767",
    b"tidb.ssl-mode must be VERIFY_IDENTITY",
    b"tidb.local-dev-allow-public-key-retrieval requires development cutover bypass",
)


class ContractError(RuntimeError):
    """Raised when source or image state violates the recovery contract."""


def _validate_digest(value: str) -> str:
    if not DIGEST_PATTERN.fullmatch(value):
        raise ContractError(
            "image digest must be sha256 followed by exactly 64 lowercase hexadecimal characters"
        )
    return value


def _validate_repository(value: str) -> str:
    if (
        not value
        or value != value.strip()
        or any(character.isspace() for character in value)
        or "://" in value
        or "@" in value
        or "/" not in value
    ):
        raise ContractError(f"invalid image repository in promotion record: {value!r}")
    return value


def _validate_commit(value: str, label: str) -> str:
    if not COMMIT_PATTERN.fullmatch(value):
        raise ContractError(f"{label} must be a full 40-character lowercase Git commit")
    return value


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


def promotion_record(
    repository: str,
    digest: str,
    parent_commit: str,
    octopus_commit: str,
) -> dict[str, object]:
    return {
        "schemaVersion": PROMOTION_RECORD_SCHEMA,
        "service": "java-coordinator",
        "image": {
            "repository": _validate_repository(repository),
            "digest": _validate_digest(digest),
        },
        "source": {
            "parentCommit": _validate_commit(parent_commit, "parent commit"),
            "octopusCommit": _validate_commit(octopus_commit, "Octopus commit"),
        },
    }


def load_promotion_record(path: Path) -> tuple[str, str, str, str]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ContractError(f"verified dev promotion record is missing: {path}") from error
    except json.JSONDecodeError as error:
        raise ContractError(f"cannot parse promotion record {path}: {error}") from error
    if not isinstance(document, Mapping):
        raise ContractError(f"promotion record must be a JSON object: {path}")
    if document.get("schemaVersion") != PROMOTION_RECORD_SCHEMA:
        raise ContractError(f"unsupported promotion record schema in {path}")
    if document.get("service") != "java-coordinator":
        raise ContractError(f"promotion record service must be java-coordinator: {path}")
    image = document.get("image")
    source = document.get("source")
    if not isinstance(image, Mapping) or not isinstance(source, Mapping):
        raise ContractError(f"promotion record image/source fields are invalid: {path}")
    repository = _validate_repository(str(image.get("repository", "")))
    digest = _validate_digest(str(image.get("digest", "")))
    parent_commit = _validate_commit(str(source.get("parentCommit", "")), "parent commit")
    octopus_commit = _validate_commit(
        str(source.get("octopusCommit", "")), "Octopus commit"
    )
    return repository, digest, parent_commit, octopus_commit


def write_promotion_record(
    path: Path,
    repository: str,
    digest: str,
    parent_commit: str,
    octopus_commit: str,
) -> None:
    document = promotion_record(
        repository, digest, parent_commit, octopus_commit
    )
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def check_image_digest(
    image: str,
    inspected: Mapping[str, object],
    expected_repository: str,
    expected_digest: str,
) -> None:
    expected_reference = f"{expected_repository}@{_validate_digest(expected_digest)}"
    if image != expected_reference:
        raise ContractError(
            "candidate image must be the exact canonical digest reference: "
            f"expected {expected_reference}, got {image}"
        )
    repo_digests = inspected.get("RepoDigests")
    if not isinstance(repo_digests, list) or expected_reference not in repo_digests:
        raise ContractError(
            f"local image inspection does not associate {expected_reference} with the candidate"
        )


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


def check_image(
    image: str,
    repository_root: Path,
    expected_digest: str,
    promotion_record_path: Path | None = None,
) -> tuple[str, str]:
    if promotion_record_path is None:
        parent_commit, octopus_commit = source_revisions(repository_root)
        expected_repository = image.rsplit("@", 1)[0] if "@" in image else ""
    else:
        (
            expected_repository,
            record_digest,
            parent_commit,
            octopus_commit,
        ) = load_promotion_record(promotion_record_path)
        if record_digest != expected_digest:
            raise ContractError(
                "candidate digest does not match verified dev promotion record: "
                f"record={record_digest} requested={expected_digest}"
            )
    inspect_payload = _docker("image", "inspect", image)
    inspected = json.loads(inspect_payload)
    if not isinstance(inspected, list) or len(inspected) != 1:
        raise ContractError(f"docker returned an unexpected inspection result for {image}")
    image_inspection = inspected[0]
    if not isinstance(image_inspection, Mapping):
        raise ContractError(f"docker returned an invalid inspection object for {image}")
    check_image_digest(
        image, image_inspection, expected_repository, expected_digest
    )
    config = image_inspection.get("Config")
    labels = config.get("Labels") if isinstance(config, Mapping) else None
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
    image.add_argument("--expected-digest", required=True)
    image.add_argument("--promotion-record", type=Path)
    image.add_argument(
        "--repository-root", type=Path, default=Path(__file__).resolve().parents[1]
    )

    record = subparsers.add_parser(
        "record", help="write verified dev image/source provenance"
    )
    record.add_argument("record_path", type=Path)
    record.add_argument("--repository", required=True)
    record.add_argument("--digest", required=True)
    record.add_argument(
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
        elif arguments.command == "image":
            parent, octopus = check_image(
                arguments.image,
                arguments.repository_root,
                arguments.expected_digest,
                arguments.promotion_record,
            )
            print(
                f"java-coordinator image contract verified: {arguments.image} "
                f"parent={parent} octopus={octopus}"
            )
        else:
            parent, octopus = source_revisions(arguments.repository_root)
            write_promotion_record(
                arguments.record_path,
                arguments.repository,
                arguments.digest,
                parent,
                octopus,
            )
            print(f"Verified dev promotion record written: {arguments.record_path}")
    except (ContractError, json.JSONDecodeError) as error:
        print(f"Octopus image contract error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
