#!/usr/bin/env python3
"""Create and verify signed fresh-start cutover evidence.

Evidence commands never contact Redpanda, TiDB, or Kubernetes. The group-plan
command writes reviewable local offset files. The separately gated group-apply
command is the only networked operation and requires the signed artifact hash,
cluster identity, and an explicit rpk configuration.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = 1
CLEAN_STATUSES = frozenset({"processed", "deduplicated"})
KNOWN_STATUSES = CLEAN_STATUSES | frozenset({"retrying", "parked"})
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
SAFE_GROUP_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")


class EvidenceError(ValueError):
    """Raised when cutover evidence is incomplete or inconsistent."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot read JSON artifact {path}: {error}") from error
    if not isinstance(value, dict):
        raise EvidenceError(f"artifact {path} must be a JSON object")
    return value


def require_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceError(f"{field} must be a non-empty string")
    return value


def require_nonnegative_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EvidenceError(f"{field} must be a non-negative integer")
    return value


def require_utc_timestamp(value: Any, field: str) -> str:
    timestamp = require_string(value, field)
    if not timestamp.endswith("Z"):
        raise EvidenceError(f"{field} must use an explicit UTC Z suffix")
    try:
        parsed = datetime.fromisoformat(timestamp[:-1] + "+00:00")
    except ValueError as error:
        raise EvidenceError(f"{field} is not an ISO-8601 timestamp: {timestamp}") from error
    if parsed.tzinfo != timezone.utc:
        raise EvidenceError(f"{field} must be UTC")
    return timestamp


def partition_map(
    artifact: dict[str, Any], offset_field: str
) -> dict[tuple[str, str, int], int]:
    partitions = artifact.get("partitions")
    if not isinstance(partitions, list) or not partitions:
        raise EvidenceError("partitions must be a non-empty array")

    result: dict[tuple[str, int], int] = {}
    for index, entry in enumerate(partitions):
        prefix = f"partitions[{index}]"
        if not isinstance(entry, dict):
            raise EvidenceError(f"{prefix} must be an object")
        group_id = require_string(entry.get("group_id"), f"{prefix}.group_id")
        topic = require_string(entry.get("topic"), f"{prefix}.topic")
        partition = require_nonnegative_int(entry.get("partition"), f"{prefix}.partition")
        offset = require_nonnegative_int(entry.get(offset_field), f"{prefix}.{offset_field}")
        key = (group_id, topic, partition)
        if key in result:
            raise EvidenceError(
                f"duplicate partition entry for {group_id}:{topic}[{partition}]"
            )
        result[key] = offset
    return result


def validate_artifact(artifact: dict[str, Any]) -> dict[tuple[str, str, int], int]:
    if artifact.get("schema_version") != SCHEMA_VERSION:
        raise EvidenceError(f"schema_version must be {SCHEMA_VERSION}")
    kind = artifact.get("kind")
    if kind not in {"cutover", "audit_end"}:
        raise EvidenceError("kind must be cutover or audit_end")
    require_string(artifact.get("cluster_id"), "cluster_id")
    require_utc_timestamp(artifact.get("captured_at"), "captured_at")

    if kind == "cutover":
        require_string(artifact.get("group_version"), "group_version")
        return partition_map(artifact, "next_offset")

    digest = require_string(artifact.get("cutover_sha256"), "cutover_sha256")
    if not SHA256_PATTERN.fullmatch(digest):
        raise EvidenceError("cutover_sha256 must be a lowercase SHA-256 digest")
    return partition_map(artifact, "end_offset")


def _openssl(operation: str, artifact: dict[str, Any], key: Path, signature: Path) -> None:
    with tempfile.NamedTemporaryFile() as canonical:
        canonical.write(canonical_bytes(artifact))
        canonical.flush()
        if operation == "sign":
            command = [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(key),
                "-in",
                canonical.name,
                "-out",
                str(signature),
            ]
        else:
            command = [
                "openssl",
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-inkey",
                str(key),
                "-in",
                canonical.name,
                "-sigfile",
                str(signature),
            ]
        try:
            subprocess.run(command, check=True, capture_output=True, text=True)
        except FileNotFoundError as error:
            raise EvidenceError("openssl is required for Ed25519 signatures") from error
        except subprocess.CalledProcessError as error:
            detail = error.stderr.strip() or error.stdout.strip() or "signature operation failed"
            raise EvidenceError(detail) from error


def sign_artifact(artifact: dict[str, Any], private_key: Path, signature: Path) -> None:
    validate_artifact(artifact)
    _openssl("sign", artifact, private_key, signature)


def verify_artifact(artifact: dict[str, Any], public_key: Path, signature: Path) -> None:
    validate_artifact(artifact)
    _openssl("verify", artifact, public_key, signature)


def load_ledger(path: Path) -> Iterable[tuple[int, dict[str, Any]]]:
    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as error:
                    raise EvidenceError(
                        f"{path}:{line_number}: invalid JSON: {error}"
                    ) from error
                if not isinstance(row, dict):
                    raise EvidenceError(f"{path}:{line_number}: ledger row must be an object")
                yield line_number, row
    except OSError as error:
        raise EvidenceError(f"cannot read ledger {path}: {error}") from error


def coverage_report(
    cutover: dict[str, Any], audit_end: dict[str, Any], ledger_path: Path
) -> dict[str, Any]:
    if cutover.get("kind") != "cutover":
        raise EvidenceError("cutover artifact has the wrong kind")
    if audit_end.get("kind") != "audit_end":
        raise EvidenceError("audit-end artifact has the wrong kind")

    starts = validate_artifact(cutover)
    ends = validate_artifact(audit_end)
    if cutover["cluster_id"] != audit_end["cluster_id"]:
        raise EvidenceError("cutover and audit-end cluster_id values differ")
    if set(starts) != set(ends):
        missing = sorted(set(starts) - set(ends))
        extra = sorted(set(ends) - set(starts))
        raise EvidenceError(f"audit partition set differs; missing={missing}, extra={extra}")

    cutover_digest = canonical_sha256(cutover)
    if audit_end["cutover_sha256"] != cutover_digest:
        raise EvidenceError("audit-end artifact references a different cutover artifact")

    group_version = cutover["group_version"]
    observed: dict[tuple[str, str, int], list[tuple[int, str]]] = defaultdict(list)
    ignored_after_end = 0
    for line_number, row in load_ledger(ledger_path):
        group_id = require_string(row.get("group_id"), f"ledger:{line_number}.group_id")
        topic = require_string(row.get("topic"), f"ledger:{line_number}.topic")
        partition = require_nonnegative_int(
            row.get("partition"), f"ledger:{line_number}.partition"
        )
        offset = require_nonnegative_int(row.get("offset"), f"ledger:{line_number}.offset")
        status = require_string(row.get("status"), f"ledger:{line_number}.status")
        if status not in KNOWN_STATUSES:
            raise EvidenceError(f"ledger:{line_number}.status is unknown: {status}")
        if row.get("group_version") != group_version:
            raise EvidenceError(f"ledger:{line_number} has the wrong group_version")
        if row.get("artifact_sha256") != cutover_digest:
            raise EvidenceError(f"ledger:{line_number} has the wrong artifact_sha256")

        key = (group_id, topic, partition)
        if key not in starts:
            raise EvidenceError(
                f"ledger:{line_number} names unknown partition "
                f"{group_id}:{topic}[{partition}]"
            )
        if offset < starts[key]:
            raise EvidenceError(
                f"ledger:{line_number} proves forbidden pre-cutoff consumption at "
                f"{group_id}:{topic}[{partition}] offset {offset}"
            )
        if offset >= ends[key]:
            ignored_after_end += 1
            continue
        observed[key].append((offset, status))

    partition_reports: list[dict[str, Any]] = []
    totals = {"expected": 0, "processed": 0, "deduplicated": 0}
    for key in sorted(starts):
        group_id, topic, partition = key
        start = starts[key]
        end = ends[key]
        if end < start:
            raise EvidenceError(
                f"audit end precedes cutoff for {group_id}:{topic}[{partition}]"
            )
        rows = sorted(observed.get(key, []))
        cursor = start
        counts = {"processed": 0, "deduplicated": 0}
        for offset, status in rows:
            if offset < cursor:
                raise EvidenceError(
                    f"duplicate ledger offset {group_id}:{topic}[{partition}]@{offset}"
                )
            if offset > cursor:
                raise EvidenceError(
                    f"unexplained ledger gap {group_id}:{topic}[{partition}] "
                    f"offsets {cursor}..{offset - 1}"
                )
            if status not in CLEAN_STATUSES:
                raise EvidenceError(
                    f"unclean status {status} at {group_id}:{topic}[{partition}] offset {offset}"
                )
            counts[status] += 1
            cursor += 1
        if cursor != end:
            raise EvidenceError(
                f"unexplained ledger gap {group_id}:{topic}[{partition}] "
                f"offsets {cursor}..{end - 1}"
            )
        expected = end - start
        totals["expected"] += expected
        totals["processed"] += counts["processed"]
        totals["deduplicated"] += counts["deduplicated"]
        partition_reports.append(
            {
                "group_id": group_id,
                "topic": topic,
                "partition": partition,
                "cutoff": start,
                "audit_end": end,
                "expected": expected,
                **counts,
            }
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "coverage_report",
        "cluster_id": cutover["cluster_id"],
        "group_version": group_version,
        "cutover_sha256": cutover_digest,
        "clean": True,
        "totals": totals,
        "ignored_at_or_after_audit_end": ignored_after_end,
        "partitions": partition_reports,
    }


def group_plan(cutover: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    if cutover.get("kind") != "cutover":
        raise EvidenceError("group plan requires a cutover artifact")
    validate_artifact(cutover)
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in cutover["partitions"]:
        group_id = entry["group_id"]
        if not SAFE_GROUP_PATTERN.fullmatch(group_id):
            raise EvidenceError(f"group_id is unsafe for an offset filename: {group_id}")
        grouped[group_id].append(entry)

    output_dir.mkdir(parents=True, exist_ok=True)
    groups: list[dict[str, Any]] = []
    for group_id in sorted(grouped):
        entries = sorted(
            grouped[group_id], key=lambda item: (item["topic"], item["partition"])
        )
        offset_file = output_dir / f"{group_id}.offsets"
        offset_file.write_text(
            "".join(
                f'{entry["topic"]} {entry["partition"]} {entry["next_offset"]}\n'
                for entry in entries
            ),
            encoding="utf-8",
        )
        groups.append(
            {
                "group_id": group_id,
                "offset_file": str(offset_file.resolve()),
                "partition_count": len(entries),
                "rpk_argv": [
                    "rpk",
                    "group",
                    "seek",
                    group_id,
                    "--to-file",
                    str(offset_file.resolve()),
                ],
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "group_plan",
        "cluster_id": cutover["cluster_id"],
        "group_version": cutover["group_version"],
        "cutover_sha256": canonical_sha256(cutover),
        "groups": groups,
    }


def apply_group_plan(
    plan: dict[str, Any], rpk_config: Path, approval_sha256: str, cluster_id: str
) -> None:
    if plan.get("cutover_sha256") != approval_sha256:
        raise EvidenceError("approval SHA-256 does not match the signed cutover")
    if plan.get("cluster_id") != cluster_id:
        raise EvidenceError("confirmed cluster_id does not match the signed cutover")
    for group in plan["groups"]:
        command = [*group["rpk_argv"], "--config", str(rpk_config)]
        try:
            subprocess.run(command, check=True)
        except FileNotFoundError as error:
            raise EvidenceError("rpk is required to initialize consumer groups") from error
        except subprocess.CalledProcessError as error:
            raise EvidenceError(
                f'rpk failed while initializing group {group["group_id"]}'
            ) from error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    canonicalize = subparsers.add_parser("canonicalize")
    canonicalize.add_argument("artifact", type=Path)
    canonicalize.add_argument("--output", type=Path)

    checksum = subparsers.add_parser("checksum")
    checksum.add_argument("artifact", type=Path)

    sign = subparsers.add_parser("sign")
    sign.add_argument("artifact", type=Path)
    sign.add_argument("--private-key", required=True, type=Path)
    sign.add_argument("--signature", required=True, type=Path)

    verify = subparsers.add_parser("verify")
    verify.add_argument("artifact", type=Path)
    verify.add_argument("--public-key", required=True, type=Path)
    verify.add_argument("--signature", required=True, type=Path)

    coverage = subparsers.add_parser("coverage")
    coverage.add_argument("--cutover", required=True, type=Path)
    coverage.add_argument("--cutover-signature", required=True, type=Path)
    coverage.add_argument("--audit-end", required=True, type=Path)
    coverage.add_argument("--audit-end-signature", required=True, type=Path)
    coverage.add_argument("--public-key", required=True, type=Path)
    coverage.add_argument("--ledger", required=True, type=Path)
    coverage.add_argument("--output", type=Path)

    group_plan_parser = subparsers.add_parser("group-plan")
    group_plan_parser.add_argument("artifact", type=Path)
    group_plan_parser.add_argument("--signature", required=True, type=Path)
    group_plan_parser.add_argument("--public-key", required=True, type=Path)
    group_plan_parser.add_argument("--output-dir", required=True, type=Path)
    group_plan_parser.add_argument("--output", type=Path)

    group_apply = subparsers.add_parser("group-apply")
    group_apply.add_argument("artifact", type=Path)
    group_apply.add_argument("--signature", required=True, type=Path)
    group_apply.add_argument("--public-key", required=True, type=Path)
    group_apply.add_argument("--output-dir", required=True, type=Path)
    group_apply.add_argument("--rpk-config", required=True, type=Path)
    group_apply.add_argument("--approval-sha256", required=True)
    group_apply.add_argument("--confirm-cluster-id", required=True)

    return parser


def write_json(value: Any, output: Path | None) -> None:
    rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if output is None:
        sys.stdout.write(rendered)
    else:
        output.write_text(rendered, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "canonicalize":
            artifact = load_json(args.artifact)
            validate_artifact(artifact)
            rendered = canonical_bytes(artifact) + b"\n"
            if args.output is None:
                sys.stdout.buffer.write(rendered)
            else:
                args.output.write_bytes(rendered)
        elif args.command == "checksum":
            artifact = load_json(args.artifact)
            validate_artifact(artifact)
            print(canonical_sha256(artifact))
        elif args.command == "sign":
            sign_artifact(load_json(args.artifact), args.private_key, args.signature)
        elif args.command == "verify":
            verify_artifact(load_json(args.artifact), args.public_key, args.signature)
            print("signature valid")
        elif args.command == "coverage":
            cutover = load_json(args.cutover)
            audit_end = load_json(args.audit_end)
            verify_artifact(cutover, args.public_key, args.cutover_signature)
            verify_artifact(audit_end, args.public_key, args.audit_end_signature)
            write_json(coverage_report(cutover, audit_end, args.ledger), args.output)
        elif args.command in {"group-plan", "group-apply"}:
            cutover = load_json(args.artifact)
            verify_artifact(cutover, args.public_key, args.signature)
            plan = group_plan(cutover, args.output_dir)
            if args.command == "group-plan":
                write_json(plan, args.output)
            else:
                apply_group_plan(
                    plan,
                    args.rpk_config,
                    args.approval_sha256,
                    args.confirm_cluster_id,
                )
                print("consumer groups initialized at signed cutover offsets")
        else:  # pragma: no cover - argparse enforces this
            raise EvidenceError(f"unknown command: {args.command}")
    except EvidenceError as error:
        print(f"cutover evidence rejected: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
