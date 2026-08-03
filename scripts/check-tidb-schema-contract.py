#!/usr/bin/env python3
"""Validate the canonical four-domain TiDB schema layout without YAML deps."""

from __future__ import annotations

import re
import sys
import hashlib
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
ROOT = REPO / "sql" / "tidb"
DOMAINS = frozenset(
    {"octopus_core", "atheros_search", "integration_console", "schema_migrator"}
)
UNSUPPORTED = {
    "trigger": re.compile(r"\bCREATE\s+TRIGGER\b", re.IGNORECASE),
    "stored routine": re.compile(r"\bCREATE\s+(?:FUNCTION|PROCEDURE)\b", re.IGNORECASE),
    "skip locked": re.compile(r"\bSKIP\s+LOCKED\b", re.IGNORECASE),
    "materialized view": re.compile(r"\bMATERIALIZED\s+VIEW\b", re.IGNORECASE),
    "PostgreSQL JSONB": re.compile(r"\bJSONB\b", re.IGNORECASE),
    "PostgreSQL timestamp": re.compile(r"\bTIMESTAMPTZ\b", re.IGNORECASE),
}


def apply_order(manifest: Path) -> list[str]:
    lines = manifest.read_text(encoding="utf-8").splitlines()
    try:
        start = next(index for index, line in enumerate(lines) if line == "apply_order:")
    except StopIteration:
        raise ValueError(f"{manifest}: missing apply_order") from None
    result: list[str] = []
    for line in lines[start + 1 :]:
        if line.startswith("  - "):
            result.append(line[4:].strip())
        elif line and not line.startswith(" "):
            break
    if not result:
        raise ValueError(f"{manifest}: apply_order must not be empty")
    return result


def scalar(manifest: Path, key: str) -> str | None:
    prefix = f"{key}:"
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :].strip().strip('"')
    return None


def executable_sql(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("--"))


def validate_checksums(
    manifest: Path, directory: Path, ordered: list[str], failures: list[str]
) -> None:
    checksum_relative = scalar(manifest, "checksums_file")
    if not checksum_relative:
        failures.append(f"{manifest.relative_to(REPO)}: missing checksums_file")
        return
    checksum_path = directory / checksum_relative
    if not checksum_path.is_file():
        failures.append(f"{manifest.relative_to(REPO)}: missing {checksum_relative}")
        return
    recorded: dict[str, str] = {}
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) != 2 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            failures.append(f"{checksum_path.relative_to(REPO)}: malformed checksum line")
            continue
        recorded[parts[1]] = parts[0]
    if set(recorded) != set(ordered):
        failures.append(
            f"{checksum_path.relative_to(REPO)}: paths differ from manifest apply_order"
        )
    for relative in ordered:
        path = directory / relative
        if path.is_file():
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if recorded.get(relative) != actual:
                failures.append(f"{path.relative_to(REPO)}: checksum mismatch")


def validate_grant_fixture(
    manifest: Path, directory: Path, domain: str, failures: list[str]
) -> None:
    grant_relative = scalar(manifest, "grant_fixture")
    if not grant_relative:
        failures.append(f"{manifest.relative_to(REPO)}: missing grant_fixture")
        return
    grant_path = directory / grant_relative
    if not grant_path.is_file():
        failures.append(f"{manifest.relative_to(REPO)}: missing {grant_relative}")
        return

    grant_sql = executable_sql(grant_path.read_text(encoding="utf-8"))
    if "RAILS_ACCOUNT" in grant_sql:
        failures.append(f"{grant_path.relative_to(REPO)}: obsolete Rails account grant")

    schema_sql = "\n".join(
        path.read_text(encoding="utf-8") for path in directory.rglob("*.sql")
    )
    objects = {
        match.group(1).lower()
        for match in re.finditer(
            r"\bCREATE\s+(?:TABLE|VIEW)\s+IF\s+NOT\s+EXISTS\s+`?([A-Za-z0-9_]+)`?",
            schema_sql,
            re.IGNORECASE,
        )
    }
    grants = list(
        re.finditer(
            r"\bGRANT\s+(.+?)\s+ON\s+`?([A-Za-z0-9_]+)`?\.`?([A-Za-z0-9_*]+)`?\s+TO\s+(.+?);",
            grant_sql,
            re.IGNORECASE | re.DOTALL,
        )
    )
    if not grants:
        if domain == "integration_console":
            return
        failures.append(f"{grant_path.relative_to(REPO)}: no GRANT statements")
        return

    for grant in grants:
        privileges, schema, table, _accounts = grant.groups()
        if schema.lower() != domain:
            failures.append(
                f"{grant_path.relative_to(REPO)}: grant targets unexpected schema {schema}"
            )
        if table != "*" and table.lower() not in objects:
            failures.append(
                f"{grant_path.relative_to(REPO)}: grant targets missing object {table}"
            )
        if domain == "atheros_search" and table == "*" and re.search(
            r"\b(?:INSERT|UPDATE|DELETE)\b", privileges, re.IGNORECASE
        ):
            failures.append(
                f"{grant_path.relative_to(REPO)}: cross-owner writes must be table-level"
            )


def main() -> int:
    failures: list[str] = []
    actual = {path.name for path in ROOT.iterdir() if path.is_dir()}
    active = actual - {"contracts"}
    if active != DOMAINS:
        failures.append(
            f"active domains must be exactly {sorted(DOMAINS)}; found {sorted(active)}"
        )
    if (ROOT / "core").exists():
        failures.append("retired sql/tidb/core baseline still exists")

    for domain in sorted(DOMAINS & actual):
        directory = ROOT / domain
        manifest = directory / "manifest.yaml"
        if not manifest.is_file():
            failures.append(f"{domain}: missing manifest.yaml")
            continue
        try:
            ordered = apply_order(manifest)
        except ValueError as error:
            failures.append(str(error))
            continue
        validate_grant_fixture(manifest, directory, domain, failures)
        listed = set()
        phases = [(directory, manifest, ordered)]
        post_manifest_relative = scalar(manifest, "post_tiflash_manifest")
        if domain == "atheros_search":
            if not post_manifest_relative:
                failures.append("atheros_search: missing post_tiflash_manifest")
            else:
                post_manifest = directory / post_manifest_relative
                if not post_manifest.is_file():
                    failures.append(
                        f"atheros_search: missing post-TiFlash manifest: {post_manifest_relative}"
                    )
                else:
                    if scalar(post_manifest, "phase") != "post_tiflash":
                        failures.append(f"{post_manifest.relative_to(REPO)}: phase must be post_tiflash")
                    try:
                        post_order = apply_order(post_manifest)
                        phases.append((post_manifest.parent, post_manifest, post_order))
                        gate_index = next(
                            i for i, value in enumerate(post_order) if "/gates/" in f"/{value}"
                        )
                        index_index = next(
                            i for i, value in enumerate(post_order) if "/indexes/" in f"/{value}"
                        )
                        if gate_index >= index_index:
                            failures.append("atheros_search: TiFlash readiness gate must precede HNSW DDL")
                    except (ValueError, StopIteration) as error:
                        failures.append(
                            f"{post_manifest.relative_to(REPO)}: incomplete gate/index order: {error}"
                        )

        for phase_directory, phase_manifest, phase_order in phases:
            validate_checksums(phase_manifest, phase_directory, phase_order, failures)
            for relative in phase_order:
                path = phase_directory / relative
                listed.add(path.resolve())
                if not path.is_file():
                    failures.append(
                        f"{phase_manifest.relative_to(REPO)}: entry does not exist: {relative}"
                    )
                    continue
                sql = executable_sql(path.read_text(encoding="utf-8"))
                for label, pattern in UNSUPPORTED.items():
                    if pattern.search(sql):
                        failures.append(f"{path.relative_to(REPO)}: unsupported {label}")
        unlisted = sorted(
            path.relative_to(directory).as_posix()
            for path in directory.rglob("*.sql")
            if path.resolve() not in listed
        )
        if unlisted:
            failures.append(f"{domain}: SQL files missing from apply_order: {unlisted}")

    search_sql = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (ROOT / "atheros_search").rglob("*.sql")
    ) if (ROOT / "atheros_search").exists() else ""
    if "VECTOR(768)" not in search_sql:
        failures.append("atheros_search: missing VECTOR(768) schema")
    if "HNSW" not in executable_sql(search_sql).upper():
        failures.append("atheros_search: missing post-TiFlash HNSW DDL")

    if failures:
        print("TiDB schema contract failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print("TiDB schema contract passed for all four isolated domains.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
