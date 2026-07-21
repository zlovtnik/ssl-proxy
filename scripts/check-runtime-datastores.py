#!/usr/bin/env python3
"""Reject active PostgreSQL or MongoDB runtime configuration outside allowlists."""

from __future__ import annotations

import fnmatch
import json
import re
import sys
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = REPO / "config" / "runtime-datastore-policy.json"


def load_policy(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema_version") != 1:
        raise ValueError("runtime datastore policy schema_version must be 1")
    return value


def files_to_scan(policy: dict[str, Any]) -> list[Path]:
    excluded = set(policy["excluded_path_parts"])
    extensions = set(policy["text_extensions"])
    files: set[Path] = set()
    for configured in policy["scan_roots"]:
        root = REPO / configured
        candidates = root.rglob("*") if root.is_dir() else [root]
        for candidate in candidates:
            relative = candidate.relative_to(REPO)
            if candidate.is_file() and not excluded.intersection(relative.parts):
                if candidate.suffix in extensions or candidate.name.startswith("Dockerfile"):
                    files.add(candidate)
    return sorted(files)


def is_allowed(relative: str, pattern_id: str, policy: dict[str, Any]) -> bool:
    return any(
        pattern_id in entry["pattern_ids"]
        and fnmatch.fnmatchcase(relative, entry["path_glob"])
        for entry in policy["allowlist"]
    )


def violations(policy: dict[str, Any]) -> list[str]:
    patterns = {
        pattern_id: re.compile(expression)
        for pattern_id, expression in policy["forbidden_patterns"].items()
    }
    found: list[str] = []
    for path in files_to_scan(policy):
        relative = path.relative_to(REPO).as_posix()
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        for line_number, line in enumerate(lines, start=1):
            for pattern_id, pattern in patterns.items():
                if pattern.search(line) and not is_allowed(relative, pattern_id, policy):
                    found.append(f"{relative}:{line_number}: {pattern_id}: {line.strip()}")
    return found


def main() -> int:
    policy_path = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_POLICY
    policy = load_policy(policy_path)
    found = violations(policy)
    if found:
        print("Active retired datastore configuration found:", file=sys.stderr)
        for violation in found:
            print(violation, file=sys.stderr)
        return 1
    print("Runtime datastore policy passed: TiDB is authoritative; Redis is ephemeral.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
