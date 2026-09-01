#!/usr/bin/env python3
"""Generate or verify the platform input contract digest in the preflight Job."""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = Path("cyber-stack/platform-input-contract.yaml")
PREFLIGHT_PATH = Path(
    "cyber-stack/base/postgres-pool-readiness/platform-input-preflight.yaml"
)
DIGEST_PATTERN = re.compile(
    r'(?P<prefix>- name: EXPECTED_CONTRACT_SHA256\n\s+value: ")[0-9a-f]{64}(?P<suffix>")'
)


def contract_digest(root: Path) -> str:
    return hashlib.sha256((root / CONTRACT_PATH).read_bytes()).hexdigest()


def manifest_digest(root: Path) -> str:
    contents = (root / PREFLIGHT_PATH).read_text(encoding="utf-8")
    match = DIGEST_PATTERN.search(contents)
    if match is None:
        raise ValueError(f"{PREFLIGHT_PATH} has no valid EXPECTED_CONTRACT_SHA256")
    return match.group(0).rsplit('"', 2)[1]


def write_digest(root: Path, expected: str) -> None:
    path = root / PREFLIGHT_PATH
    contents = path.read_text(encoding="utf-8")
    updated, replacements = DIGEST_PATTERN.subn(
        lambda match: f"{match.group('prefix')}{expected}{match.group('suffix')}",
        contents,
    )
    if replacements != 1:
        raise ValueError(
            f"{PREFLIGHT_PATH} must contain exactly one EXPECTED_CONTRACT_SHA256"
        )
    path.write_text(updated, encoding="utf-8")


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
        expected = contract_digest(root)
        if args.write:
            write_digest(root, expected)
            print(f"updated {PREFLIGHT_PATH} to {expected}")
            return 0
        actual = manifest_digest(root)
    except (OSError, ValueError) as error:
        print(f"contract-digest: {error}", file=sys.stderr)
        return 1
    if actual != expected:
        print("contract-digest: preflight digest is stale", file=sys.stderr)
        print(f"expected: {expected}", file=sys.stderr)
        print(f"actual:   {actual}", file=sys.stderr)
        return 1
    print(f"contract-digest: {actual}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
