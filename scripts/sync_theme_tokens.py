#!/usr/bin/env python3
"""Sync or check RCLabs theme token values across first-party UI surfaces.

Reads theme/rclabs.tokens.json (single source of truth) and rewrites or verifies
the mapped local custom properties in each surface file. Local alias names stay
unchanged; only hex/font values are managed.

Usage:
  python3 scripts/sync_theme_tokens.py           # rewrite managed token values
  python3 scripts/sync_theme_tokens.py --check   # exit 1 on drift
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
TOKENS_PATH = Path("theme/rclabs.tokens.json")

# local CSS/TS property name -> role key in the JSON (core/semantic/fonts)
# Only tokens that hold literal hex or font-stack values are listed.

CSS_ROOT = "css-root"
TS_OBJECT = "ts-object"

SURFACES: list[dict] = [
    {
        "path": "apps/product-site/src/styles/site.css",
        "format": CSS_ROOT,
        "map": {
            "--bg": "core.page",
            "--surface": "core.surface",
            "--raised": "core.raised",
            "--inset": "core.inset",
            "--text": "core.text",
            "--muted": "core.muted",
            "--action": "core.accent",
            "--action-text": "core.on-accent",
            "--success": "semantic.success",
            "--rule": "core.border",
            "--divider": "core.divider",
            "--focus": "core.accent",
        },
    },
    {
        "path": "apps/integration-console/atheros-search-ui/src/styles/tokens.css",
        "format": CSS_ROOT,
        "map": {
            "--color-bg": "core.page",
            "--color-bg-alt": "core.surface",
            "--color-surface": "core.surface",
            "--color-surface-2": "core.raised",
            "--color-surface-3": "core.raised",
            "--color-border": "core.border",
            "--color-border-strong": "core.muted",
            "--color-border-focus": "core.accent",
            "--color-text-primary": "core.text",
            "--color-text-secondary": "core.muted",
            "--color-text-tertiary": "core.muted",
            "--color-accent": "core.accent",
            "--color-accent-strong": "semantic.accent-hover",
            "--color-accent-ink": "core.on-accent",
            "--color-info": "semantic.info",
            "--color-warn": "semantic.warning",
            "--color-warn-bg": "semantic.warning-bg",
            "--color-danger": "semantic.danger",
            "--color-danger-bg": "semantic.danger-bg",
            "--color-ok": "semantic.success",
            "--color-ok-bg": "semantic.success-bg",
            "--font-sans": "fonts.sans",
            "--font-mono": "fonts.mono",
        },
    },
    {
        "path": "apps/schema-migrator/schema-migrator-ui/src/design/tokens.ts",
        "format": TS_OBJECT,
        "map": {
            "--color-obsidian-950": "core.page",
            "--color-obsidian-925": "core.surface",
            "--color-obsidian-900": "core.surface",
            "--color-obsidian-850": "core.raised",
            "--color-obsidian-800": "core.raised",
            "--color-obsidian-700": "core.border",
            "--color-stone-500": "core.muted",
            "--color-stone-100": "core.text",
            "--color-amber-500": "semantic.warning",
            "--color-green-500": "core.accent",
            "--color-green-400": "semantic.accent-hover",
            "--color-blue-500": "semantic.info",
            "--color-red-500": "semantic.danger",
            "--color-red-400": "semantic.danger-hover",
            "--color-border-strong": "core.muted",
            "--color-accent-contrast": "core.on-accent",
            "--font-sans": "fonts.sans",
            "--font-mono": "fonts.mono",
        },
    },
    {
        "path": (
            "cyber-stack/base/schema-migrator/configmaps/keycloak-theme/"
            "login/resources/css/custom-login.css"
        ),
        "format": CSS_ROOT,
        "map": {
            "--auth-bg": "core.page",
            "--auth-card": "core.surface",
            "--auth-control": "core.raised",
            "--auth-control-focus": "core.raised",
            "--auth-border": "core.border",
            "--auth-border-strong": "core.muted",
            "--auth-border-active": "core.accent",
            "--auth-ring": "core.accent",
            "--auth-text": "core.text",
            "--auth-muted": "core.muted",
            "--auth-subtle": "core.muted",
            "--auth-accent": "core.accent",
            "--auth-accent-hover": "semantic.accent-hover",
            "--auth-error": "semantic.danger",
            "--auth-error-border": "semantic.danger",
            "--auth-warning": "semantic.warning",
            "--auth-info": "semantic.info",
        },
    },
    {
        "path": "static/index.html",
        "format": CSS_ROOT,
        "map": {
            "--bg": "core.page",
            "--surface": "core.surface",
            "--border": "core.border",
            "--text": "core.text",
            "--muted": "core.muted",
            "--green": "core.accent",
            "--yellow": "semantic.warning",
            "--red": "semantic.danger",
            "--blue": "semantic.info",
        },
    },
]

HEX_RE = re.compile(r"^#[0-9A-Fa-f]{6}$")


def load_roles(root: Path) -> dict[str, str]:
    data = json.loads((root / TOKENS_PATH).read_text(encoding="utf-8"))
    roles: dict[str, str] = {}
    for section in ("core", "semantic", "fonts"):
        for name, value in data[section].items():
            roles[f"{section}.{name}"] = value
    return roles


def normalize_hex(value: str) -> str:
    value = value.strip()
    if HEX_RE.match(value):
        return "#" + value[1:].upper()
    return value


def expected_value(roles: dict[str, str], role: str) -> str:
    try:
        return normalize_hex(roles[role])
    except KeyError as exc:
        raise SystemExit(f"unknown theme role: {role}") from exc


def css_pattern(local: str) -> re.Pattern[str]:
    return re.compile(
        rf"(?P<prefix>{re.escape(local)}\s*:\s*)(?P<value>[^;]+)(?P<suffix>;)"
    )


def ts_pattern(local: str) -> re.Pattern[str]:
    return re.compile(
        rf"(?P<prefix>\"{re.escape(local)}\"\s*:\s*(?P<q>['\"]))"
        rf"(?P<value>.*?)(?P<suffix>(?P=q))"
    )


def process_file(
    root: Path,
    surface: dict,
    roles: dict[str, str],
    *,
    check: bool,
) -> list[str]:
    path = root / surface["path"]
    text = path.read_text(encoding="utf-8")
    pattern_factory = css_pattern if surface["format"] == CSS_ROOT else ts_pattern
    errors: list[str] = []
    updated = text

    for local, role in surface["map"].items():
        want = expected_value(roles, role)
        pattern = pattern_factory(local)
        matches = list(pattern.finditer(updated))
        if not matches:
            errors.append(f"{surface['path']}: missing token {local}")
            continue
        if len(matches) > 1:
            errors.append(f"{surface['path']}: duplicate token {local}")
            continue
        match = matches[0]
        current = match.group("value").strip()
        current_norm = normalize_hex(current)
        want_norm = normalize_hex(want)
        # Font stacks are not hex; compare after strip only.
        if current_norm == want_norm or current.strip() == want:
            continue
        if check:
            errors.append(
                f"{surface['path']}: {local} is {current!r}, expected {want!r} ({role})"
            )
            continue
        replacement = (
            f"{match.group('prefix')}{want}{match.group('suffix')}"
        )
        updated = updated[: match.start()] + replacement + updated[match.end() :]

    if not check and updated != text:
        path.write_text(updated, encoding="utf-8")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="report drift and exit non-zero instead of rewriting files",
    )
    args = parser.parse_args()
    roles = load_roles(REPOSITORY_ROOT)
    errors: list[str] = []
    for surface in SURFACES:
        errors.extend(
            process_file(REPOSITORY_ROOT, surface, roles, check=args.check)
        )
    if errors:
        for line in errors:
            print(line, file=sys.stderr)
        print(f"theme tokens: {len(errors)} problem(s)", file=sys.stderr)
        return 1
    mode = "check" if args.check else "sync"
    print(f"theme tokens {mode}: ok ({len(SURFACES)} surfaces)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
