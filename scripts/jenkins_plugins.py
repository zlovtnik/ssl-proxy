#!/usr/bin/env python3
"""Generate and audit the reproducible Jenkins plugin lock."""

from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any


DEFAULT_REQUIREMENTS = Path("docker/jenkins/plugins.txt")
DEFAULT_LOCK = Path("docker/jenkins/plugins.lock.txt")
DEFAULT_DOCKERFILE = Path("docker/jenkins/Dockerfile")
DEFAULT_UPDATE_CENTER = "https://updates.jenkins.io/update-center.actual.json"
DEFAULT_RESOLVER_TIMEOUT = 240.0
DEFAULT_FETCH_TIMEOUT = 20.0
SYSTEM_CA_BUNDLES = (
    Path("/etc/ssl/cert.pem"),
    Path("/etc/ssl/certs/ca-certificates.crt"),
    Path("/etc/pki/tls/certs/ca-bundle.crt"),
)
PLUGIN_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
DIGEST_PINNED_IMAGE = re.compile(r"[^\s]+@sha256:[0-9a-f]{64}")


class PluginAuditError(Exception):
    """An actionable plugin lock or audit failure."""


def parse_pins_text(
    text: str, *, source: str, require_sorted: bool = False
) -> dict[str, str]:
    pins: dict[str, str] = {}
    names: list[str] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.count(":") != 1:
            raise PluginAuditError(
                f"{source}:{line_number}: expected an exact name:version pin"
            )
        name, version = line.split(":", 1)
        if not PLUGIN_NAME.fullmatch(name) or not version or any(
            character.isspace() for character in version
        ):
            raise PluginAuditError(
                f"{source}:{line_number}: invalid plugin pin {line!r}"
            )
        if version in {"latest", "experimental"} or "://" in version:
            raise PluginAuditError(
                f"{source}:{line_number}: plugin versions must be exact"
            )
        if name in pins:
            raise PluginAuditError(
                f"{source}:{line_number}: duplicate plugin pin for {name}"
            )
        pins[name] = version
        names.append(name)
    if not pins:
        raise PluginAuditError(f"{source}: no plugin pins found")
    if require_sorted and names != sorted(names):
        raise PluginAuditError(f"{source}: lock entries must be sorted by plugin name")
    return pins


def read_pins(path: Path, *, require_sorted: bool = False) -> dict[str, str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise PluginAuditError(f"cannot read {path}: {error}") from error
    return parse_pins_text(text, source=str(path), require_sorted=require_sorted)


def parse_resolver_output(output: str) -> dict[str, str]:
    marker = "Resulting plugin list:"
    marker_index = output.rfind(marker)
    if marker_index < 0:
        raise PluginAuditError(
            "plugin resolver output did not contain 'Resulting plugin list:'"
        )
    pins: dict[str, str] = {}
    for line in output[marker_index + len(marker) :].splitlines():
        line = line.strip()
        if not line:
            continue
        if line == "Done" or line.endswith("warnings:"):
            break
        fields = line.split()
        if len(fields) != 2:
            raise PluginAuditError(f"invalid plugin resolver result line: {line!r}")
        name, version = fields
        if not PLUGIN_NAME.fullmatch(name) or not version:
            raise PluginAuditError(f"invalid plugin resolver result line: {line!r}")
        if name in pins:
            raise PluginAuditError(f"plugin resolver returned duplicate plugin {name}")
        pins[name] = version
    if not pins:
        raise PluginAuditError("plugin resolver returned an empty effective plugin set")
    return pins


def extract_base_image(dockerfile: Path) -> str:
    try:
        text = dockerfile.read_text(encoding="utf-8")
    except OSError as error:
        raise PluginAuditError(f"cannot read {dockerfile}: {error}") from error
    match = re.search(r"(?m)^FROM\s+(\S+)", text)
    if match is None or DIGEST_PINNED_IMAGE.fullmatch(match.group(1)) is None:
        raise PluginAuditError(
            f"{dockerfile}: first base image must be pinned by sha256 digest"
        )
    return match.group(1)


def resolve_plugins(
    requirements: Path,
    dockerfile: Path,
    *,
    timeout: float = DEFAULT_RESOLVER_TIMEOUT,
    command_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, str]:
    image = extract_base_image(dockerfile)
    mount = f"{requirements.resolve()}:/tmp/plugins.txt:ro"
    command = [
        "docker",
        "run",
        "--rm",
        "--volume",
        mount,
        image,
        "jenkins-plugin-cli",
        "--plugin-file",
        "/tmp/plugins.txt",
        "--latest=true",
        "--no-download",
        "--list",
    ]
    try:
        result = command_runner(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise PluginAuditError(
            f"plugin resolver timed out after {timeout:g} seconds"
        ) from error
    except OSError as error:
        raise PluginAuditError(f"cannot run plugin resolver: {error}") from error
    if result.returncode != 0:
        detail = " ".join((result.stderr or result.stdout or "").split())
        raise PluginAuditError(
            f"plugin resolver failed with exit {result.returncode}: "
            f"{detail[:500] or 'no diagnostic output'}"
        )
    return parse_resolver_output(result.stdout)


def validate_direct_requirements(
    requirements: Mapping[str, str], effective: Mapping[str, str]
) -> None:
    missing = sorted(set(requirements) - set(effective))
    changed = sorted(
        name
        for name in requirements.keys() & effective.keys()
        if requirements[name] != effective[name]
    )
    details = []
    if missing:
        details.append("missing direct requirements: " + ", ".join(missing))
    if changed:
        details.append(
            "direct requirement versions changed by resolution: "
            + ", ".join(
                f"{name} {requirements[name]} -> {effective[name]}" for name in changed
            )
        )
    if details:
        raise PluginAuditError("; ".join(details))


def write_lock(path: Path, pins: Mapping[str, str]) -> None:
    content = "".join(f"{name}:{pins[name]}\n" for name in sorted(pins))
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.chmod(temporary_name, 0o644)
        os.replace(temporary_name, path)
    except OSError as error:
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass
        raise PluginAuditError(f"cannot atomically write {path}: {error}") from error


def fetch_update_center(
    url: str,
    *,
    timeout: float = DEFAULT_FETCH_TIMEOUT,
    opener: Callable[..., Any] = urllib.request.urlopen,
) -> Any:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "ssl-proxy-plugin-audit/1"},
    )
    default_paths = ssl.get_default_verify_paths()
    cafile = default_paths.cafile
    if cafile is None:
        cafile = next((str(path) for path in SYSTEM_CA_BUNDLES if path.is_file()), None)
    context = ssl.create_default_context(cafile=cafile)
    try:
        with opener(request, timeout=timeout, context=context) as response:
            payload = response.read()
    except (OSError, urllib.error.URLError) as error:
        raise PluginAuditError(f"cannot fetch Jenkins update-center metadata: {error}") from error
    try:
        return json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PluginAuditError(f"Jenkins update-center metadata is not valid JSON: {error}") from error


def matching_warnings(
    pins: Mapping[str, str], document: Any
) -> list[tuple[str, str, str, str, str]]:
    if not isinstance(document, Mapping):
        raise PluginAuditError("Jenkins update-center metadata must be a JSON object")
    warnings = document.get("warnings")
    if not isinstance(warnings, list):
        raise PluginAuditError("Jenkins update-center metadata has no valid warnings array")
    matches = []
    for index, warning in enumerate(warnings):
        location = f"warnings[{index}]"
        if not isinstance(warning, Mapping) or not isinstance(warning.get("type"), str):
            raise PluginAuditError(f"Jenkins update-center {location} is malformed")
        if warning["type"] != "plugin":
            continue
        required = ("name", "id", "message", "url", "versions")
        if any(key not in warning for key in required):
            raise PluginAuditError(f"Jenkins update-center {location} is malformed")
        name = warning["name"]
        warning_id = warning["id"]
        message = warning["message"]
        warning_url = warning["url"]
        versions = warning["versions"]
        if (
            not all(isinstance(value, str) and value for value in (name, warning_id, message, warning_url))
            or not isinstance(versions, list)
        ):
            raise PluginAuditError(f"Jenkins update-center {location} is malformed")
        if name not in pins:
            continue
        for version_index, version_range in enumerate(versions):
            if not isinstance(version_range, Mapping) or not isinstance(
                version_range.get("pattern"), str
            ):
                raise PluginAuditError(
                    f"Jenkins update-center {location}.versions[{version_index}] is malformed"
                )
            pattern = version_range["pattern"]
            try:
                affected = re.fullmatch(pattern, pins[name]) is not None
            except re.error as error:
                raise PluginAuditError(
                    f"Jenkins update-center {location} has invalid version pattern: {error}"
                ) from error
            if affected:
                matches.append(
                    (name, pins[name], warning_id, message, warning_url)
                )
                break
    return matches


def describe_drift(lock: Mapping[str, str], effective: Mapping[str, str]) -> list[str]:
    diagnostics = []
    added = sorted(set(effective) - set(lock))
    removed = sorted(set(lock) - set(effective))
    changed = sorted(
        name
        for name in lock.keys() & effective.keys()
        if lock[name] != effective[name]
    )
    if added:
        diagnostics.append("lock is missing resolved plugins: " + ", ".join(added))
    if removed:
        diagnostics.append("lock contains plugins no longer resolved: " + ", ".join(removed))
    if changed:
        diagnostics.append(
            "resolved plugin versions drifted: "
            + ", ".join(
                f"{name} {lock[name]} -> {effective[name]}" for name in changed
            )
        )
    return diagnostics


def generate_lock(requirements_path: Path, lock_path: Path, dockerfile: Path, timeout: float) -> None:
    requirements = read_pins(requirements_path)
    effective = resolve_plugins(requirements_path, dockerfile, timeout=timeout)
    validate_direct_requirements(requirements, effective)
    write_lock(lock_path, effective)
    print(f"Wrote {len(effective)} Jenkins plugin pins to {lock_path}")


def audit(
    requirements_path: Path,
    lock_path: Path,
    dockerfile: Path,
    update_center: str,
    resolver_timeout: float,
    fetch_timeout: float,
) -> None:
    requirements = read_pins(requirements_path)
    lock = read_pins(lock_path, require_sorted=True)
    effective = resolve_plugins(
        requirements_path, dockerfile, timeout=resolver_timeout
    )
    validate_direct_requirements(requirements, effective)
    diagnostics = describe_drift(lock, effective)
    document = fetch_update_center(update_center, timeout=fetch_timeout)
    warnings = matching_warnings(lock, document)
    diagnostics.extend(
        f"security warning for {name}:{version}: {warning_id}: {message} {url}"
        for name, version, warning_id, message, url in warnings
    )
    if diagnostics:
        raise PluginAuditError("\n".join(diagnostics))
    print(
        f"Jenkins plugin audit passed: {len(requirements)} direct requirements, "
        f"{len(lock)} locked plugins, no resolution drift or security warnings"
    )


def positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("timeout must be positive")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("lock", "audit"):
        subparser = subparsers.add_parser(name)
        subparser.add_argument("--requirements", type=Path, default=DEFAULT_REQUIREMENTS)
        subparser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
        subparser.add_argument("--dockerfile", type=Path, default=DEFAULT_DOCKERFILE)
        subparser.add_argument(
            "--resolver-timeout", type=positive_float, default=DEFAULT_RESOLVER_TIMEOUT
        )
    audit_parser = subparsers.choices["audit"]
    audit_parser.add_argument("--update-center", default=DEFAULT_UPDATE_CENTER)
    audit_parser.add_argument(
        "--fetch-timeout", type=positive_float, default=DEFAULT_FETCH_TIMEOUT
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "lock":
            generate_lock(
                arguments.requirements,
                arguments.lock,
                arguments.dockerfile,
                arguments.resolver_timeout,
            )
        else:
            audit(
                arguments.requirements,
                arguments.lock,
                arguments.dockerfile,
                arguments.update_center,
                arguments.resolver_timeout,
                arguments.fetch_timeout,
            )
    except PluginAuditError as error:
        print(f"jenkins-plugin-{arguments.command}: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
