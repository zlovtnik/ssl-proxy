#!/usr/bin/env python3
"""Publish the first-party images selected by a canonical environment."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from classify_changes import SUBMODULE_IMAGES
from image_contract import (
    ENVIRONMENTS,
    FIRST_PARTY_SERVICES,
    ImageContract,
    ImageContractError,
    load_buildx_digest,
    load_image_contracts,
    split_registry_repository,
)


RunCommand = Callable[[Sequence[str], Path], int]
SUBMODULE_SERVICE_PATHS = {
    service: path
    for path, services in SUBMODULE_IMAGES.items()
    for service in services
    if path.startswith("apps/")
}


@dataclass(frozen=True)
class PublishSettings:
    environment: str
    tag: str
    build_date: str
    builder: str
    platform: str
    registry_plain_http: str
    atheros_search_ui_api_base: str
    atheros_search_ui_title: str
    atheros_search_ui_keycloak_url: str
    atheros_search_ui_keycloak_realm: str
    atheros_search_ui_keycloak_client_id: str
    source_revision: str
    make_command: tuple[str, ...] = ("make",)


def make_publish_command(
    contract: ImageContract,
    metadata_path: Path,
    settings: PublishSettings,
) -> list[str]:
    registry, _repository_path = split_registry_repository(contract.repository)
    return [
        *settings.make_command,
        "--no-print-directory",
        f"publish-{contract.service}",
        f"TAG={settings.tag}",
        f"BUILD_DATE={settings.build_date}",
        f"BUILDER={settings.builder}",
        f"PLATFORM={settings.platform}",
        f"REGISTRY={registry}",
        f"REGISTRY_PLAIN_HTTP={settings.registry_plain_http}",
        f"PUBLISH_REPOSITORY={contract.repository}",
        f"PUBLISH_METADATA_FILE={metadata_path}",
        f"ATHEROS_SEARCH_UI_API_BASE={settings.atheros_search_ui_api_base}",
        f"ATHEROS_SEARCH_UI_TITLE={settings.atheros_search_ui_title}",
        f"ATHEROS_SEARCH_UI_KEYCLOAK_URL={settings.atheros_search_ui_keycloak_url}",
        f"ATHEROS_SEARCH_UI_KEYCLOAK_REALM={settings.atheros_search_ui_keycloak_realm}",
        f"ATHEROS_SEARCH_UI_KEYCLOAK_CLIENT_ID={settings.atheros_search_ui_keycloak_client_id}",
    ]


def submodule_revision(repository_root: Path, path: str) -> str:
    result = subprocess.run(
        ("git", "ls-tree", "HEAD", "--", path),
        cwd=repository_root,
        capture_output=True,
        text=True,
        check=False,
    )
    fields = result.stdout.split(None, 3)
    if result.returncode or len(fields) != 4 or fields[:2] != ["160000", "commit"]:
        raise ImageContractError(f"cannot read pinned gitlink for {path}")
    return fields[2]


def make_reuse_command(
    contract: ImageContract, metadata_path: Path, settings: PublishSettings, revision: str
) -> list[str]:
    return [
        "docker", "buildx", "imagetools", "create", "--builder", settings.builder,
        "--tag", f"{contract.repository}:{settings.tag}",
        "--tag", f"{contract.repository}:latest",
        "--metadata-file", str(metadata_path),
        f"{contract.repository}:{revision}",
    ]


def publication_report(
    contract: ImageContract, pushed_digest: str, environment: str
) -> str:
    status = "MATCH" if pushed_digest == contract.digest else "UNPINNED"
    lines = [
        f"{contract.service}: {status}",
        f"  repository: {contract.repository}",
        f"  pinned:     {contract.digest}",
        f"  pushed:     {pushed_digest}",
    ]
    if status == "UNPINNED":
        lines.append(f"  bump:       {bump_command(contract, pushed_digest, environment)}")
    else:
        lines.append("  bump:       not required")
    return "\n".join(lines)


def bump_command(
    contract: ImageContract, pushed_digest: str, environment: str
) -> str:
    return (
        f"make bump-digest-{contract.service} "
        f"ENV={environment} DIGEST={pushed_digest}"
    )


def bump_commands_report(commands: Sequence[str]) -> str:
    if not commands:
        return "No digest updates are required."
    return "\n".join(
        (
            "Manual digest updates (run only when ready):",
            *commands,
        )
    )


def _run_command(command: Sequence[str], repository_root: Path) -> int:
    return subprocess.run(command, cwd=repository_root, check=False).returncode


def non_empty_value(value: str) -> str:
    if not value.strip():
        raise argparse.ArgumentTypeError("must not be empty")
    return value


def publish_environment(
    repository_root: Path,
    settings: PublishSettings,
    *,
    run_command: RunCommand = _run_command,
    output: Callable[[str], None] = print,
    max_workers: int = 1,
    manifest_out: Path | None = None,
    commands_out: Path | None = None,
    only: Sequence[str] | None = None,
    reuse_submodules: bool = False,
) -> int:
    if max_workers < 1 or max_workers > 3:
        raise ImageContractError("max workers must be between 1 and 3")
    contracts = load_image_contracts(repository_root, settings.environment)
    if only is not None:
        unknown = set(only) - set(FIRST_PARTY_SERVICES)
        if unknown:
            raise ImageContractError("unknown service(s): " + ", ".join(sorted(unknown)))
        selected = set(only)
        contracts = tuple(contract for contract in contracts if contract.service in selected)
    output(
        f"Publishing {len(contracts)} Kubernetes images for ENV={settings.environment}; "
        "repositories and pins come from canonical Kustomize"
    )
    with tempfile.TemporaryDirectory(prefix="ssl-proxy-buildx-metadata-") as directory:
        metadata_root = Path(directory)
        def publish_one(
            contract: ImageContract,
        ) -> tuple[int, str, dict[str, str] | None, str | None]:
            metadata_path = metadata_root / f"{contract.service}.json"
            source_revision = settings.source_revision
            if reuse_submodules and contract.service in SUBMODULE_SERVICE_PATHS:
                source_revision = submodule_revision(
                    repository_root, SUBMODULE_SERVICE_PATHS[contract.service]
                )
                command = make_reuse_command(contract, metadata_path, settings, source_revision)
            else:
                command = make_publish_command(contract, metadata_path, settings)
            returncode = run_command(command, repository_root)
            if returncode != 0:
                return (
                    returncode or 1,
                    f"{contract.service}: publication failed with exit status {returncode}",
                    None,
                    None,
                )
            try:
                pushed_digest = load_buildx_digest(metadata_path)
            except ImageContractError as error:
                return (
                    1,
                    f"{contract.service}: cannot verify pushed digest: {error}",
                    None,
                    None,
                )
            command = (
                bump_command(contract, pushed_digest, settings.environment)
                if pushed_digest != contract.digest
                else None
            )
            return (
                0,
                publication_report(contract, pushed_digest, settings.environment),
                {
                    "service": contract.service,
                    "slice": contract.slice_name,
                    "repository": contract.repository,
                    "digest": pushed_digest,
                    "sourceRevision": source_revision,
                },
                command,
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(executor.map(publish_one, contracts))
        for _returncode, report, _entry, _command in results:
            output(report)
        failures = [
            returncode
            for returncode, _report, _entry, _command in results
            if returncode
        ]
        if failures:
            return failures[0]
        entries = [
            entry
            for _returncode, _report, entry, _command in results
            if entry is not None
        ]
        commands = [
            command
            for _returncode, _report, _entry, command in results
            if command is not None
        ]
        if manifest_out is not None:
            manifest_out.parent.mkdir(parents=True, exist_ok=True)
            document = {
                "schemaVersion": 1,
                "environment": settings.environment,
                "sourceRevision": settings.source_revision,
                "generatedAt": settings.build_date,
                "images": entries,
            }
            manifest_out.write_text(
                json.dumps(document, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        if commands_out is not None:
            commands_out.parent.mkdir(parents=True, exist_ok=True)
            commands_out.write_text(
                bump_commands_report(commands) + "\n",
                encoding="utf-8",
            )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment", choices=ENVIRONMENTS, default="prod")
    parser.add_argument(
        "--repository-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--tag", required=True)
    parser.add_argument("--build-date", required=True)
    parser.add_argument("--builder", required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--registry-plain-http", choices=("0", "1"), default="0")
    parser.add_argument("--atheros-search-ui-api-base", default="")
    parser.add_argument("--atheros-search-ui-title", default="atheros search")
    parser.add_argument(
        "--atheros-search-ui-keycloak-url", default="https://gateway.rclabs.uk"
    )
    parser.add_argument("--atheros-search-ui-keycloak-realm", default="middleware")
    parser.add_argument(
        "--atheros-search-ui-keycloak-client-id", default="atheros-search-ui"
    )
    parser.add_argument("--make-command", default="make")
    parser.add_argument("--source-revision", required=True, type=non_empty_value)
    parser.add_argument("--max-workers", type=int, default=1)
    parser.add_argument("--manifest-out", type=Path)
    parser.add_argument("--commands-out", type=Path)
    parser.add_argument("--only", help="comma-separated services; an empty value publishes none")
    parser.add_argument("--reuse-submodules", choices=("true", "false"), default="false")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    settings = PublishSettings(
        environment=arguments.environment,
        tag=arguments.tag,
        build_date=arguments.build_date,
        builder=arguments.builder,
        platform=arguments.platform,
        registry_plain_http=arguments.registry_plain_http,
        atheros_search_ui_api_base=arguments.atheros_search_ui_api_base,
        atheros_search_ui_title=arguments.atheros_search_ui_title,
        atheros_search_ui_keycloak_url=arguments.atheros_search_ui_keycloak_url,
        atheros_search_ui_keycloak_realm=arguments.atheros_search_ui_keycloak_realm,
        atheros_search_ui_keycloak_client_id=(
            arguments.atheros_search_ui_keycloak_client_id
        ),
        source_revision=arguments.source_revision,
        make_command=tuple(shlex.split(arguments.make_command)),
    )
    try:
        return publish_environment(
            arguments.repository_root.resolve(),
            settings,
            max_workers=arguments.max_workers,
            manifest_out=arguments.manifest_out,
            commands_out=arguments.commands_out,
            only=None if arguments.only is None else tuple(filter(None, arguments.only.split(","))),
            reuse_submodules=arguments.reuse_submodules == "true",
        )
    except ImageContractError as error:
        print(f"image contract error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
