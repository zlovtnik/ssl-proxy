#!/usr/bin/env python3
"""Publish the first-party images selected by a canonical environment."""

from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from image_contract import (
    ENVIRONMENTS,
    ImageContract,
    ImageContractError,
    load_buildx_digest,
    load_image_contracts,
    split_registry_repository,
)


RunCommand = Callable[[Sequence[str], Path], int]


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
    ]


def publication_report(
    contract: ImageContract, pushed_digest: str, environment: str
) -> str:
    status = "MATCH" if pushed_digest == contract.digest else "UNPINNED"
    bump_command = (
        f"make bump-digest-{contract.service} ENV={environment} DIGEST={pushed_digest}"
    )
    return "\n".join(
        (
            f"{contract.service}: {status}",
            f"  repository: {contract.repository}",
            f"  pinned:     {contract.digest}",
            f"  pushed:     {pushed_digest}",
            f"  bump:       {bump_command}",
        )
    )


def _run_command(command: Sequence[str], repository_root: Path) -> int:
    return subprocess.run(command, cwd=repository_root, check=False).returncode


def publish_environment(
    repository_root: Path,
    settings: PublishSettings,
    *,
    run_command: RunCommand = _run_command,
    output: Callable[[str], None] = print,
) -> int:
    contracts = load_image_contracts(repository_root, settings.environment)
    output(
        f"Publishing {len(contracts)} Kubernetes images for ENV={settings.environment}; "
        "repositories and pins come from canonical Kustomize"
    )
    with tempfile.TemporaryDirectory(prefix="ssl-proxy-buildx-metadata-") as directory:
        metadata_root = Path(directory)
        for contract in contracts:
            metadata_path = metadata_root / f"{contract.service}.json"
            command = make_publish_command(contract, metadata_path, settings)
            output(f"\nPublishing {contract.service} -> {contract.repository}")
            returncode = run_command(command, repository_root)
            if returncode != 0:
                output(
                    f"{contract.service}: publication failed with exit status {returncode}"
                )
                return returncode or 1
            try:
                pushed_digest = load_buildx_digest(metadata_path)
            except ImageContractError as error:
                output(f"{contract.service}: cannot verify pushed digest: {error}")
                return 1
            output(publication_report(contract, pushed_digest, settings.environment))
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
    parser.add_argument("--make-command", default="make")
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
        make_command=tuple(shlex.split(arguments.make_command)),
    )
    try:
        return publish_environment(arguments.repository_root.resolve(), settings)
    except ImageContractError as error:
        print(f"image contract error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
