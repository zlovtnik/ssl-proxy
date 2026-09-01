#!/usr/bin/env python3
"""Validate and expose first-party Kubernetes image contracts."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode


DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
ENVIRONMENTS = ("dev", "prod")
SERVICE_SLICES = (
    ("ssl-proxy", "app-stack"),
    ("java-coordinator", "app-stack"),
    ("atheros-sensor", "app-stack"),
    ("atheros-search", "app-stack"),
    ("atheros-search-ui", "app-stack"),
    ("schema-migrator-backend", "app-stack"),
    ("schema-migrator-ui", "app-stack"),
    ("postgres-runtime-schema", "data-plane"),
)
FIRST_PARTY_SERVICES = tuple(service for service, _slice in SERVICE_SLICES)


class ImageContractError(ValueError):
    """The canonical Kustomize image contract is invalid."""


class KustomizationLoader(yaml.SafeLoader):
    """Load Kustomize's YAML 1.2 output with PyYAML's YAML 1.1 parser."""


def _construct_value_as_string(
    loader: KustomizationLoader, node: ScalarNode
) -> str:
    return loader.construct_scalar(node)


KustomizationLoader.add_constructor(
    "tag:yaml.org,2002:value", _construct_value_as_string
)


@dataclass(frozen=True)
class ImageContract:
    service: str
    slice_name: str
    repository: str
    digest: str

    @property
    def reference(self) -> str:
        return f"{self.repository}@{self.digest}"


def validate_environment(environment: str) -> str:
    if environment not in ENVIRONMENTS:
        raise ImageContractError(
            f"environment must be one of {', '.join(ENVIRONMENTS)}: {environment}"
        )
    return environment


def validate_digest(value: str, *, label: str = "digest") -> str:
    if not DIGEST_PATTERN.fullmatch(value):
        raise ImageContractError(
            f"{label} must be sha256 followed by exactly 64 lowercase hexadecimal characters"
        )
    return value


def split_registry_repository(repository: str) -> tuple[str, str]:
    """Return the registry authority and Registry API repository path."""

    parts = repository.split("/")
    first = parts[0]
    if "." in first or ":" in first or first == "localhost":
        if len(parts) < 2:
            raise ImageContractError(f"image repository has no path: {repository}")
        return first, "/".join(parts[1:])
    if len(parts) == 1:
        return "registry-1.docker.io", f"library/{repository}"
    return "registry-1.docker.io", repository


def _load_kustomization(path: Path) -> Mapping[str, Any]:
    try:
        document = yaml.load(
            path.read_text(encoding="utf-8"), Loader=KustomizationLoader
        )
    except FileNotFoundError as error:
        raise ImageContractError(f"canonical Kustomization is missing: {path}") from error
    except yaml.YAMLError as error:
        raise ImageContractError(f"cannot parse {path}: {error}") from error
    if not isinstance(document, Mapping) or document.get("kind") != "Kustomization":
        raise ImageContractError(f"expected a Kustomization document: {path}")
    return document


def _image_entries(path: Path) -> dict[str, list[Mapping[str, Any]]]:
    document = _load_kustomization(path)
    raw_images = document.get("images", [])
    if not isinstance(raw_images, list):
        raise ImageContractError(f"images must be a list in {path}")

    entries: dict[str, list[Mapping[str, Any]]] = {}
    for index, item in enumerate(raw_images):
        if not isinstance(item, Mapping):
            raise ImageContractError(f"images[{index}] must be a mapping in {path}")
        name = item.get("name")
        if not isinstance(name, str) or not name:
            raise ImageContractError(f"images[{index}].name must be a string in {path}")
        entries.setdefault(name, []).append(item)
    return entries


def _validate_repository(value: Any, *, service: str, path: Path) -> str:
    if not isinstance(value, str) or not value:
        raise ImageContractError(f"{path}: {service} must define newName")
    if (
        value != value.strip()
        or any(character.isspace() for character in value)
        or "://" in value
        or "@" in value
        or "/" not in value
    ):
        raise ImageContractError(
            f"{path}: {service} newName must be an untagged image repository: {value!r}"
        )
    final_component = value.rsplit("/", 1)[-1]
    if ":" in final_component:
        raise ImageContractError(
            f"{path}: {service} newName must not contain a tag: {value}"
        )
    return value


def _validate_entry(
    service: str, entry: Mapping[str, Any], *, path: Path
) -> tuple[str, str]:
    if "newTag" in entry:
        raise ImageContractError(
            f"{path}: {service} uses newTag; first-party images must be digest-pinned"
        )
    repository = _validate_repository(entry.get("newName"), service=service, path=path)
    digest_value = entry.get("digest")
    if not isinstance(digest_value, str):
        raise ImageContractError(f"{path}: {service} must define a digest")
    digest = validate_digest(digest_value, label=f"{path}: {service} digest")
    return repository, digest


def load_image_contracts(repository_root: Path, environment: str) -> tuple[ImageContract, ...]:
    """Load the eight deployable image repositories and pins from Kustomize."""

    environment = validate_environment(environment)
    matrix = repository_root.resolve() / "cyber-stack" / "matrix" / environment
    paths = {
        "app-stack": matrix / "app-stack" / "kustomization.yaml",
        "data-plane": matrix / "data-plane" / "kustomization.yaml",
    }
    entries = {name: _image_entries(path) for name, path in paths.items()}
    service_slices = dict(SERVICE_SLICES)

    for slice_name in ("app-stack", "data-plane"):
        for service in FIRST_PARTY_SERVICES:
            count = len(entries[slice_name].get(service, []))
            expected = service_slices[service] == slice_name
            if expected and count != 1:
                raise ImageContractError(
                    f"{paths[slice_name]} must contain exactly one image mapping for "
                    f"{service}; found {count}"
                )
            if not expected and count:
                raise ImageContractError(
                    f"{paths[slice_name]} contains first-party image {service}, owned by "
                    f"{service_slices[service]}"
                )

    contracts: list[ImageContract] = []
    for service, slice_name in SERVICE_SLICES:
        owner_entry = entries[slice_name][service][0]
        owner_value = _validate_entry(service, owner_entry, path=paths[slice_name])
        contracts.append(
            ImageContract(
                service=service,
                slice_name=slice_name,
                repository=owner_value[0],
                digest=owner_value[1],
            )
        )
    return tuple(contracts)


def registry_authority(contracts: Sequence[ImageContract]) -> str:
    """Return the one registry authority shared by deployable image contracts."""

    authorities = {
        split_registry_repository(contract.repository)[0] for contract in contracts
    }
    if len(authorities) != 1:
        raise ImageContractError(
            "deployable image contracts must use one registry authority; found "
            + ", ".join(sorted(authorities))
        )
    return next(iter(authorities))


def load_registry_authority(repository_root: Path, environment: str) -> str:
    """Load and validate the registry authority for one environment."""

    return registry_authority(load_image_contracts(repository_root, environment))


def repository_from_kustomization(path: Path, service: str) -> str:
    entries = _image_entries(path)
    matches = entries.get(service, [])
    if len(matches) != 1:
        raise ImageContractError(
            f"{path} must contain exactly one image mapping for {service}; found {len(matches)}"
        )
    return _validate_repository(matches[0].get("newName"), service=service, path=path)


def _mapping_value(node: MappingNode, field: str) -> ScalarNode | SequenceNode | MappingNode | None:
    for key_node, value_node in node.value:
        if isinstance(key_node, ScalarNode) and key_node.value == field:
            return value_node
    return None


def update_image_digest(path: Path, service: str, digest: str) -> None:
    """Update one validated image digest without reformatting the Kustomization."""

    digest = validate_digest(digest)
    repository_from_kustomization(path, service)
    content = path.read_text(encoding="utf-8")
    try:
        document_node = yaml.compose(content, Loader=KustomizationLoader)
    except yaml.YAMLError as error:
        raise ImageContractError(f"cannot parse {path}: {error}") from error
    if not isinstance(document_node, MappingNode):
        raise ImageContractError(f"expected a Kustomization document: {path}")
    images_node = _mapping_value(document_node, "images")
    if not isinstance(images_node, SequenceNode):
        raise ImageContractError(f"images must be a list in {path}")

    digest_nodes: list[ScalarNode] = []
    for image_node in images_node.value:
        if not isinstance(image_node, MappingNode):
            continue
        name_node = _mapping_value(image_node, "name")
        if not isinstance(name_node, ScalarNode) or name_node.value != service:
            continue
        digest_node = _mapping_value(image_node, "digest")
        if not isinstance(digest_node, ScalarNode):
            raise ImageContractError(f"{path}: {service} must define a digest")
        digest_nodes.append(digest_node)
    if len(digest_nodes) != 1:
        raise ImageContractError(
            f"{path} must contain exactly one image mapping for {service}; "
            f"found {len(digest_nodes)}"
        )

    digest_node = digest_nodes[0]
    updated = (
        content[: digest_node.start_mark.index]
        + digest
        + content[digest_node.end_mark.index :]
    )
    if updated == content:
        return
    mode = path.stat().st_mode
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as temporary:
            temporary.write(updated)
            temporary_name = temporary.name
        os.chmod(temporary_name, mode)
        os.replace(temporary_name, path)
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def extract_buildx_digest(metadata: Mapping[str, Any]) -> str:
    """Extract the pushed manifest digest from Docker Buildx metadata."""

    candidates: list[str] = []
    direct = metadata.get("containerimage.digest")
    if isinstance(direct, str):
        candidates.append(direct)

    flat_descriptor = metadata.get("containerimage.descriptor.digest")
    if isinstance(flat_descriptor, str):
        candidates.append(flat_descriptor)

    descriptor = metadata.get("containerimage.descriptor")
    if isinstance(descriptor, Mapping) and isinstance(descriptor.get("digest"), str):
        candidates.append(descriptor["digest"])

    if not candidates:
        raise ImageContractError(
            "Buildx metadata does not contain containerimage.digest or a descriptor digest"
        )
    unique = set(candidates)
    if len(unique) != 1:
        raise ImageContractError(
            f"Buildx metadata contains inconsistent manifest digests: {sorted(unique)}"
        )
    return validate_digest(candidates[0], label="Buildx manifest digest")


def load_buildx_digest(path: Path) -> str:
    try:
        metadata = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ImageContractError(f"Buildx metadata file is missing: {path}") from error
    except json.JSONDecodeError as error:
        raise ImageContractError(f"cannot parse Buildx metadata {path}: {error}") from error
    if not isinstance(metadata, Mapping):
        raise ImageContractError(f"Buildx metadata must be a JSON object: {path}")
    return extract_buildx_digest(metadata)


def _contract_command(arguments: argparse.Namespace) -> int:
    contracts = load_image_contracts(arguments.repository_root, arguments.environment)
    if arguments.format == "json":
        print(
            json.dumps(
                [
                    {
                        "service": contract.service,
                        "slice": contract.slice_name,
                        "repository": contract.repository,
                        "digest": contract.digest,
                        "reference": contract.reference,
                    }
                    for contract in contracts
                ],
                indent=2,
                sort_keys=True,
            )
        )
    else:
        for contract in contracts:
            print(
                "\t".join(
                    (
                        contract.service,
                        contract.slice_name,
                        contract.repository,
                        contract.digest,
                    )
                )
            )
    return 0


def _metadata_command(arguments: argparse.Namespace) -> int:
    print(load_buildx_digest(arguments.metadata))
    return 0


def _registry_authority_command(arguments: argparse.Namespace) -> int:
    print(load_registry_authority(arguments.repository_root, arguments.environment))
    return 0


def _repository_command(arguments: argparse.Namespace) -> int:
    print(repository_from_kustomization(arguments.kustomization, arguments.service))
    return 0


def _set_digest_command(arguments: argparse.Namespace) -> int:
    update_image_digest(arguments.kustomization, arguments.service, arguments.digest)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    contract = subparsers.add_parser("contract", help="print the selected image contract")
    contract.add_argument("--environment", choices=ENVIRONMENTS, default="prod")
    contract.add_argument(
        "--repository-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    contract.add_argument("--format", choices=("tsv", "json"), default="tsv")
    contract.set_defaults(handler=_contract_command)

    authority = subparsers.add_parser(
        "registry-authority",
        help="print the shared registry authority for the selected image contract",
    )
    authority.add_argument("--environment", choices=ENVIRONMENTS, default="prod")
    authority.add_argument(
        "--repository-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    authority.set_defaults(handler=_registry_authority_command)

    metadata = subparsers.add_parser(
        "buildx-digest", help="extract the pushed manifest digest from Buildx metadata"
    )
    metadata.add_argument("metadata", type=Path)
    metadata.set_defaults(handler=_metadata_command)

    repository = subparsers.add_parser(
        "repository", help="read one image repository from a Kustomization"
    )
    repository.add_argument("--kustomization", type=Path, required=True)
    repository.add_argument("--service", required=True)
    repository.set_defaults(handler=_repository_command)

    set_digest = subparsers.add_parser(
        "set-digest", help="update one image digest without reformatting the file"
    )
    set_digest.add_argument("--kustomization", type=Path, required=True)
    set_digest.add_argument("--service", required=True)
    set_digest.add_argument("--digest", required=True)
    set_digest.set_defaults(handler=_set_digest_command)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        return arguments.handler(arguments)
    except ImageContractError as error:
        print(f"image contract error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
