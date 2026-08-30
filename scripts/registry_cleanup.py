#!/usr/bin/env python3
"""Plan or apply safe retention to a Docker Registry v2 instance.

Git-pinned and live Kubernetes digests are always protected. The default mode
is read-only; manifest deletion requires both --apply and an exact confirmation.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import yaml

from image_contract import DIGEST_PATTERN, split_registry_repository


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_MEDIA_TYPES = (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
)
ACCEPT = ", ".join(MANIFEST_MEDIA_TYPES)
CONFIRMATION = "DELETE-UNPINNED-MANIFESTS"


class RegistryCleanupError(RuntimeError):
    """A registry inventory or safety check failed."""


@dataclass(frozen=True)
class DigestRecord:
    digest: str
    tags: tuple[str, ...]
    created: dt.datetime | None


@dataclass(frozen=True)
class RepositoryPlan:
    repository: str
    keep: tuple[DigestRecord, ...]
    delete: tuple[DigestRecord, ...]
    protected: frozenset[str]


class RegistryClient:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self._manifests: dict[tuple[str, str], Mapping[str, Any]] = {}
        self._created: dict[tuple[str, str], dt.datetime | None] = {}

    def _request(
        self,
        path_or_url: str,
        *,
        method: str = "GET",
        accept: str | None = None,
    ) -> tuple[Mapping[str, str], bytes]:
        url = (
            path_or_url
            if path_or_url.startswith(("http://", "https://"))
            else f"{self.base_url}{path_or_url}"
        )
        headers = {"Accept": accept} if accept else {}
        request = urllib.request.Request(url, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return dict(response.headers.items()), response.read()
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", errors="replace").strip()
            detail = body or error.reason
            raise RegistryCleanupError(
                f"registry {method} {urllib.parse.urlsplit(url).path} returned {error.code}: {detail}"
            ) from error
        except urllib.error.URLError as error:
            raise RegistryCleanupError(f"registry request failed: {error.reason}") from error

    def _paged(self, path: str, field: str) -> tuple[str, ...]:
        url: str | None = f"{self.base_url}{path}"
        values: list[str] = []
        while url:
            headers, body = self._request(url)
            try:
                payload = json.loads(body)
            except json.JSONDecodeError as error:
                raise RegistryCleanupError(f"registry returned invalid JSON for {path}") from error
            page = payload.get(field) or []
            if not isinstance(page, list) or not all(isinstance(item, str) for item in page):
                raise RegistryCleanupError(f"registry returned invalid {field} list")
            values.extend(page)
            url = next_link(headers.get("Link"), url)
        return tuple(values)

    def repositories(self) -> tuple[str, ...]:
        return self._paged("/v2/_catalog?n=100", "repositories")

    def tags(self, repository: str) -> tuple[str, ...]:
        encoded = quote_repository(repository)
        return self._paged(f"/v2/{encoded}/tags/list?n=100", "tags")

    def digest(self, repository: str, reference: str) -> str:
        encoded_repository = quote_repository(repository)
        encoded_reference = urllib.parse.quote(reference, safe=":")
        path = f"/v2/{encoded_repository}/manifests/{encoded_reference}"
        try:
            headers, _ = self._request(path, method="HEAD", accept=ACCEPT)
        except RegistryCleanupError:
            headers, _ = self._request(path, accept=ACCEPT)
        digest = header(headers, "Docker-Content-Digest")
        if digest is None or not DIGEST_PATTERN.fullmatch(digest):
            raise RegistryCleanupError(
                f"registry did not return a valid digest for {repository}:{reference}"
            )
        return digest

    def manifest(self, repository: str, digest: str) -> Mapping[str, Any]:
        key = (repository, digest)
        cached = self._manifests.get(key)
        if cached is not None:
            return cached
        encoded_repository = quote_repository(repository)
        headers, body = self._request(
            f"/v2/{encoded_repository}/manifests/{digest}", accept=ACCEPT
        )
        try:
            payload = json.loads(body)
        except json.JSONDecodeError as error:
            raise RegistryCleanupError(
                f"manifest {repository}@{digest} is invalid JSON"
            ) from error
        if not isinstance(payload, Mapping):
            raise RegistryCleanupError(f"manifest {repository}@{digest} is not an object")
        media_type = str(payload.get("mediaType") or header(headers, "Content-Type") or "")
        if media_type.split(";", 1)[0] not in MANIFEST_MEDIA_TYPES:
            raise RegistryCleanupError(
                f"manifest {repository}@{digest} has unsupported media type {media_type!r}"
            )
        self._manifests[key] = payload
        return payload

    def created(self, repository: str, digest: str) -> dt.datetime | None:
        key = (repository, digest)
        if key in self._created:
            return self._created[key]
        payload = self.manifest(repository, digest)
        created: dt.datetime | None = None
        children = payload.get("manifests")
        if isinstance(children, list):
            timestamps = []
            for child in children:
                if not isinstance(child, Mapping):
                    continue
                child_digest = child.get("digest")
                if isinstance(child_digest, str) and DIGEST_PATTERN.fullmatch(child_digest):
                    child_created = self.created(repository, child_digest)
                    if child_created is not None:
                        timestamps.append(child_created)
            if timestamps:
                created = max(timestamps)
        else:
            config = payload.get("config")
            config_digest = config.get("digest") if isinstance(config, Mapping) else None
            if isinstance(config_digest, str) and DIGEST_PATTERN.fullmatch(config_digest):
                encoded_repository = quote_repository(repository)
                _, blob = self._request(
                    f"/v2/{encoded_repository}/blobs/{config_digest}"
                )
                try:
                    config_payload = json.loads(blob)
                except json.JSONDecodeError:
                    config_payload = {}
                if isinstance(config_payload, Mapping):
                    created = parse_timestamp(config_payload.get("created"))
        self._created[key] = created
        return created

    def delete_manifest(self, repository: str, digest: str) -> None:
        encoded_repository = quote_repository(repository)
        self._request(
            f"/v2/{encoded_repository}/manifests/{digest}", method="DELETE"
        )


def header(headers: Mapping[str, str], name: str) -> str | None:
    expected = name.lower()
    for key, value in headers.items():
        if key.lower() == expected:
            return value
    return None


def next_link(link: str | None, current_url: str) -> str | None:
    if not link:
        return None
    current_parts = urllib.parse.urlsplit(current_url)
    for part in link.split(","):
        target, _, parameters = part.strip().partition(";")
        if 'rel="next"' not in parameters and "rel=next" not in parameters:
            continue
        if not target.startswith("<") or not target.endswith(">"):
            raise RegistryCleanupError("registry returned an invalid pagination Link")
        resolved = urllib.parse.urljoin(current_url, target[1:-1])
        resolved_parts = urllib.parse.urlsplit(resolved)
        if resolved_parts.scheme != current_parts.scheme or resolved_parts.netloc != current_parts.netloc:
            raise RegistryCleanupError(
                "registry returned a pagination link to a different authority"
            )
        return resolved
    return None


def quote_repository(repository: str) -> str:
    if not repository or repository.startswith("/") or ".." in repository.split("/"):
        raise RegistryCleanupError(f"invalid registry repository: {repository!r}")
    return "/".join(urllib.parse.quote(part, safe="") for part in repository.split("/"))


def parse_timestamp(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def reference_digest(reference: str) -> tuple[str, str, str] | None:
    for prefix in ("docker-pullable://", "docker://"):
        if reference.startswith(prefix):
            reference = reference[len(prefix) :]
    repository_reference, separator, digest = reference.rpartition("@")
    if not separator or not DIGEST_PATTERN.fullmatch(digest):
        return None
    last_slash = repository_reference.rfind("/")
    last_colon = repository_reference.rfind(":")
    if last_colon > last_slash:
        repository_reference = repository_reference[:last_colon]
    authority, repository = split_registry_repository(repository_reference)
    return authority, repository, digest


def git_protected_digests(root: Path, registry: str) -> dict[str, set[str]]:
    protected: dict[str, set[str]] = {}
    matrix = root / "cyber-stack/matrix"
    if not matrix.is_dir():
        raise RegistryCleanupError(f"cyber-stack/matrix directory not found: {matrix}")
    for path in sorted(matrix.rglob("*.yaml")):
        try:
            documents = yaml.safe_load_all(path.read_text(encoding="utf-8"))
            for document in documents:
                if not isinstance(document, Mapping):
                    continue
                images = document.get("images")
                if not isinstance(images, list):
                    continue
                for image in images:
                    if not isinstance(image, Mapping):
                        continue
                    repository_value = image.get("newName")
                    digest = image.get("digest")
                    if not isinstance(repository_value, str) or not isinstance(digest, str):
                        continue
                    if not DIGEST_PATTERN.fullmatch(digest):
                        continue
                    authority, repository = split_registry_repository(repository_value)
                    if authority == registry:
                        protected.setdefault(repository, set()).add(digest)
        except yaml.YAMLError as error:
            raise RegistryCleanupError(f"cannot parse {path}: {error}") from error
    return protected


def pod_image_references(payload: Mapping[str, Any]) -> Iterable[str]:
    items = payload.get("items")
    if not isinstance(items, list):
        raise RegistryCleanupError("kubectl pod inventory is invalid")
    for item in items:
        if not isinstance(item, Mapping):
            continue
        spec = item.get("spec")
        status = item.get("status")
        if isinstance(spec, Mapping):
            for field in ("initContainers", "containers", "ephemeralContainers"):
                containers = spec.get(field)
                if isinstance(containers, list):
                    for container in containers:
                        if isinstance(container, Mapping) and isinstance(container.get("image"), str):
                            yield container["image"]
        if isinstance(status, Mapping):
            for field in (
                "initContainerStatuses",
                "containerStatuses",
                "ephemeralContainerStatuses",
            ):
                statuses = status.get(field)
                if isinstance(statuses, list):
                    for container in statuses:
                        if isinstance(container, Mapping) and isinstance(container.get("imageID"), str):
                            yield container["imageID"]


def live_protected_digests(
    registry: str, context: str | None
) -> dict[str, set[str]]:
    command = ["kubectl"]
    if context:
        command.extend(("--context", context))
    command.extend(("get", "pods", "--all-namespaces", "-o", "json"))
    try:
        completed = subprocess.run(
            command, capture_output=True, check=False, timeout=60
        )
    except subprocess.TimeoutExpired as error:
        raise RegistryCleanupError(
            "live Kubernetes image inventory timed out"
        ) from error
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RegistryCleanupError(f"live Kubernetes image inventory failed: {detail}")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RegistryCleanupError("kubectl returned invalid JSON") from error
    protected: dict[str, set[str]] = {}
    for reference in pod_image_references(payload):
        parsed = reference_digest(reference)
        if parsed is None:
            continue
        authority, repository, digest = parsed
        if authority == registry:
            protected.setdefault(repository, set()).add(digest)
    return protected


def merge_protected(*sources: Mapping[str, set[str]]) -> dict[str, set[str]]:
    merged: dict[str, set[str]] = {}
    for source in sources:
        for repository, digests in source.items():
            merged.setdefault(repository, set()).update(digests)
    return merged


def choose_retention(
    repository: str,
    records: Sequence[DigestRecord],
    protected: set[str],
    latest_digest: str | None,
    keep_recent: int,
) -> RepositoryPlan:
    retained = set(protected)
    if latest_digest:
        retained.add(latest_digest)
    known = sorted(
        (record for record in records if record.created is not None),
        key=lambda record: (record.created, record.digest),
        reverse=True,
    )
    retained.update(record.digest for record in known[:keep_recent])
    retained.update(record.digest for record in records if record.created is None)
    keep = tuple(record for record in records if record.digest in retained)
    delete = tuple(record for record in records if record.digest not in retained)
    return RepositoryPlan(repository, keep, delete, frozenset(protected))


def inventory_repository(
    client: RegistryClient,
    repository: str,
    protected: set[str],
    keep_recent: int,
) -> RepositoryPlan:
    digest_tags: dict[str, set[str]] = {}
    for tag in client.tags(repository):
        digest_tags.setdefault(client.digest(repository, tag), set()).add(tag)
    for digest in protected:
        if digest not in digest_tags:
            try:
                client.digest(repository, digest)
            except RegistryCleanupError:
                continue
            digest_tags[digest] = set()
    records = tuple(
        DigestRecord(
            digest=digest,
            tags=tuple(sorted(tags)),
            created=client.created(repository, digest),
        )
        for digest, tags in sorted(digest_tags.items())
    )
    latest_digest = next(
        (record.digest for record in records if "latest" in record.tags), None
    )
    return choose_retention(
        repository, records, protected, latest_digest, keep_recent
    )


def format_created(value: dt.datetime | None) -> str:
    return value.isoformat().replace("+00:00", "Z") if value else "unknown"


def print_plan(plans: Sequence[RepositoryPlan]) -> None:
    total = 0
    for plan in plans:
        print(
            f"{plan.repository}: keep {len(plan.keep)} manifest(s), "
            f"delete {len(plan.delete)} manifest(s), protect {len(plan.protected)} digest(s)"
        )
        for record in plan.delete:
            tags = ",".join(record.tags[:4])
            if len(record.tags) > 4:
                tags += ",..."
            print(
                f"  DELETE {record.digest} created={format_created(record.created)} "
                f"tags={tags or '<untagged>'}"
            )
            total += 1
    print(f"planned manifest deletions: {total}")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "--registry",
        default=os.environ.get("REGISTRY", "192.168.1.242:5000"),
        help="registry authority without a URL scheme",
    )
    result.add_argument("--plain-http", action="store_true")
    result.add_argument("--repository-root", type=Path, default=REPOSITORY_ROOT)
    result.add_argument("--repository", action="append", default=[])
    result.add_argument("--keep-recent", type=int, default=12)
    result.add_argument("--context", help="kubectl context for live digest protection")
    result.add_argument("--skip-live-cluster", action="store_true")
    result.add_argument("--apply", action="store_true")
    result.add_argument("--confirm")
    return result


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        if arguments.keep_recent < 1:
            raise RegistryCleanupError("--keep-recent must be positive")
        if "/" in arguments.registry or "://" in arguments.registry:
            raise RegistryCleanupError("--registry must be an authority without a path or scheme")
        if arguments.apply and arguments.confirm != CONFIRMATION:
            raise RegistryCleanupError(
                f"--apply requires --confirm {CONFIRMATION}"
            )
        if arguments.apply and arguments.plain_http:
            raise RegistryCleanupError(
                "--apply is not allowed with --plain-http"
            )
        if arguments.apply and arguments.skip_live_cluster:
            raise RegistryCleanupError(
                "--apply requires live Kubernetes digest protection"
            )
        scheme = "http" if arguments.plain_http else "https"
        client = RegistryClient(f"{scheme}://{arguments.registry}")
        git_digests = git_protected_digests(
            arguments.repository_root.resolve(), arguments.registry
        )
        live_digests: dict[str, set[str]] = {}
        if not arguments.skip_live_cluster:
            live_digests = live_protected_digests(arguments.registry, arguments.context)
        protected = merge_protected(git_digests, live_digests)
        repositories = (
            tuple(arguments.repository)
            if arguments.repository
            else client.repositories()
        )
        plans = tuple(
            inventory_repository(
                client,
                repository,
                protected.get(repository, set()),
                arguments.keep_recent,
            )
            for repository in sorted(set(repositories))
        )
        print_plan(plans)
        if not arguments.apply:
            print(f"dry run only; use --apply --confirm {CONFIRMATION} after review")
            return 0
        for plan in plans:
            for record in plan.delete:
                client.delete_manifest(plan.repository, record.digest)
                print(f"deleted {plan.repository}@{record.digest}")
        print(
            "manifest deletion complete; stop the registry and run offline garbage "
            "collection before restarting it"
        )
        return 0
    except RegistryCleanupError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
