#!/usr/bin/env python3
"""Apply a verified release manifest and open or update its digest PR."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from image_contract import FIRST_PARTY_SERVICES, ImageContractError, load_image_contracts, validate_digest


SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class ReleaseImage:
    service: str
    repository: str
    digest: str


@dataclass(frozen=True)
class ReleaseManifest:
    source_revision: str
    images: tuple[ReleaseImage, ...]


def load_release_manifest(path: Path, repository_root: Path) -> ReleaseManifest:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ImageContractError(f"cannot load release manifest {path}: {error}") from error
    if not isinstance(document, Mapping) or document.get("schemaVersion") != 1:
        raise ImageContractError("release manifest must use schemaVersion 1")
    if document.get("environment") != "prod":
        raise ImageContractError("release manifest must target prod")
    source_revision = document.get("sourceRevision")
    if not isinstance(source_revision, str) or not SHA_PATTERN.fullmatch(source_revision):
        raise ImageContractError("release manifest sourceRevision must be a full Git SHA")
    expected = {contract.service: contract for contract in load_image_contracts(repository_root, "prod")}
    raw_images = document.get("images")
    if not isinstance(raw_images, list):
        raise ImageContractError("release manifest images must be a list")
    images: list[ReleaseImage] = []
    for item in raw_images:
        if not isinstance(item, Mapping):
            raise ImageContractError("release manifest image entries must be objects")
        service = item.get("service")
        repository = item.get("repository")
        digest = item.get("digest")
        if not isinstance(service, str) or service not in expected:
            raise ImageContractError(f"release manifest has unsupported service: {service}")
        if repository != expected[service].repository:
            raise ImageContractError(f"release manifest repository drift for {service}")
        if item.get("sourceRevision") != source_revision:
            raise ImageContractError(f"release manifest source revision drift for {service}")
        images.append(ReleaseImage(service, str(repository), validate_digest(str(digest))))
    if tuple(sorted(image.service for image in images)) != tuple(sorted(FIRST_PARTY_SERVICES)):
        raise ImageContractError("release manifest must contain every deployable service exactly once")
    return ReleaseManifest(source_revision, tuple(sorted(images, key=lambda image: image.service)))


def run(command: Sequence[str], root: Path, *, env: Mapping[str, str] | None = None) -> str:
    completed = subprocess.run(
        command,
        cwd=root,
        env=dict(env) if env is not None else None,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        detail = " ".join((completed.stderr or completed.stdout).split())[:500]
        raise RuntimeError(f"command failed ({command[0]}): {detail}")
    return completed.stdout.strip()


def github_request(token: str, repository: str, method: str, path: str, payload: Mapping[str, Any] | None = None) -> Any:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}{path}",
        data=data,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ssl-proxy-jenkins-promotion",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"GitHub API {method} {path} failed with {error.code}: {detail}") from error


def promote(manifest_path: Path, repository_root: Path, repository: str, token: str) -> str:
    manifest = load_release_manifest(manifest_path, repository_root)
    for image in manifest.images:
        run(
            (
                str(repository_root / "scripts" / "bump-image-digest.sh"),
                image.service,
                "prod",
                image.digest,
            ),
            repository_root,
        )
    changed = run(("git", "diff", "--name-only"), repository_root).splitlines()
    allowed = {
        "cyber-stack/matrix/prod/app-stack/kustomization.yaml",
        "cyber-stack/matrix/prod/data-plane/kustomization.yaml",
    }
    unexpected = sorted(set(changed) - allowed)
    if unexpected:
        raise RuntimeError("promotion attempted to include unexpected files: " + ", ".join(unexpected))
    if not changed:
        return "No digest changes were required"

    branch = f"codex/image-promotion-{manifest.source_revision[:12]}"
    run(("git", "checkout", "-B", branch), repository_root)
    run(("git", "config", "user.name", "ssl-proxy Jenkins"), repository_root)
    run(("git", "config", "user.email", "jenkins@ssl-proxy.invalid"), repository_root)
    run(("git", "add", *sorted(allowed)), repository_root)
    run(
        (
            "git",
            "commit",
            "-m",
            f"chore: promote images for {manifest.source_revision[:12]} [digest-promotion]",
        ),
        repository_root,
    )

    with tempfile.TemporaryDirectory(prefix="ssl-proxy-git-askpass-") as directory:
        askpass = Path(directory) / "askpass.sh"
        askpass.write_text(
            "#!/bin/sh\ncase \"$1\" in *Username*) printf '%s\\n' x-access-token ;; *Password*) printf '%s\\n' \"$GITHUB_TOKEN\" ;; *) exit 1 ;; esac\n",
            encoding="utf-8",
        )
        askpass.chmod(0o700)
        git_env = os.environ.copy()
        git_env.update(
            {
                "GITHUB_TOKEN": token,
                "GIT_ASKPASS": str(askpass),
                "GIT_TERMINAL_PROMPT": "0",
            }
        )
        run(("git", "push", "--force-with-lease", "origin", f"HEAD:refs/heads/{branch}"), repository_root, env=git_env)

    owner = repository.split("/", 1)[0]
    query = urllib.parse.urlencode({"state": "open", "head": f"{owner}:{branch}", "base": "main"})
    existing = github_request(token, repository, "GET", f"/pulls?{query}")
    title = f"Promote images for {manifest.source_revision[:12]}"
    body = (
        "Jenkins built and verified immutable registry digests for source revision "
        f"`{manifest.source_revision}`. Merge only after required checks and review pass."
    )
    if isinstance(existing, list) and existing:
        number = existing[0]["number"]
        result = github_request(token, repository, "PATCH", f"/pulls/{number}", {"title": title, "body": body})
    else:
        result = github_request(
            token,
            repository,
            "POST",
            "/pulls",
            {"title": title, "body": body, "head": branch, "base": "main"},
        )
    return str(result.get("html_url", "digest promotion PR updated"))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--github-repository", default="zlovtnik/ssl-proxy")
    arguments = parser.parse_args(argv)
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token:
        parser.error("GITHUB_TOKEN is required")
    try:
        print(promote(arguments.manifest, arguments.repository_root.resolve(), arguments.github_repository, token))
    except (ImageContractError, RuntimeError) as error:
        print(f"promotion failed: {error}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
