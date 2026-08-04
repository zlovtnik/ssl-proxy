#!/usr/bin/env python3
"""Validate the tracked README inventory and local Markdown links."""

from __future__ import annotations

import argparse
import configparser
import re
import subprocess
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit


README_NAME = "README.md"
MARKDOWN_LINK = re.compile(
    r"!?\[[^\]]*]\(\s*(?P<target><[^>\n]+>|[^)\s]+)(?:\s+(?:\"[^\"]*\"|'[^']*'))?\s*\)"
)
REFERENCE_LINK = re.compile(
    r"^\s{0,3}\[[^\]]+]:\s*(?P<target><[^>\n]+>|\S+)", re.MULTILINE
)
HTML_ANCHOR = re.compile(
    r"<a\s+[^>]*(?:id|name)\s*=\s*[\"'](?P<anchor>[^\"']+)[\"'][^>]*>",
    re.IGNORECASE,
)
HEADING = re.compile(r"^\s{0,3}(?P<marks>#{1,6})\s+(?P<title>.+?)\s*#*\s*$")
HTML_TAG = re.compile(r"<[^>]+>")
INLINE_MARKUP = re.compile(r"[*_~`]")


class GitError(RuntimeError):
    pass


def run_git(root: Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if check and result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise GitError(f"git {' '.join(args)} failed in {root}: {detail}")
    return result.stdout


def run_git_bytes(root: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace").strip()
        raise GitError(f"git {' '.join(args)} failed in {root}: {detail}")
    return result.stdout


@dataclass(frozen=True)
class Gitlink:
    path: str
    oid: str


@dataclass
class SubmoduleSnapshot:
    root: Path
    oid: str
    files: set[str]

    def contains(self, relative: str) -> bool:
        normalized = relative.rstrip("/")
        if not normalized:
            return True
        return normalized in self.files or any(
            item.startswith(f"{normalized}/") for item in self.files
        )

    def read(self, relative: str) -> str:
        return run_git(self.root, "show", f"{self.oid}:{relative}")


class RepositoryView:
    def __init__(self, root: Path, snapshots: dict[str, SubmoduleSnapshot]):
        self.root = root.resolve()
        self.snapshots = snapshots

    def _snapshot_path(self, path: Path) -> tuple[SubmoduleSnapshot, str] | None:
        resolved = path.resolve()
        try:
            repo_relative = resolved.relative_to(self.root).as_posix()
        except ValueError:
            return None
        for prefix, snapshot in sorted(
            self.snapshots.items(), key=lambda item: len(item[0]), reverse=True
        ):
            if repo_relative == prefix:
                return snapshot, ""
            if repo_relative.startswith(f"{prefix}/"):
                return snapshot, repo_relative[len(prefix) + 1 :]
        return None

    def exists(self, path: Path) -> bool:
        located = self._snapshot_path(path)
        if located is None:
            return path.exists()
        snapshot, relative = located
        return snapshot.contains(relative)

    def read(self, path: Path) -> str:
        located = self._snapshot_path(path)
        if located is None:
            return path.read_text(encoding="utf-8")
        snapshot, relative = located
        return snapshot.read(relative)


def parse_gitlinks(root: Path) -> list[Gitlink]:
    records = run_git_bytes(root, "ls-files", "-s", "-z").split(b"\0")
    links: list[Gitlink] = []
    for record in records:
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, oid, _stage = metadata.decode().split()
        if mode == "160000":
            links.append(
                Gitlink(
                    path=raw_path.decode("utf-8", errors="surrogateescape"),
                    oid=oid,
                )
            )
    return links


def parse_submodule_mappings(root: Path) -> dict[str, str]:
    path = root / ".gitmodules"
    if not path.is_file():
        return {}
    parser = configparser.ConfigParser()
    parser.read(path, encoding="utf-8")
    mappings: dict[str, str] = {}
    for section in parser.sections():
        if not section.startswith("submodule "):
            continue
        submodule_path = parser.get(section, "path", fallback="").strip()
        if submodule_path:
            mappings[submodule_path] = parser.get(section, "url", fallback="").strip()
    return mappings


def load_inventory(path: Path) -> tuple[set[str], list[str]]:
    errors: list[str] = []
    if not path.is_file():
        return set(), [f"README inventory is missing: {path}"]
    entries: set[str] = set()
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        normalized = Path(value).as_posix()
        if normalized in entries:
            errors.append(f"{path}:{number}: duplicate inventory entry: {normalized}")
        entries.add(normalized)
    return entries, errors


def discover_readmes(
    root: Path,
) -> tuple[set[str], dict[str, SubmoduleSnapshot], list[str]]:
    errors: list[str] = []
    mappings = parse_submodule_mappings(root)
    gitlinks = parse_gitlinks(root)
    gitlink_paths = {link.path for link in gitlinks}

    for path in sorted(mappings.keys() - gitlink_paths):
        errors.append(f".gitmodules maps {path}, but the parent index has no gitlink")

    parent_files = {
        item.decode("utf-8", errors="surrogateescape")
        for item in run_git_bytes(root, "ls-files", "-z").split(b"\0")
        if item
    }
    readmes = {
        path
        for path in parent_files
        if Path(path).name == README_NAME and path not in gitlink_paths
    }
    snapshots: dict[str, SubmoduleSnapshot] = {}

    for link in gitlinks:
        if link.path not in mappings:
            errors.append(f"gitlink has no .gitmodules mapping: {link.path}")
            continue
        checkout = root / link.path
        if not checkout.is_dir():
            errors.append(f"submodule checkout is missing: {link.path}")
            continue
        inside = run_git(checkout, "rev-parse", "--is-inside-work-tree", check=False).strip()
        if inside != "true":
            errors.append(f"submodule checkout is not a Git worktree: {link.path}")
            continue
        object_check = subprocess.run(
            ["git", "-C", str(checkout), "cat-file", "-e", f"{link.oid}^{{commit}}"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if object_check.returncode != 0:
            errors.append(
                f"submodule checkout lacks parent-pinned commit {link.oid}: {link.path}"
            )
            continue
        files = {
            item.decode("utf-8", errors="surrogateescape")
            for item in run_git_bytes(
                checkout, "ls-tree", "-r", "--name-only", "-z", link.oid
            ).split(b"\0")
            if item
        }
        snapshots[link.path] = SubmoduleSnapshot(checkout, link.oid, files)
        readmes.update(
            f"{link.path}/{item}"
            for item in files
            if Path(item).name == README_NAME
        )

    return readmes, snapshots, errors


def strip_fenced_code(text: str) -> str:
    output: list[str] = []
    fence: tuple[str, int] | None = None
    for line in text.splitlines(keepends=True):
        match = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if fence is None and match:
            token = match.group(1)
            fence = (token[0], len(token))
            output.append("\n" if line.endswith("\n") else "")
            continue
        if fence is not None:
            if match and match.group(1)[0] == fence[0] and len(match.group(1)) >= fence[1]:
                fence = None
            output.append("\n" if line.endswith("\n") else "")
            continue
        output.append(line)
    return "".join(output)


def github_slug(value: str) -> str:
    value = HTML_TAG.sub("", value)
    value = INLINE_MARKUP.sub("", value).strip().lower()
    value = unicodedata.normalize("NFKC", value)
    value = "".join(
        char
        for char in value
        if char.isalnum() or char in {" ", "-", "_"}
    )
    return re.sub(r"\s+", "-", value)


def anchors_for(text: str) -> set[str]:
    clean = strip_fenced_code(text)
    anchors = {match.group("anchor") for match in HTML_ANCHOR.finditer(clean)}
    counts: dict[str, int] = {}
    for line in clean.splitlines():
        match = HEADING.match(line)
        if not match:
            continue
        base = github_slug(match.group("title"))
        if not base:
            continue
        occurrence = counts.get(base, 0)
        anchors.add(base if occurrence == 0 else f"{base}-{occurrence}")
        counts[base] = occurrence + 1
    return anchors


def local_targets(text: str) -> list[str]:
    clean = strip_fenced_code(text)
    clean = re.sub(r"(`+)[^\n]*?\1", "", clean)
    targets = [match.group("target") for match in MARKDOWN_LINK.finditer(clean)]
    targets.extend(match.group("target") for match in REFERENCE_LINK.finditer(clean))
    return [target[1:-1] if target.startswith("<") and target.endswith(">") else target for target in targets]


def validate_document(path: Path, text: str, view: RepositoryView) -> list[str]:
    errors: list[str] = []
    for target in local_targets(text):
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or target.startswith("//"):
            continue
        raw_path = unquote(parsed.path)
        fragment = unquote(parsed.fragment)
        if raw_path.startswith("/"):
            resolved = (view.root / raw_path.lstrip("/")).resolve()
        elif raw_path:
            resolved = (path.parent / raw_path).resolve()
        else:
            resolved = path.resolve()

        try:
            resolved.relative_to(view.root)
        except ValueError:
            errors.append(f"{path}: local link escapes repository: {target}")
            continue

        if not view.exists(resolved):
            errors.append(f"{path}: broken local link: {target}")
            continue
        if not fragment:
            continue
        try:
            target_text = view.read(resolved)
        except (OSError, GitError, UnicodeDecodeError) as error:
            errors.append(f"{path}: cannot read anchor target {target}: {error}")
            continue
        if fragment not in anchors_for(target_text):
            errors.append(f"{path}: invalid local anchor: {target}")
    return errors


def tracked_parent_documents(root: Path) -> set[str]:
    files = {
        item.decode("utf-8", errors="surrogateescape")
        for item in run_git_bytes(root, "ls-files", "-z").split(b"\0")
        if item
    }
    return {
        path
        for path in files
        if Path(path).name == README_NAME
        or (path.startswith("docs/") and path.endswith(".md"))
    }


def check_repository(root: Path, inventory_path: Path | None = None) -> list[str]:
    root = root.resolve()
    inventory_path = inventory_path or root / "docs/readme-inventory.txt"
    expected, errors = load_inventory(inventory_path)
    try:
        discovered, snapshots, discovery_errors = discover_readmes(root)
    except GitError as error:
        return errors + [str(error)]
    errors.extend(discovery_errors)

    for path in sorted(expected - discovered):
        errors.append(f"README inventory entry is missing or untracked: {path}")
    for path in sorted(discovered - expected):
        errors.append(f"tracked README is absent from inventory: {path}")

    view = RepositoryView(root, snapshots)
    documents = tracked_parent_documents(root)
    documents.update(discovered)
    for prefix, snapshot in snapshots.items():
        documents.update(
            f"{prefix}/{relative}"
            for relative in snapshot.files
            if Path(relative).suffix.lower() == ".md"
        )
    for relative in sorted(documents):
        path = root / relative
        try:
            text = view.read(path)
        except (OSError, GitError, UnicodeDecodeError) as error:
            errors.append(f"{path}: cannot read tracked Markdown: {error}")
            continue
        errors.extend(validate_document(path, text, view))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository root",
    )
    parser.add_argument("--inventory", type=Path, default=None)
    args = parser.parse_args()

    errors = check_repository(args.root, args.inventory)
    if errors:
        for error in errors:
            print(f"docs-check: {error}", file=sys.stderr)
        return 1
    print("docs-check: README inventory and local Markdown links are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
