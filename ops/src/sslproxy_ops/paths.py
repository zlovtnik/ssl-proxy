from __future__ import annotations

from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def repo_root() -> Path:
    """Return the ssl-proxy repository root without mutating process cwd."""

    start = Path(__file__).resolve()
    for candidate in start.parents:
        if (candidate / "AGENTS.md").is_file() and (candidate / "docker-compose.yaml").is_file():
            return candidate
    raise RuntimeError(f"could not locate ssl-proxy repo root from {start}")


def ops_root() -> Path:
    return repo_root() / "ops"

