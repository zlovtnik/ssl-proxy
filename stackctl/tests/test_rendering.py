"""Security tests for render artifact paths."""

from __future__ import annotations

from pathlib import Path

import pytest

from sslproxy_ops.stack.rendering import safe_artifact_dir


def test_artifact_path_cannot_leave_repository(tmp_path: Path):
    with pytest.raises(ValueError, match="repository root"):
        safe_artifact_dir(tmp_path, "../outside")


def test_artifact_path_rejects_symlink_parent(tmp_path: Path):
    outside = tmp_path.parent / "outside-artifacts"
    outside.mkdir(exist_ok=True)
    link = tmp_path / "linked"
    link.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        safe_artifact_dir(tmp_path, link / "run")
