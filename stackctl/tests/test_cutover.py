"""Tests for digest-guarded Helm ownership cutover."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from sslproxy_ops.stack.core import Component, StackConfig
from sslproxy_ops.stack.cutover import (
    _canonical_digest,
    apply_plan,
    load_verified_plan,
)


def _private_plan(tmp_path: Path) -> tuple[Path, dict]:
    payload = {
        "version": 1,
        "context": "test",
        "namespace": "default",
        "umbrella_release": "ssl-proxy",
        "kustomize_overlay": "cyber-stack/base",
        "matrix": [],
        "finalized": False,
    }
    payload["digest"] = _canonical_digest(payload)
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(payload))
    os.chmod(path, 0o600)
    return path, payload


def test_plan_digest_rejects_tampering(tmp_path: Path):
    path, payload = _private_plan(tmp_path)
    assert load_verified_plan(path, payload["digest"])["context"] == "test"
    payload["namespace"] = "other"
    path.write_text(json.dumps(payload))
    with pytest.raises(RuntimeError, match="digest mismatch"):
        load_verified_plan(path, payload["digest"])


def test_plan_rejects_symlink(tmp_path: Path):
    path, payload = _private_plan(tmp_path)
    link = tmp_path / "linked-plan.json"
    link.symlink_to(path)
    with pytest.raises(RuntimeError, match="symlink"):
        load_verified_plan(link, payload["digest"])


def test_apply_uses_plan_captured_overlay(tmp_path: Path):
    path, payload = _private_plan(tmp_path)
    backups = tmp_path / "backups"
    backups.mkdir()
    for name in ("live-state.json", "manifest.redacted.yaml", "pvcs.json"):
        (backups / name).write_text("{}")
    (backups / "overlay.yaml").write_text(
        "kustomize_overlay: cyber-stack/base\n"
    )
    overlay = tmp_path / "cyber-stack" / "base"
    overlay.mkdir(parents=True)
    config = StackConfig(
        version=1,
        components={
            "config": Component(
                type="helm",
                stage="bootstrap",
                release="ssl-proxy-platform-config",
                chart="./chart",
                values_key="platformConfig",
            )
        },
    )
    rendered = SimpleNamespace(effective_values={"global": {}})
    with (
        patch("sslproxy_ops.stack.cutover._verify_confirmations"),
        patch("sslproxy_ops.stack.cutover._verify_uids"),
        patch("sslproxy_ops.stack.cutover.load_umbrella_values", return_value=[{}]),
        patch("sslproxy_ops.stack.cutover.render_component", return_value=rendered),
        patch("sslproxy_ops.stack.cutover.kustomize_apply") as mock_apply,
        patch("sslproxy_ops.stack.cutover.status", return_value=[]),
        patch("sslproxy_ops.stack.cutover.smoke", return_value=[]),
    ):
        apply_plan(
            config,
            tmp_path,
            path,
            payload["digest"],
            "test",
            "ssl-proxy",
            True,
            None,
            {},
        )

    assert mock_apply.call_args.args == (str(overlay),)
