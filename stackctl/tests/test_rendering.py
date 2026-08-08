"""Security tests for render artifact paths."""

from __future__ import annotations

from pathlib import Path

import pytest

from sslproxy_ops.stack.core import StackConfig
from sslproxy_ops.stack.deploy import _redact_dict
from sslproxy_ops.stack.rendering import (
    RenderedComponent,
    _filter_sensitive,
    safe_artifact_dir,
    write_parity_artifacts,
)


def test_filter_sensitive_removes_nested_keys_from_collections():
    filtered = _filter_sensitive(
        {
            "database": {"host": "tidb", "password": "db-password"},
            "clients": [
                {"name": "keycloak", "adminPassword": "admin-password"},
                {"name": "public", "port": 8080},
            ],
        }
    )

    assert filtered == {
        "database": {"host": "tidb"},
        "clients": [
            {"name": "keycloak"},
            {"name": "public", "port": 8080},
        ],
    }


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


def test_parity_artifacts_redact_all_secret_payload_fields(tmp_path: Path):
    encoded_secret = "YXJiaXRyYXJ5LXNlY3JldA=="
    plain_secret = "arbitrary-plain-secret"
    secret = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": "opaque-secret",
            "annotations": {"password": "sensitive-annotation"},
        },
        "data": {"arbitraryPayload": encoded_secret},
        "stringData": {"unrecognizedPayload": plain_secret},
    }
    component = RenderedComponent(
        name="test",
        manifest="",
        resources=[secret],
        effective_values={},
    )

    write_parity_artifacts(
        tmp_path,
        StackConfig(version=1),
        tmp_path,
        [secret],
        [component],
        [],
        _redact_dict,
    )

    for name in ("umbrella.normalized.yaml", "split.normalized.yaml"):
        snapshot = (tmp_path / name).read_text()
        assert encoded_secret not in snapshot
        assert plain_secret not in snapshot
        assert "sensitive-annotation" not in snapshot
        assert "[REDACTED]" in snapshot
