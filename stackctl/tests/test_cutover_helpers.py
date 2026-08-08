from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from sslproxy_ops.stack.cutover import _live_uid, _validated_overlay_path


def test_live_uid_reports_managed_by_label_as_its_owner_source():
    live = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout=json.dumps(
            {
                "metadata": {
                    "uid": "uid-1",
                    "labels": {"app.kubernetes.io/managed-by": "kustomize"},
                }
            }
        ),
        stderr="",
    )
    with patch("sslproxy_ops.stack.cutover.kubectl", return_value=live):
        uid, owner_source, owner_value = _live_uid(
            ("apps", "Deployment", "default", "api"),
            "default",
            "test",
            None,
        )

    assert uid == "uid-1"
    assert owner_source == "app.kubernetes.io/managed-by"
    assert owner_value == "kustomize"


def test_validated_overlay_path_rejects_escape(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    with (
        patch(
            "sslproxy_ops.stack.cutover.OVERLAY_MAP",
            {"default": "../outside"},
        ),
        pytest.raises(RuntimeError, match="escapes root directory"),
    ):
        _validated_overlay_path({"namespace": "default"}, root)
