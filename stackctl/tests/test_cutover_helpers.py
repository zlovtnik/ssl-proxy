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
                    "annotations": {"meta.helm.sh/release-name": "stale-release"},
                    "labels": {
                        "app.kubernetes.io/instance": "stale-release",
                        "app.kubernetes.io/managed-by": "kustomize",
                    },
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
    plan_path = tmp_path / "plan.json"
    backups = tmp_path / "backups"
    backups.mkdir()
    (backups / "overlay.yaml").write_text("kustomize_overlay: ../outside\n")

    with pytest.raises(RuntimeError, match="escapes root directory"):
        _validated_overlay_path(
            {"namespace": "default", "kustomize_overlay": "../outside"},
            root,
            plan_path,
        )


def test_validated_overlay_path_rejects_backup_mismatch(tmp_path: Path):
    root = tmp_path / "root"
    overlay = root / "cyber-stack" / "base"
    overlay.mkdir(parents=True)
    plan_path = tmp_path / "plan.json"
    backups = tmp_path / "backups"
    backups.mkdir()
    (backups / "overlay.yaml").write_text("kustomize_overlay: cyber-stack/matrix/dev\n")

    with pytest.raises(RuntimeError, match="does not match"):
        _validated_overlay_path(
            {"namespace": "default", "kustomize_overlay": "cyber-stack/base"},
            root,
            plan_path,
        )
