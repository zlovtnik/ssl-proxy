from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from sslproxy_ops.stack.cluster import preflight
from sslproxy_ops.stack.core import StackConfig


def test_preflight_requires_helm_after_kubectl(tmp_path: Path):
    with patch(
        "sslproxy_ops.stack.cluster.shutil.which",
        side_effect=lambda name: "/usr/bin/kubectl" if name == "kubectl" else None,
    ):
        with pytest.raises(RuntimeError, match="required tool not found: helm"):
            preflight(StackConfig(version=1), tmp_path, "default", None, None)
