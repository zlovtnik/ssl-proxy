"""pytest configuration for stackctl tests.

Ensures the stackctl/ directory is on sys.path so that deploy.py
can import from the stackctl module (stackctl.py).
"""

from __future__ import annotations

import sys
from pathlib import Path

_root = Path(__file__).resolve().parents[2]
_ops_src = _root / "ops" / "src"
if str(_ops_src) not in sys.path:
    sys.path.insert(0, str(_ops_src))

# Preserve historical test imports while exercising the canonical modules.
from sslproxy_ops.stack import core as _core  # noqa: E402
from sslproxy_ops.stack import deploy as _deploy  # noqa: E402
from sslproxy_ops.stack import gates as _gates  # noqa: E402
from sslproxy_ops.stack import shell as _shell  # noqa: E402

sys.modules["stackctl"] = _core
sys.modules["deploy"] = _deploy
sys.modules["gates"] = _gates
sys.modules["shell"] = _shell
