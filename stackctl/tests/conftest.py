"""pytest configuration for stackctl tests.

Ensures the stackctl/ directory is on sys.path so that deploy.py
can import from the stackctl module (stackctl.py).
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add the parent directory (stackctl/) to sys.path so that
# "from stackctl import ..." works when deploy.py is imported.
_stackctl_dir = Path(__file__).resolve().parent.parent
if str(_stackctl_dir) not in sys.path:
    sys.path.insert(0, str(_stackctl_dir))