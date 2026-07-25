#!/usr/bin/env python3
"""Compatibility launcher for the canonical ``ops stack`` command."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    launcher = root / "scripts" / "stackctl.sh"
    os.execv("/bin/bash", ["bash", str(launcher), *sys.argv[1:]])
    return 126


if __name__ == "__main__":
    raise SystemExit(main())
