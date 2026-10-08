#!/usr/bin/env python3
"""Fail if any first-party UI theme tokens drift from theme/rclabs.tokens.json."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().with_name("sync_theme_tokens.py")

if __name__ == "__main__":
    sys.argv = [str(SCRIPT), "--check", *sys.argv[1:]]
    runpy.run_path(str(SCRIPT), run_name="__main__")
