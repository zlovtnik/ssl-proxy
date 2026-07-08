from __future__ import annotations

from pathlib import Path

from sslproxy_ops import shell


def render_qr_text(text: str, *, qr_type: str, margin: int) -> None:
    shell.run(
        ["qrencode", "-t", qr_type, "-m", str(margin)],
        check=True,
        capture=False,
        input_text=text,
    )


def render_qr_file(path: Path, *, qr_type: str, margin: int) -> None:
    render_qr_text(path.read_text(), qr_type=qr_type, margin=margin)

