#!/usr/bin/env bash

sslproxy_ensure_ops_venv() {
    local root="$1"
    local venv="$root/ops/.venv"
    local marker="$venv/.installed"

    if [ -x "$venv/bin/python" ] &&
        [ -f "$marker" ] &&
        [ "$marker" -nt "$root/ops/pyproject.toml" ] &&
        [ "$marker" -nt "$root/ops/uv.lock" ]; then
        return
    fi

    if ! python3 -m venv "$venv"; then
        echo "failed to create $venv; install python3-venv or set OPS_PYTHON to a prepared Python" >&2
        exit 1
    fi
    "$venv/bin/python" -m pip install --upgrade pip
    "$venv/bin/python" -m pip install -e "$root/ops"
    touch "$marker"
}

sslproxy_exec_ops() {
    local root="$1"
    shift

    if [ -n "${OPS_PYTHON:-}" ]; then
        exec env PYTHONPATH="$root/ops/src${PYTHONPATH:+:$PYTHONPATH}" "$OPS_PYTHON" -m sslproxy_ops "$@"
    fi

    if command -v uv >/dev/null 2>&1; then
        exec uv run --project "$root/ops" python -m sslproxy_ops "$@"
    fi

    sslproxy_ensure_ops_venv "$root"
    exec "$root/ops/.venv/bin/python" -m sslproxy_ops "$@"
}
