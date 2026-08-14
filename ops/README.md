# sslproxy-ops

`sslproxy-ops` is the typed Python CLI used by the repository's host and
operator scripts. The shell wrappers under `scripts/` create or reuse the
`ops/.venv` environment and invoke this package.

Run an operator wrapper from the repository root, for example:

```bash
sudo ./scripts/prep_ath.sh wlan0
```

For development, install the package and its test dependencies in editable
mode:

```bash
python3 -m venv ops/.venv
ops/.venv/bin/python -m pip install -e 'ops[dev]'
ops/.venv/bin/python -m pytest ops/tests
```
