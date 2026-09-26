#!/usr/bin/env python3
"""Check or repair Cloudflare Pages watch paths for the pinned UI submodules."""

from __future__ import annotations

import argparse
import copy
import fnmatch
import json
import os
from pathlib import Path
import ssl
import sys
import tomllib
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
PROJECT_SUBMODULES = {
    "ssl-proxy-search": "apps/integration-console",
    "ssl-proxy-migrator": "apps/schema-migrator",
}


def watch_paths_patch(project: dict, name: str) -> dict:
    source = project.get("source") or {}
    config = source.get("config") or {}
    if (
        project.get("name") != name
        or source.get("type") != "github"
        or config.get("owner") != "zlovtnik"
        or config.get("repo_name") != "ssl-proxy"
        or config.get("production_branch") != "main"
    ):
        raise ValueError("Pages project must track zlovtnik/ssl-proxy on main")
    if not config.get("production_deployments_enabled", config.get("deployments_enabled", False)):
        raise ValueError("Pages production Git deployments are disabled")

    includes = list(config.get("path_includes") or [])
    missing = []
    for path in (PROJECT_SUBMODULES[name], ".gitmodules"):
        if any(fnmatch.fnmatchcase(path, pattern) for pattern in config.get("path_excludes") or []):
            raise ValueError(f"Pages path exclusions block {path}; review those exclusions first")
        if not any(fnmatch.fnmatchcase(path, pattern) for pattern in includes):
            missing.append(path)
    if not missing:
        return {}

    # Retain the existing source settings, including branch and preview policies.
    updated = copy.deepcopy(source)
    updated["config"]["path_includes"] = includes + missing
    return {"source": updated}


def cloudflare_token() -> str:
    token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
    if token:
        return token
    config_home = os.environ.get("XDG_CONFIG_HOME")
    if not config_home:
        config_home = str(Path.home() / ("Library/Preferences" if sys.platform == "darwin" else ".config"))
    path = Path(config_home) / ".wrangler/config/default.toml"
    if path.exists():
        auth = tomllib.loads(path.read_text(encoding="utf-8"))
        token = auth.get("oauth_token") or auth.get("api_token") or ""
    if not token:
        raise ValueError("Set CLOUDFLARE_API_TOKEN or log in with wrangler")
    return token


def api_request(url: str, token: str, patch: dict | None = None) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(patch).encode() if patch is not None else None,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="PATCH" if patch is not None else "GET",
    )
    ca_file = os.environ.get("SSL_CERT_FILE")
    if not ca_file and Path("/etc/ssl/cert.pem").exists():
        ca_file = "/etc/ssl/cert.pem"
    context = ssl.create_default_context(cafile=ca_file)
    with urllib.request.urlopen(request, timeout=20, context=context) as response:
        result = json.load(response)
    if not result.get("success"):
        raise ValueError("Cloudflare rejected the Pages settings request")
    return result["result"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", choices=PROJECT_SUBMODULES, default="ssl-proxy-migrator")
    parser.add_argument("--account-id", default=os.environ.get("CLOUDFLARE_ACCOUNT_ID", ""))
    parser.add_argument("--apply", action="store_true", help="apply only the displayed watch-path correction")
    args = parser.parse_args()
    try:
        account = args.account_id
        cache = ROOT / ".wrangler/cache/pages.json"
        if not account and cache.exists():
            account = json.loads(cache.read_text(encoding="utf-8"))["account_id"]
        if not account or len(account) != 32 or any(char not in "0123456789abcdef" for char in account):
            raise ValueError("Set CLOUDFLARE_ACCOUNT_ID to the existing Pages account ID")
        token = cloudflare_token()
        url = f"https://api.cloudflare.com/client/v4/accounts/{account}/pages/projects/{args.project}"
        patch = watch_paths_patch(api_request(url, token), args.project)
        if not patch:
            print(f"{args.project}: UI submodule and .gitmodules are watched")
            return 0
        print(json.dumps(patch, indent=2))
        if not args.apply:
            print("Watch-path correction required; rerun with --apply when ready.")
            return 1
        if watch_paths_patch(api_request(url, token, patch), args.project):
            raise ValueError("Cloudflare did not retain the watch-path correction")
        print(f"{args.project}: watch paths corrected. Rebuild the latest main deployment in Pages.")
        return 0
    except (ValueError, KeyError, OSError) as error:
        print(f"Pages watch paths: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
