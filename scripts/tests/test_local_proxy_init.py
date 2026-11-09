"""Exercise local VPN initialization in disposable, network-isolated containers."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
IMAGE = os.environ.get("LOCAL_PROXY_TEST_IMAGE", "ssl-proxy-local-proxy:dev")


@unittest.skipUnless(
    os.environ.get("LOCAL_DOCKER_TESTS") == "1",
    "set LOCAL_DOCKER_TESTS=1 with the local proxy image built to run Docker tests",
)
class LocalProxyInitTests(unittest.TestCase):
    def run_init(self, corefile=None, stubs=None, relay=True):
        temporary_root = "/private/tmp" if Path("/private/tmp").is_dir() else None
        with tempfile.TemporaryDirectory(prefix="local-proxy-init-", dir=temporary_root) as directory:
            fixture = Path(directory)
            (fixture / "Corefile").write_text(
                corefile if corefile is not None else (ROOT / "config/coredns/Corefile").read_text()
            )
            (fixture / "server.conf").write_bytes((ROOT / "config/templates/server.conf").read_bytes())
            binaries = fixture / "bin"
            binaries.mkdir()
            commands = {"getent": "#!/bin/sh\nprintf '192.0.2.10 STREAM host.docker.internal\\n'\n"}
            commands.update(stubs or {})
            for name, source in commands.items():
                (binaries / name).write_text(source)

            # Copy executable stubs onto the container filesystem: host mounts
            # can be noexec on Docker Desktop. No live configuration is mounted.
            harness = """
set -eu
mkdir /tmp/test-bin
cp /bootstrap/bin/* /tmp/test-bin/
chmod 755 /tmp/test-bin/*
export PATH="/tmp/test-bin:$PATH"
if bash /init-proxy.sh; then result=0; else result=$?; fi
if [ -e /run/local-secrets/admin_api_key ]; then
    echo ADMIN_DEST=present
    printf 'ADMIN_MODE=%s\\n' "$(stat -c %a /run/local-secrets/admin_api_key)"
    printf 'ADMIN_BYTES=%s\\n' "$(wc -c < /run/local-secrets/admin_api_key)"
else
    echo ADMIN_DEST=absent
fi
if [ -f /config/coredns/Corefile ]; then
    grep -F 'forward .' /config/coredns/Corefile || true
fi
exit "$result"
"""
            return subprocess.run(
                [
                    "docker", "run", "--rm", "--network", "none", "--user", "0:0",
                    "--cap-add", "NET_ADMIN", "--tmpfs", "/config",
                    "--tmpfs", "/run/local-secrets", "--mount",
                    f"type=bind,src={fixture},dst=/bootstrap,readonly", "--mount",
                    f"type=bind,src={ROOT / 'docker/local/init-proxy.sh'},dst=/init-proxy.sh,readonly",
                    "--env", f"LOCAL_MAC_EGRESS_ENABLED={'true' if relay else 'false'}",
                    "--env", "LOCAL_MAC_DNS_PORT=1853", "--env", "LOCAL_VPN_ENDPOINT=127.0.0.1",
                    "--env", "LOCAL_VPN_PORT=51820", "--entrypoint", "/bin/bash", IMAGE,
                    "-c", harness,
                ],
                capture_output=True,
                text=True,
                timeout=45,
            )

    def test_valid_upstream_is_replaced_with_configured_relay(self):
        result = self.run_init()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("    forward . tls://192.0.2.10:1853 {", result.stdout)
        self.assertNotIn("tls://1.1.1.1", result.stdout)

    def test_failed_host_lookup_reports_error_and_stops_initialization(self):
        for output in ("", "printf '192.0.2.10 STREAM host.docker.internal\\n'\n"):
            with self.subTest(partial_output=bool(output)):
                result = self.run_init(stubs={"getent": f"#!/bin/sh\n{output}exit 2\n"})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Failed to resolve an IPv4 address for host.docker.internal", result.stderr)
                self.assertNotIn("forward .", result.stdout)
                self.assertIn("ADMIN_DEST=absent", result.stdout)

    def test_empty_host_lookup_reports_error_and_stops_initialization(self):
        result = self.run_init(stubs={"getent": "#!/bin/sh\nexit 0\n"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Failed to resolve an IPv4 address for host.docker.internal", result.stderr)
        self.assertNotIn("forward .", result.stdout)
        self.assertIn("ADMIN_DEST=absent", result.stdout)

    def test_generated_admin_key_has_restrictive_permissions(self):
        result = self.run_init(relay=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ADMIN_MODE=600", result.stdout)
        self.assertIn("ADMIN_BYTES=65", result.stdout)

    def test_missing_expected_upstream_fails_before_generating_keys(self):
        result = self.run_init(corefile=". {\n    forward . 8.8.8.8\n}\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(result.stderr.strip(), "failure must be reported to stderr")
        self.assertIn("ADMIN_DEST=absent", result.stdout)

    def test_lookalike_addresses_do_not_match_literal_upstreams(self):
        corefile = (ROOT / "config/coredns/Corefile").read_text().replace(
            "tls://1.1.1.1 tls://1.0.0.1", "tls://1x1x1x1 tls://1y0y0y1"
        )
        result = self.run_init(corefile=corefile)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(result.stderr.strip(), "failure must be reported to stderr")
        self.assertIn("ADMIN_DEST=absent", result.stdout)

    def test_unchanged_generated_corefile_fails_before_generating_keys(self):
        result = self.run_init(stubs={"sed": "#!/bin/sh\ncat /bootstrap/Corefile\n"})
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(result.stderr.strip(), "failure must be reported to stderr")
        self.assertIn("ADMIN_DEST=absent", result.stdout)

    def test_failed_admin_key_generation_does_not_publish_partial_key(self):
        result = self.run_init(
            relay=False,
            stubs={"openssl": "#!/bin/sh\nprintf 'partial-key'\nexit 1\n"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ADMIN_DEST=absent", result.stdout)


if __name__ == "__main__":
    unittest.main()
