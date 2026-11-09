"""Exercise local TLS recovery with OpenSSL in an isolated tools container.

Set LOCAL_TLS_TEST_IMAGE to a built docker/local/Dockerfile image to run.
"""

import os
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
IMAGE = os.environ.get("LOCAL_TLS_TEST_IMAGE")
INITIALIZE = "sh /test/init-material.sh >/tmp/initialize.log 2>&1"


@unittest.skipUnless(IMAGE, "set LOCAL_TLS_TEST_IMAGE to run Docker/OpenSSL tests")
class LocalTlsMaterialTests(unittest.TestCase):
    def run_container(self, script):
        result = subprocess.run(
            [
                "docker", "run", "--rm", "--network", "none",
                "--tmpfs", "/local-secrets", "--tmpfs", "/postgres-tls",
                "--tmpfs", "/octopus-secrets",
                "--mount",
                f"type=bind,src={ROOT / 'docker/local/init-material.sh'},dst=/test/init-material.sh,readonly",
                "--entrypoint", "/bin/sh", IMAGE, "-eu", "-c", script,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_fresh_material_has_valid_tls_and_permissions(self):
        self.run_container(INITIALIZE + """
openssl verify -CAfile /postgres-tls/ca.crt -verify_hostname postgres /postgres-tls/server.crt
test "$(stat -c %a /postgres-tls/server.key)" = 600
test "$(stat -c %u /postgres-tls/server.key)" = 999
test "$(stat -c %a /local-secrets/schema_owner.password)" = 440
test "$(stat -c %g /local-secrets/schema_owner.password)" = 999
cmp /local-secrets/octopus_runtime.password /octopus-secrets/octopus_runtime.password
cmp /postgres-tls/ca.crt /octopus-secrets/ca.crt
test "$(find /octopus-secrets -type f | wc -l)" = 2
""")

    def test_valid_material_is_unchanged_on_restart(self):
        self.run_container(INITIALIZE + """
sha256sum /local-secrets/*.password /postgres-tls/ca.key /postgres-tls/ca.crt \
  /postgres-tls/server.key /postgres-tls/server.crt >/tmp/original.sha256
""" + INITIALIZE + """
sha256sum --check --status /tmp/original.sha256
""")

    def test_replacing_ca_repairs_server_certificate_and_key(self):
        self.run_container(INITIALIZE + """
old_certificate=$(sha256sum /postgres-tls/server.crt)
old_key=$(sha256sum /postgres-tls/server.key)
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
  -subj '/CN=replacement local CA' -addext 'basicConstraints=critical,CA:TRUE' \
  -keyout /postgres-tls/ca.key -out /postgres-tls/ca.crt >/tmp/new-ca.log 2>&1
sha256sum /postgres-tls/ca.key /postgres-tls/ca.crt /local-secrets/*.password >/tmp/retained.sha256
""" + INITIALIZE + """
test "$old_certificate" != "$(sha256sum /postgres-tls/server.crt)"
test "$old_key" != "$(sha256sum /postgres-tls/server.key)"
sha256sum --check --status /tmp/retained.sha256
openssl verify -CAfile /postgres-tls/ca.crt -verify_hostname postgres /postgres-tls/server.crt
cmp /postgres-tls/ca.crt /local-secrets/ca.crt
cmp /postgres-tls/ca.crt /octopus-secrets/ca.crt
""")

    def test_wrong_hostname_certificate_is_replaced(self):
        self.run_container(INITIALIZE + """
openssl req -new -newkey rsa:2048 -nodes -subj '/CN=wrong-host' \
  -keyout /postgres-tls/server.key -out /tmp/wrong.csr >/tmp/wrong-csr.log 2>&1
openssl x509 -req -days 1 -in /tmp/wrong.csr -CA /postgres-tls/ca.crt \
  -CAkey /postgres-tls/ca.key -CAcreateserial -out /postgres-tls/server.crt >/tmp/wrong-cert.log 2>&1
openssl verify -CAfile /postgres-tls/ca.crt /postgres-tls/server.crt
""" + INITIALIZE + """
openssl verify -CAfile /postgres-tls/ca.crt -verify_hostname postgres /postgres-tls/server.crt
""")

    def test_incomplete_ca_is_rejected_without_replacement(self):
        for missing in ("ca.key", "ca.crt"):
            with self.subTest(missing=missing):
                self.run_container(INITIALIZE + f"""
rm /postgres-tls/{missing}
sha256sum /postgres-tls/* >/tmp/retained.sha256
if {INITIALIZE}; then
  echo 'incomplete CA was accepted' >&2
  exit 1
fi
grep -q 'incomplete local CA material' /tmp/initialize.log
test ! -e /postgres-tls/{missing}
sha256sum --check --status /tmp/retained.sha256
""")


if __name__ == "__main__":
    unittest.main()
