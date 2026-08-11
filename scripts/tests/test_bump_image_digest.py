from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPOSITORY_ROOT / "scripts" / "bump-image-digest.sh"
DIGEST = "sha256:" + "a" * 64


class BumpImageDigestTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.log = self.root / "kustomize.log"
        (self.root / "scripts").mkdir()
        shutil.copy2(SCRIPT, self.root / "scripts" / SCRIPT.name)
        for environment in ("dev", "prod"):
            for slice_name in ("app-stack", "data-plane"):
                overlay = self.root / "cyber-stack" / "matrix" / environment / slice_name
                overlay.mkdir(parents=True)
                image = "tidb-runtime-schema" if slice_name == "data-plane" else "ssl-proxy"
                (overlay / "kustomization.yaml").write_text(
                    "apiVersion: kustomize.config.k8s.io/v1beta1\n"
                    "kind: Kustomization\n"
                    "images:\n"
                    f"  - name: {image}\n"
                    f"    newName: registry/{image}\n"
                    "    digest: sha256:" + "b" * 64 + "\n",
                    encoding="utf-8",
                )
            aggregate = self.root / "cyber-stack" / "matrix" / environment
            (aggregate / "kustomization.yaml").write_text(
                "apiVersion: kustomize.config.k8s.io/v1beta1\n"
                "kind: Kustomization\n"
                "images:\n"
                "  - name: ssl-proxy\n"
                "    newName: registry/ssl-proxy\n"
                "    digest: sha256:" + "b" * 64 + "\n"
                "  - name: tidb-runtime-schema\n"
                "    newName: registry/tidb-runtime-schema\n"
                "    digest: sha256:" + "b" * 64 + "\n",
                encoding="utf-8",
            )
        self.kustomize = self.root / "fake-kustomize"
        self.kustomize.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            "printf '%s\\n' \"$*\" >> \"$KUSTOMIZE_LOG\"\n"
            "if [ \"$1\" = edit ]; then\n"
            "  assignment=$4\n"
            "  service=${assignment%%=*}\n"
            "  reference=${assignment#*=}\n"
            "  digest=${reference##*@}\n"
            "  awk -v service=\"$service\" -v digest=\"$digest\" '\n"
            "    $1 == \"-\" && $2 == \"name:\" { active = ($3 == service) }\n"
            "    active && $1 == \"digest:\" { sub(/sha256:[0-9a-f]+/, digest) }\n"
            "    { print }\n"
            "  ' kustomization.yaml > kustomization.yaml.tmp\n"
            "  mv kustomization.yaml.tmp kustomization.yaml\n"
            "fi\n",
            encoding="utf-8",
        )
        self.kustomize.chmod(0o755)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def run_helper(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ | {
            "SSL_PROXY_REPOSITORY_ROOT": str(self.root),
            "KUSTOMIZE": str(self.kustomize),
            "KUSTOMIZE_LOG": str(self.log),
        }
        return subprocess.run(
            [str(self.root / "scripts" / SCRIPT.name), *arguments],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=environment,
        )

    def test_updates_only_the_owning_app_stack_overlay_and_renders_it(self) -> None:
        result = self.run_helper("ssl-proxy", "dev", DIGEST)

        self.assertEqual(0, result.returncode, result.stderr)
        changed = (self.root / "cyber-stack/matrix/dev/app-stack/kustomization.yaml").read_text()
        aggregate = (self.root / "cyber-stack/matrix/dev/kustomization.yaml").read_text()
        untouched = (self.root / "cyber-stack/matrix/dev/data-plane/kustomization.yaml").read_text()
        self.assertIn(f"digest: {DIGEST}", changed)
        self.assertIn(f"digest: {DIGEST}", aggregate)
        self.assertIn("digest: sha256:" + "b" * 64, untouched)
        self.assertIn("edit set image ssl-proxy=registry/ssl-proxy@" + DIGEST, self.log.read_text())
        self.assertIn("build --load-restrictor LoadRestrictionsNone", self.log.read_text())

    def test_maps_schema_image_to_data_plane(self) -> None:
        result = self.run_helper("tidb-runtime-schema", "prod", DIGEST)

        self.assertEqual(0, result.returncode, result.stderr)
        data_plane = self.root / "cyber-stack/matrix/prod/data-plane/kustomization.yaml"
        app_stack = self.root / "cyber-stack/matrix/prod/app-stack/kustomization.yaml"
        aggregate = self.root / "cyber-stack/matrix/prod/kustomization.yaml"
        self.assertIn(f"digest: {DIGEST}", data_plane.read_text())
        self.assertIn(f"digest: {DIGEST}", aggregate.read_text())
        self.assertIn("digest: sha256:" + "b" * 64, app_stack.read_text())

    def test_rejects_invalid_arguments_without_editing(self) -> None:
        for arguments in (
            ("wg-key-rotator", "dev", DIGEST),
            ("unknown", "dev", DIGEST),
            ("ssl-proxy", "stage", DIGEST),
            ("ssl-proxy", "dev", "sha256:" + "A" * 64),
        ):
            with self.subTest(arguments=arguments):
                result = self.run_helper(*arguments)
                self.assertNotEqual(0, result.returncode)

        self.assertFalse(self.log.exists())

    def test_rejects_missing_or_misrouted_image_mapping(self) -> None:
        kustomization = self.root / "cyber-stack/matrix/dev/app-stack/kustomization.yaml"
        kustomization.write_text(kustomization.read_text().replace("ssl-proxy", "other", 1))

        result = self.run_helper("ssl-proxy", "dev", DIGEST)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("exactly one image mapping", result.stderr)
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
