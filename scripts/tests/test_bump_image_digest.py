from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPOSITORY_ROOT / "scripts" / "bump-image-digest.sh"
IMAGE_CONTRACT = REPOSITORY_ROOT / "scripts" / "image_contract.py"
DIGEST = "sha256:" + "a" * 64
DEV_DIGEST = "sha256:" + "b" * 64
PROD_DIGEST = "sha256:" + "c" * 64


class BumpImageDigestTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.log = self.root / "kustomize.log"
        self.octopus_contract_log = self.root / "octopus-contract.log"
        (self.root / "scripts").mkdir()
        shutil.copy2(SCRIPT, self.root / "scripts" / SCRIPT.name)
        shutil.copy2(IMAGE_CONTRACT, self.root / "scripts" / IMAGE_CONTRACT.name)
        for environment in ("dev", "prod"):
            for slice_name in ("app-stack", "data-plane"):
                overlay = self.root / "cyber-stack" / "matrix" / environment / slice_name
                overlay.mkdir(parents=True)
                image = "tidb-runtime-schema" if slice_name == "data-plane" else "ssl-proxy"
                java_mapping = (
                    "  - name: java-coordinator\n"
                    "    newName: registry/java-coordinator\n"
                    f"    digest: {DEV_DIGEST if environment == 'dev' else PROD_DIGEST}\n"
                    if slice_name == "app-stack"
                    else ""
                )
                (overlay / "kustomization.yaml").write_text(
                    "apiVersion: kustomize.config.k8s.io/v1beta1\n"
                    "kind: Kustomization\n"
                    "images:\n"
                    f"  - name: {image}\n"
                    f"    newName: registry/{image}\n"
                    "    digest: sha256:" + "b" * 64 + "\n"
                    + java_mapping,
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
                "    digest: sha256:" + "b" * 64 + "\n"
                "  - name: java-coordinator\n"
                "    newName: registry/java-coordinator\n"
                f"    digest: {DEV_DIGEST if environment == 'dev' else PROD_DIGEST}\n",
                encoding="utf-8",
            )
        dev_record = self.root / "cyber-stack/matrix/dev/app-stack/java-coordinator-promotion.json"
        dev_record.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "service": "java-coordinator",
                    "image": {
                        "repository": "registry/java-coordinator",
                        "digest": DEV_DIGEST,
                    },
                    "source": {
                        "parentCommit": "1" * 40,
                        "octopusCommit": "2" * 40,
                    },
                }
            )
            + "\n",
            encoding="utf-8",
        )
        self.octopus_contract = self.root / "scripts/octopus_image_contract.py"
        self.octopus_contract.write_text(
            """import json
import os
import sys
from pathlib import Path

with Path(os.environ["OCTOPUS_CONTRACT_LOG"]).open("a", encoding="utf-8") as log:
    log.write(" ".join(sys.argv[1:]) + "\\n")
if sys.argv[1] == "record":
    output = Path(sys.argv[2])
    repository = sys.argv[sys.argv.index("--repository") + 1]
    digest = sys.argv[sys.argv.index("--digest") + 1]
    output.write_text(json.dumps({
        "schemaVersion": 1,
        "service": "java-coordinator",
        "image": {"repository": repository, "digest": digest},
        "source": {"parentCommit": "1" * 40, "octopusCommit": "2" * 40},
    }, sort_keys=True) + "\\n", encoding="utf-8")
""",
            encoding="utf-8",
        )
        self.kustomize = self.root / "fake-kustomize"
        self.kustomize.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            "printf '%s\\n' \"$*\" >> \"$KUSTOMIZE_LOG\"\n"
            "if [ \"${KUSTOMIZE_FAIL_DIRECTORY:-}\" = \"$PWD\" ]; then exit 9; fi\n"
            "if [ \"$1\" = edit ]; then\n"
            "  assignment=$4\n"
            "  service=${assignment%%=*}\n"
            "  reference=${assignment#*=}\n"
            "  digest=${reference##*@}\n"
            "  python3 - \"$service\" \"$digest\" <<'PY'\n"
            "import sys\n"
            "from pathlib import Path\n"
            "import yaml\n"
            "path = Path('kustomization.yaml')\n"
            "document = yaml.safe_load(path.read_text(encoding='utf-8'))\n"
            "for image in document['images']:\n"
            "    if image['name'] == sys.argv[1]:\n"
            "        image['digest'] = sys.argv[2]\n"
            "path.write_text(yaml.safe_dump(document, sort_keys=False), encoding='utf-8')\n"
            "PY\n"
            "fi\n",
            encoding="utf-8",
        )
        self.kustomize.chmod(0o755)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def run_helper(
        self, *arguments: str, extra_environment: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ | {
            "SSL_PROXY_REPOSITORY_ROOT": str(self.root),
            "KUSTOMIZE": str(self.kustomize),
            "KUSTOMIZE_LOG": str(self.log),
            "OCTOPUS_CONTRACT_LOG": str(self.octopus_contract_log),
        }
        environment.update(extra_environment or {})
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

    def test_accepts_kustomize_reordered_image_mapping_keys(self) -> None:
        for relative in (
            "cyber-stack/matrix/prod/app-stack/kustomization.yaml",
            "cyber-stack/matrix/prod/kustomization.yaml",
        ):
            path = self.root / relative
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "  - name: ssl-proxy\n"
                    "    newName: registry/ssl-proxy\n"
                    "    digest: sha256:" + "b" * 64 + "\n",
                    "  - digest: sha256:" + "b" * 64 + "\n"
                    "    name: ssl-proxy\n"
                    "    newName: registry/ssl-proxy\n",
                ),
                encoding="utf-8",
            )

        result = self.run_helper("ssl-proxy", "prod", DIGEST)

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn(
            f"digest: {DIGEST}",
            (self.root / "cyber-stack/matrix/prod/app-stack/kustomization.yaml").read_text(),
        )
        self.assertIn(
            f"digest: {DIGEST}",
            (self.root / "cyber-stack/matrix/prod/kustomization.yaml").read_text(),
        )

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

    def test_rolls_back_both_files_when_second_update_fails(self) -> None:
        owner = self.root / "cyber-stack/matrix/prod/app-stack/kustomization.yaml"
        aggregate = self.root / "cyber-stack/matrix/prod/kustomization.yaml"
        owner_before = owner.read_text(encoding="utf-8")
        aggregate_before = aggregate.read_text(encoding="utf-8")

        result = self.run_helper(
            "ssl-proxy",
            "prod",
            DIGEST,
            extra_environment={"KUSTOMIZE_FAIL_DIRECTORY": str(aggregate.parent)},
        )

        self.assertNotEqual(0, result.returncode)
        self.assertEqual(owner_before, owner.read_text(encoding="utf-8"))
        self.assertEqual(aggregate_before, aggregate.read_text(encoding="utf-8"))

    def test_rejects_kubectl_as_an_editor(self) -> None:
        result = self.run_helper(
            "ssl-proxy",
            "prod",
            DIGEST,
            extra_environment={"KUSTOMIZE": "kubectl"},
        )

        self.assertEqual(2, result.returncode)
        self.assertIn("standalone kustomize CLI", result.stderr)
        self.assertFalse(self.log.exists())

    def test_dev_java_promotion_requires_and_records_exact_inspected_candidate(self) -> None:
        candidate = f"registry/java-coordinator@{DIGEST}"
        result = self.run_helper(
            "java-coordinator",
            "dev",
            DIGEST,
            extra_environment={"JAVA_COORDINATOR_IMAGE": candidate},
        )

        self.assertEqual(0, result.returncode, result.stderr)
        app_stack = self.root / "cyber-stack/matrix/dev/app-stack/kustomization.yaml"
        aggregate = self.root / "cyber-stack/matrix/dev/kustomization.yaml"
        self.assertIn(f"digest: {DIGEST}", app_stack.read_text(encoding="utf-8"))
        self.assertIn(f"digest: {DIGEST}", aggregate.read_text(encoding="utf-8"))
        record = json.loads(
            (
                self.root
                / "cyber-stack/matrix/dev/app-stack/java-coordinator-promotion.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(DIGEST, record["image"]["digest"])
        contract_log = self.octopus_contract_log.read_text(encoding="utf-8")
        self.assertIn(f"image {candidate} --expected-digest {DIGEST}", contract_log)
        self.assertIn("record", contract_log)

    def test_java_promotion_rejects_missing_or_mismatched_candidate_before_edit(self) -> None:
        for candidate in (None, f"registry/other@{DIGEST}"):
            with self.subTest(candidate=candidate):
                environment = (
                    {}
                    if candidate is None
                    else {"JAVA_COORDINATOR_IMAGE": candidate}
                )
                result = self.run_helper(
                    "java-coordinator", "dev", DIGEST, extra_environment=environment
                )
                self.assertNotEqual(0, result.returncode)
        self.assertFalse(self.log.exists())

    def test_prod_java_promotion_must_match_dev_pin_and_uses_dev_provenance(self) -> None:
        wrong = self.run_helper(
            "java-coordinator",
            "prod",
            DIGEST,
            extra_environment={
                "JAVA_COORDINATOR_IMAGE": f"registry/java-coordinator@{DIGEST}"
            },
        )
        self.assertNotEqual(0, wrong.returncode)
        self.assertIn("must exactly match the tested dev pin", wrong.stderr)
        self.assertFalse(self.log.exists())

        candidate = f"registry/java-coordinator@{DEV_DIGEST}"
        accepted = self.run_helper(
            "java-coordinator",
            "prod",
            DEV_DIGEST,
            extra_environment={"JAVA_COORDINATOR_IMAGE": candidate},
        )
        self.assertEqual(0, accepted.returncode, accepted.stderr)
        prod_stack = self.root / "cyber-stack/matrix/prod/app-stack/kustomization.yaml"
        self.assertIn(f"digest: {DEV_DIGEST}", prod_stack.read_text(encoding="utf-8"))
        prod_record = self.root / "cyber-stack/matrix/prod/app-stack/java-coordinator-promotion.json"
        dev_record = self.root / "cyber-stack/matrix/dev/app-stack/java-coordinator-promotion.json"
        self.assertEqual(
            dev_record.read_text(encoding="utf-8"),
            prod_record.read_text(encoding="utf-8"),
        )
        contract_log = self.octopus_contract_log.read_text(encoding="utf-8")
        self.assertIn("--promotion-record", contract_log)

    def test_java_promotion_rolls_back_pin_and_provenance_together(self) -> None:
        owner = self.root / "cyber-stack/matrix/dev/app-stack/kustomization.yaml"
        aggregate = self.root / "cyber-stack/matrix/dev/kustomization.yaml"
        record = self.root / "cyber-stack/matrix/dev/app-stack/java-coordinator-promotion.json"
        owner_before = owner.read_text(encoding="utf-8")
        aggregate_before = aggregate.read_text(encoding="utf-8")
        record_before = record.read_text(encoding="utf-8")

        result = self.run_helper(
            "java-coordinator",
            "dev",
            DIGEST,
            extra_environment={
                "JAVA_COORDINATOR_IMAGE": f"registry/java-coordinator@{DIGEST}",
                "KUSTOMIZE_FAIL_DIRECTORY": str(aggregate.parent),
            },
        )

        self.assertNotEqual(0, result.returncode)
        self.assertEqual(owner_before, owner.read_text(encoding="utf-8"))
        self.assertEqual(aggregate_before, aggregate.read_text(encoding="utf-8"))
        self.assertEqual(record_before, record.read_text(encoding="utf-8"))

    def test_make_java_target_passes_the_exact_candidate_to_the_gate(self) -> None:
        candidate = f"registry/java-coordinator@{DIGEST}"
        result = subprocess.run(
            [
                "make",
                "-n",
                "bump-digest-java-coordinator",
                "ENV=prod",
                f"DIGEST={DIGEST}",
                f"IMAGE={candidate}",
            ],
            cwd=REPOSITORY_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn(f'JAVA_COORDINATOR_IMAGE="{candidate}"', result.stdout)
        self.assertIn("./scripts/bump-image-digest.sh java-coordinator", result.stdout)


if __name__ == "__main__":
    unittest.main()
