from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path

import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from image_contract import FIRST_PARTY_SERVICES, ImageContract  # noqa: E402
from publish_images import (  # noqa: E402
    PublishSettings,
    build_parser,
    make_publish_command,
    publication_report,
    publish_environment,
)


PIN = "sha256:" + "a" * 64
NEW_DIGEST = "sha256:" + "b" * 64


def write_contract(root: Path, environment: str = "prod") -> None:
    matrix = root / "cyber-stack" / "matrix" / environment
    for slice_name, services in (
        ("app-stack", FIRST_PARTY_SERVICES[:-1]),
        ("data-plane", FIRST_PARTY_SERVICES[-1:]),
    ):
        path = matrix / slice_name / "kustomization.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "apiVersion: kustomize.config.k8s.io/v1beta1\n"
            "kind: Kustomization\n"
            "images:\n"
            + "".join(
                f"  - name: {service}\n"
                f"    newName: registry.test:5000/releases/{service}\n"
                f"    digest: {PIN}\n"
                for service in services
            ),
            encoding="utf-8",
        )
    (matrix / "kustomization.yaml").write_text(
        "apiVersion: kustomize.config.k8s.io/v1beta1\n"
        "kind: Kustomization\n"
        "namespace: prod-ssl-proxy\n"
        "images:\n"
        + "".join(
            f"  - name: {service}\n"
            f"    newName: registry.test:5000/releases/{service}\n"
            f"    digest: {PIN}\n"
            for service in FIRST_PARTY_SERVICES
        ),
        encoding="utf-8",
    )


def settings() -> PublishSettings:
    return PublishSettings(
        environment="prod",
        tag="abc1234",
        build_date="2026-08-11T00:00:00Z",
        builder="test-builder",
        platform="linux/amd64",
        registry_plain_http="1",
        atheros_search_ui_api_base="",
        atheros_search_ui_title="search title",
        atheros_search_ui_keycloak_url="https://identity.test",
        atheros_search_ui_keycloak_realm="test-realm",
        atheros_search_ui_keycloak_client_id="search-ui",
        source_revision="c" * 40,
        make_command=("gmake",),
    )


class PublishImagesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        write_contract(self.root)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_command_uses_exact_contract_repository_and_metadata_path(self) -> None:
        contract = ImageContract(
            "ssl-proxy", "app-stack", "registry.test:5000/team/proxy-runtime", PIN
        )
        metadata = self.root / "metadata.json"

        command = make_publish_command(contract, metadata, settings())

        self.assertIn("publish-ssl-proxy", command)
        self.assertIn("REGISTRY=registry.test:5000", command)
        self.assertIn("PUBLISH_REPOSITORY=registry.test:5000/team/proxy-runtime", command)
        self.assertIn(f"PUBLISH_METADATA_FILE={metadata}", command)
        self.assertIn(
            "ATHEROS_SEARCH_UI_KEYCLOAK_URL=https://identity.test", command
        )
        self.assertIn("ATHEROS_SEARCH_UI_KEYCLOAK_REALM=test-realm", command)
        self.assertIn("ATHEROS_SEARCH_UI_KEYCLOAK_CLIENT_ID=search-ui", command)
        self.assertNotIn("registry.test:5000/ssl-proxy", " ".join(command))

    def test_parser_rejects_empty_source_revision(self) -> None:
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit):
            build_parser().parse_args(
                [
                    "--tag",
                    "abc1234",
                    "--build-date",
                    "2026-08-11T00:00:00Z",
                    "--builder",
                    "test-builder",
                    "--platform",
                    "linux/amd64",
                    "--source-revision",
                    "",
                ]
            )

    def test_publishes_eight_images_and_reports_match_and_unpinned(self) -> None:
        commands: list[list[str]] = []
        output: list[str] = []

        def fake_run(command: list[str], _root: Path) -> int:
            commands.append(list(command))
            metadata_argument = next(
                argument for argument in command if argument.startswith("PUBLISH_METADATA_FILE=")
            )
            metadata = Path(metadata_argument.split("=", 1)[1])
            digest = PIN if len(commands) == 1 else NEW_DIGEST
            metadata.write_text(
                json.dumps({"containerimage.digest": digest}), encoding="utf-8"
            )
            return 0

        result = publish_environment(
            self.root,
            settings(),
            run_command=fake_run,
            output=output.append,
        )

        report = "\n".join(output)
        self.assertEqual(0, result)
        self.assertEqual(8, len(commands))
        self.assertFalse(any("wg-key-rotator" in " ".join(command) for command in commands))
        self.assertIn("ssl-proxy: MATCH", report)
        self.assertIn("java-coordinator: UNPINNED", report)
        self.assertIn(
            f"make bump-digest-java-coordinator ENV=prod DIGEST={NEW_DIGEST}", report
        )
        for service, command in zip(FIRST_PARTY_SERVICES, commands, strict=True):
            self.assertIn(
                f"PUBLISH_REPOSITORY=registry.test:5000/releases/{service}", command
            )

    def test_unpinned_is_success_but_publication_failure_is_not(self) -> None:
        report = publication_report(
            ImageContract("ssl-proxy", "app-stack", "registry/team/proxy", PIN),
            NEW_DIGEST,
            "dev",
        )
        self.assertIn("UNPINNED", report)
        self.assertIn(
            f"make bump-digest-ssl-proxy ENV=dev DIGEST={NEW_DIGEST}", report
        )

        result = publish_environment(
            self.root,
            settings(),
            run_command=lambda _command, _root: 7,
            output=lambda _line: None,
        )
        self.assertEqual(7, result)


if __name__ == "__main__":
    unittest.main()
