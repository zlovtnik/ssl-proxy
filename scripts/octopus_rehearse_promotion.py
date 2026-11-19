"""Rehearse the coordinator digest change and Git revert in a disposable checkout."""

import argparse
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import yaml

from image_contract import KustomizationLoader, update_image_digest, validate_digest


ROOT = Path(__file__).resolve().parents[1]
PROD = Path("cyber-stack/matrix/prod")
SERVICE = "java-coordinator"


def render(root):
    return subprocess.check_output([
        "kustomize", "build", "--load-restrictor", "LoadRestrictionsNone",
        root / PROD / "app-stack",
    ])


def deployment(documents):
    (result,) = (doc for doc in documents if doc["kind"] == "Deployment"
                 and doc["metadata"]["name"] == "ssl-proxy-java-coordinator")
    return result


def rehearse(root, digest, print_patch):
    def git(*args):
        return subprocess.check_output([
            "git", "-c", "user.name=G4 rehearsal", "-c", "user.email=g4@localhost",
            "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", *args,
        ], cwd=root)

    shutil.copytree(ROOT / "cyber-stack", root / "cyber-stack")
    git("init", "--quiet")
    git("add", "cyber-stack")
    git("commit", "-qm", "Production baseline")
    baseline = render(root)
    expected = list(yaml.load_all(baseline, Loader=KustomizationLoader))
    spec = deployment(expected)["spec"]
    template = spec["template"]
    if (spec["replicas"] != 1 or spec["strategy"] != {"type": "Recreate"}
        or template["metadata"]["annotations"]["ssl-proxy.io/processor-profile"] != "broker-drain"):
        raise ValueError("expected singleton Recreate deployment using broker-drain")
    (container,) = (c for c in template["spec"]["containers"] if c["name"] == SERVICE)
    previous = container["image"]
    repository, previous_digest = previous.rsplit("@", 1)
    validate_digest(previous_digest)
    if digest == previous_digest:
        raise ValueError("candidate digest matches production")
    container["image"] = f"{repository}@{digest}"
    (jvm,) = (e for e in container["env"] if e["name"] == "JAVA_TOOL_OPTIONS")
    container["env"].remove(jvm)

    update_image_digest(root / PROD / "app-stack/kustomization.yaml", SERVICE, digest)
    # A strategic merge deletion also removes the value inherited from the base.
    patch = root / PROD / "patches/java-coordinator.yaml"
    content = patch.read_text()
    original = '            - name: JAVA_TOOL_OPTIONS\n              value: "' + jvm["value"] + '"'
    if content.count(original) != 1:
        raise ValueError("production JVM patch changed; review the cutover edit")
    patch.write_text(content.replace(original, "            - name: JAVA_TOOL_OPTIONS\n              $patch: delete"))
    git("commit", "-qam", "Rehearse native coordinator cutover")
    candidate = list(yaml.load_all(render(root), Loader=KustomizationLoader))
    if candidate != expected:
        raise ValueError("promotion changed the render beyond the coordinator image and JVM option")
    diff = git("diff", "HEAD^", "HEAD")
    git("revert", "--no-edit", "HEAD")
    if render(root) != baseline or git("diff", "HEAD~2", "HEAD"):
        raise ValueError("Git revert did not restore the production baseline")
    if print_patch:
        print(diff.decode(), end="")
    print(f"Verified app-stack render and Git revert. Rollback image {previous}", file=sys.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--fixture", action="store_true", help="exercise the manifest change with a synthetic digest")
    mode.add_argument("--digest", type=validate_digest, help="emit a review patch for the verified candidate digest")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="octopus-g4-") as directory:
        rehearse(Path(directory), args.digest or "sha256:" + "0" * 64, bool(args.digest))
