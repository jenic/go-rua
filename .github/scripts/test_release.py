"""Offline release orchestration tests; Sigstore/GitHub calls are simulated."""

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("release.sh").resolve()
# Archive names are project configuration; keep them in the release script only.
ARCHIVES = shlex.split(re.search(r"(?ms)^archives=\((.*?)^\)", SCRIPT.read_text())[1], comments=True)
ASSETS = [*ARCHIVES, "SHA256SUMS"]
SIGNED_ASSETS = [*ASSETS, "provenance.sigstore.json", *(f"{name}.sigstore.json" for name in ASSETS)]
REPOSITORY = "example/project"
MODULE_PATH = "go-rua"

# These fakes exercise control flow and argument handling, not cryptography.
FAKE_TOOL = r'''#!/usr/bin/env python3
import hashlib, json, os, pathlib, shutil, sys
p = pathlib.Path
args = sys.argv[1:]
root = p(os.environ["FIXTURE"])
tool = p(sys.argv[0]).name
with (root / "calls").open("a") as log:
    log.write(json.dumps([tool, *args]) + "\n")
def option(name):
    return args[args.index(name) + 1]
def digest(path):
    return hashlib.sha256(p(path).read_bytes()).hexdigest()
state = root / "state"
remote = root / "remote"
if tool == "cosign":
    blob = args[-1]
    bundle = p(option("--bundle"))
    identity = (os.environ["GITHUB_SERVER_URL"] + "/" + os.environ["GITHUB_REPOSITORY"]
                + "/.github/workflows/release.yml@refs/tags/" + os.environ["RELEASE_TAG"])
    issuer = "https://token.actions.githubusercontent.com"
    if args[0] == "sign-blob":
        assert "--yes" in args and option("--oidc-provider") == "github-actions"
        if os.getenv("FAIL_SIGN"): sys.exit(1)
        bundle.write_text(json.dumps([digest(blob), identity, issuer]))
    elif args[0] == "verify-blob":
        wanted = [digest(blob), option("--certificate-identity"), option("--certificate-oidc-issuer")]
        if os.getenv("FAIL_VERIFY") or json.loads(bundle.read_text()) != wanted: sys.exit(1)
    else: sys.exit(1)
elif args[:2] == ["attestation", "verify"]:
    assert "--deny-self-hosted-runners" in args and option("--format") == "json"
    data = json.loads(p(option("--bundle")).read_text())
    wanted = {
        "repo": option("--repo"), "identity": option("--cert-identity"),
        "issuer": option("--cert-oidc-issuer"), "ref": option("--source-ref"),
        "sha": option("--source-digest"),
    }
    if any(data[key] != value for key, value in wanted.items()) or not data["hosted"]:
        sys.exit(1)
    statement = data["statement"]
    if statement["predicateType"] != option("--predicate-type"): sys.exit(1)
    if not any(s["digest"].get("sha256") == digest(args[2]) for s in statement["subject"]):
        sys.exit(1)
    print(os.getenv("PROVENANCE_OUTPUT", json.dumps([{"verificationResult": {"statement": statement}}])))
    # Emit valid output even on failure, to exercise the caller's pipefail handling.
    if os.getenv("FAIL_PROVENANCE") or (os.getenv("FAIL_PROVENANCE_AFTER_DOWNLOAD") and (root / "downloaded").exists()):
        sys.exit(1)
elif args[0] == "api":
    if os.getenv("FAIL_API"): sys.exit(1)
    if "--paginate" in args:
        if state.exists(): print("true" if state.read_text() == "draft" else "false")
    elif "/git/ref/tags/" in args[1] or "/git/tags/" in args[1]:
        sha = os.environ["GITHUB_SHA"]
        if os.getenv("WRONG_SHA") or (os.getenv("MOVE_TAG_AFTER_DOWNLOAD") and (root / "downloaded").exists()):
            sha = "b" * 40
        if os.getenv("ANNOTATED") and "/git/ref/" in args[1]: print("tag\t" + "c" * 40)
        else: print("commit\t" + sha)
    else: sys.exit(1)
elif args[:2] == ["release", "create"]:
    assert "--verify-tag" in args and "--draft" in args and "--generate-notes" in args
    state.write_text("draft")
elif args[:2] == ["release", "upload"]:
    assert state.read_text() == "draft"
    remote.mkdir(exist_ok=True)
    for asset in args[3:]:
        if asset.startswith("--"): continue
        shutil.copyfile(asset, remote / asset)
        if os.getenv("FAIL_UPLOAD"): sys.exit(1)
elif args[:2] == ["release", "download"]:
    target = p(option("--dir"))
    shutil.copytree(remote, target, dirs_exist_ok=True)
    if os.getenv("TAMPER_DOWNLOAD"): (target / "SHA256SUMS.sigstore.json").write_text("[]")
    if os.getenv("TAMPER_PROVENANCE_DOWNLOAD"): (target / "provenance.sigstore.json").write_text("{}")
    if os.getenv("REENCODE_PROVENANCE_DOWNLOAD"):
        bundle = target / "provenance.sigstore.json"
        bundle.write_text(bundle.read_text() + "\n")
    (root / "downloaded").touch()
elif args[:2] == ["release", "edit"]:
    assert "--draft=false" in args and state.read_text() == "draft"
    assert sorted(asset.name for asset in remote.iterdir()) == sorted(json.loads(os.environ["RELEASE_ASSETS"]))
    state.write_text("published")
else: sys.exit(1)
'''


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "go.mod").write_text(f"module {MODULE_PATH}\n")
        self.dist = self.root / "dist"
        self.dist.mkdir()
        for name in ARCHIVES:
            (self.dist / name).write_bytes(name.encode())
        self.write_checksums()
        tools = self.root / "tools"
        tools.mkdir()
        for name in ["gh", "cosign"]:
            path = tools / name
            path.write_text(FAKE_TOOL)
            path.chmod(0o755)
        self.env = dict(os.environ, PATH=f"{tools}:{os.environ['PATH']}", FIXTURE=str(self.root),
                        RELEASE_TAG="v1.2.3", GITHUB_SHA="a" * 40,
                        GITHUB_REPOSITORY=REPOSITORY, GITHUB_SERVER_URL="https://github.com",
                        RELEASE_ASSETS=json.dumps(SIGNED_ASSETS))
        self.write_provenance()

    def write_checksums(self):
        (self.dist / "SHA256SUMS").write_text("".join(
            f"{hashlib.sha256((self.dist / name).read_bytes()).hexdigest()}  {name}\n"
            for name in ARCHIVES))

    def write_provenance(self):
        # This fake bundle is understood only by FAKE_TOOL; it is not a Sigstore bundle.
        data = {
            "repo": self.env["GITHUB_REPOSITORY"],
            "identity": (self.env["GITHUB_SERVER_URL"] + "/" + self.env["GITHUB_REPOSITORY"]
                         + "/.github/workflows/release.yml@refs/tags/" + self.env["RELEASE_TAG"]),
            "issuer": "https://token.actions.githubusercontent.com",
            "ref": "refs/tags/" + self.env["RELEASE_TAG"],
            "sha": self.env["GITHUB_SHA"], "hosted": True,
            "statement": {
                "_type": "https://in-toto.io/Statement/v1",
                "predicateType": "https://slsa.dev/provenance/v1",
                "subject": [{"name": name, "digest": {
                    "sha256": hashlib.sha256((self.dist / name).read_bytes()).hexdigest()
                }} for name in ASSETS],
            },
        }
        (self.dist / "provenance.sigstore.json").write_text(json.dumps(data))

    def run_release(self, command, success=True, **env):
        result = subprocess.run(["bash", str(SCRIPT), command, str(self.dist)],
                                cwd=self.root, env=dict(self.env, **env), text=True, capture_output=True)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result

    def calls(self):
        path = self.root / "calls"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_semver_and_prerelease_detection(self):
        for tag, prerelease in [("v0.0.0", False), ("v1.2.3-rc.1", True),
                                ("v1.2.3-0", True), ("v1.2.3", False)]:
            with self.subTest(tag=tag):
                output = self.run_release("metadata", RELEASE_TAG=tag).stdout
                self.assertIn(f"tag={tag}\n", output)
                self.assertIn(f"prerelease={str(prerelease).lower()}\n", output)
        for tag in ["1.2.3", "v1", "v01.2.3", "v1.2.3-01", "v1.2.3-", "v1.2.3+", "v1.2.3\n",
                    "v1.2.3;echo bad", "v1.2.3+build-with-hyphen", "v1.2.3-0+build", "v1.2.3+incompatible"]:
            with self.subTest(tag=tag):
                self.run_release("metadata", success=False, RELEASE_TAG=tag)
        self.assertEqual(self.calls(), [])

    def test_metadata_needs_no_go_module_publication(self):
        (self.root / "go.mod").unlink()
        self.run_release("metadata", RELEASE_TAG="v2.0.0")
        self.assertEqual(self.calls(), [])

    def test_asset_set_and_checksums(self):
        (self.dist / "provenance.sigstore.json").unlink()
        self.run_release("check-assets")
        for name in [ARCHIVES[0], "SHA256SUMS"]:
            path = self.dist / name
            original = path.read_bytes()
            path.write_bytes(b"tampered")
            self.run_release("check-assets", success=False)
            path.write_bytes(original)
        extra = self.dist / "unexpected"
        extra.touch()
        self.run_release("check-assets", success=False)
        extra.unlink()
        archive = self.dist / ARCHIVES[0]
        archive.unlink()
        self.run_release("check-assets", success=False)
        archive.symlink_to(self.dist / "SHA256SUMS")
        self.run_release("check-assets", success=False)

    def test_signs_every_file_and_checks_annotated_tag(self):
        self.run_release("sign", ANNOTATED="1")
        self.assertEqual(len(list(self.dist.iterdir())), len(SIGNED_ASSETS))
        self.assertEqual(sum(c[:3] == ["gh", "attestation", "verify"] for c in self.calls()), len(ASSETS))
        self.assertEqual(sum(c[:2] == ["cosign", "sign-blob"] for c in self.calls()), len(ASSETS))
        self.assertEqual(sum(c[:2] == ["cosign", "verify-blob"] for c in self.calls()), len(ASSETS))

    def test_signing_stops_on_tag_or_sigstore_failure(self):
        for failure in ["WRONG_SHA", "FAIL_API", "FAIL_SIGN", "FAIL_VERIFY"]:
            with self.subTest(failure=failure):
                for bundle in self.dist.glob("*.sigstore.json"):
                    bundle.unlink()
                self.write_provenance()
                self.run_release("sign", success=False, **{failure: "1"})
        self.assertFalse((self.root / "state").exists())

    def test_publish_stable_and_refuse_published_release(self):
        self.run_release("sign")
        self.run_release("publish")
        self.assertEqual((self.root / "state").read_text(), "published")
        self.assertEqual(len(list((self.root / "remote").iterdir())), len(SIGNED_ASSETS))
        self.assertEqual(sum(c[:3] == ["gh", "attestation", "verify"] for c in self.calls()), 3 * len(ASSETS))
        edit = next(c for c in self.calls() if c[:3] == ["gh", "release", "edit"])
        self.assertIn("--prerelease=false", edit)
        calls_before = len(self.calls())
        self.run_release("publish", success=False)
        self.assertFalse(any(c[:3] == ["gh", "release", "upload"] for c in self.calls()[calls_before:]))

    def test_prerelease_upload_failure_can_resume(self):
        self.env["RELEASE_TAG"] = "v1.2.3-rc.1"
        self.write_provenance()
        self.run_release("sign")
        self.run_release("publish", success=False, FAIL_UPLOAD="1")
        self.assertEqual((self.root / "state").read_text(), "draft")
        self.run_release("publish")
        self.assertEqual((self.root / "state").read_text(), "published")
        creates = [c for c in self.calls() if c[:3] == ["gh", "release", "create"]]
        self.assertEqual(len(creates), 1)
        self.assertIn("--latest=false", creates[0])
        edit = next(c for c in self.calls() if c[:3] == ["gh", "release", "edit"])
        self.assertIn("--prerelease=true", edit)
        self.assertIn("--latest=false", edit)

    def test_wrong_signer_or_issuer_prevents_publication(self):
        self.run_release("sign")
        bundle = self.dist / "SHA256SUMS.sigstore.json"
        original = json.loads(bundle.read_text())
        for field in [1, 2]:
            data = original.copy()
            data[field] = "https://untrusted.example"
            bundle.write_text(json.dumps(data))
            self.run_release("publish", success=False)
        self.assertFalse((self.root / "state").exists())

    def test_changed_archive_with_recomputed_checksums_is_rejected(self):
        self.run_release("sign")
        (self.dist / ARCHIVES[0]).write_bytes(b"changed after signing")
        self.write_checksums()
        self.run_release("publish", success=False)
        self.assertFalse((self.root / "state").exists())

    def test_download_verification_and_tag_movement_prevent_publication(self):
        self.run_release("sign")
        for failure in ["TAMPER_DOWNLOAD", "MOVE_TAG_AFTER_DOWNLOAD", "TAMPER_PROVENANCE_DOWNLOAD",
                        "FAIL_PROVENANCE_AFTER_DOWNLOAD", "REENCODE_PROVENANCE_DOWNLOAD"]:
            with self.subTest(failure=failure):
                (self.root / "downloaded").unlink(missing_ok=True)
                calls_before = len(self.calls())
                self.run_release("publish", success=False, **{failure: "1"})
                self.assertEqual((self.root / "state").read_text(), "draft")
                self.assertTrue(any(c[:3] == ["gh", "release", "download"]
                                    for c in self.calls()[calls_before:]))
        self.assertFalse(any(c[:3] == ["gh", "release", "edit"] for c in self.calls()))

    def test_provenance_asset_modes(self):
        self.run_release("check-assets", success=False)
        result = subprocess.run(["bash", str(SCRIPT), "check-assets", str(self.dist), "attested"],
                                cwd=self.root, env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.run_release("verify-provenance")

    def test_missing_malformed_or_symlinked_provenance_stops_signing(self):
        bundle = self.dist / "provenance.sigstore.json"
        for contents in [None, "", "{", "{}"]:
            with self.subTest(contents=contents):
                bundle.unlink(missing_ok=True)
                if contents is not None:
                    bundle.write_text(contents)
                self.run_release("sign", success=False)
        bundle.unlink()
        bundle.symlink_to(self.dist / "SHA256SUMS")
        self.run_release("sign", success=False)
        self.assertFalse(any(c[:2] == ["cosign", "sign-blob"] for c in self.calls()))

    def test_provenance_certificate_policy_stops_signing_and_publication(self):
        self.run_release("sign")
        bundle = self.dist / "provenance.sigstore.json"
        original = json.loads(bundle.read_text())
        failures = [("repo", "other/repository"), ("identity", "https://untrusted.example"),
                    ("issuer", "https://untrusted.example"), ("ref", "refs/heads/main"),
                    ("sha", "b" * 40), ("hosted", False)]
        for field, value in failures:
            with self.subTest(field=field):
                changed = dict(original, **{field: value})
                bundle.write_text(json.dumps(changed))
                self.run_release("publish", success=False)
        self.assertFalse((self.root / "state").exists())
        # Check the same policy before any blob signing occurs.
        for signature in self.dist.glob("*.sigstore.json"):
            if signature != bundle:
                signature.unlink()
        calls_before = len(self.calls())
        for field, value in failures:
            bundle.write_text(json.dumps(dict(original, **{field: value})))
            self.run_release("sign", success=False)
        self.assertFalse(any(c[:2] == ["cosign", "sign-blob"] for c in self.calls()[calls_before:]))

    def test_wrong_provenance_subjects_and_predicate_are_rejected(self):
        self.run_release("sign")
        bundle = self.dist / "provenance.sigstore.json"
        original = bundle.read_text()
        for mutation in ["missing", "extra", "duplicate", "renamed", "digest", "predicate", "type"]:
            with self.subTest(mutation=mutation):
                data = json.loads(original)
                statement = data["statement"]
                subjects = statement["subject"]
                if mutation == "missing": subjects.pop()
                elif mutation == "extra": subjects.append({"name": "extra", "digest": {"sha256": "0" * 64}})
                elif mutation == "duplicate": subjects.append(subjects[0])
                elif mutation == "renamed": subjects[0]["name"] = "wrong-name.tar.gz"
                elif mutation == "digest": subjects[-1]["digest"]["sha256"] = "0" * 64
                elif mutation == "predicate": statement["predicateType"] = "https://example.org/other"
                elif mutation == "type": statement["_type"] = "https://in-toto.io/Statement/v0.1"
                bundle.write_text(json.dumps(data))
                self.run_release("publish", success=False)
        self.assertFalse((self.root / "state").exists())

    def test_provenance_verifier_failure_or_invalid_output_fails_closed(self):
        self.run_release("sign", success=False, FAIL_PROVENANCE="1")
        self.assertFalse(any(c[:2] == ["cosign", "sign-blob"] for c in self.calls()))
        self.run_release("sign")
        self.run_release("publish", success=False, FAIL_PROVENANCE="1")
        for output in ["", "{", "null", "{}", "[]", "[{}]",
                       '[{"verificationResult": {"statement": null}}]',
                       '[{"verificationResult": {}}, {"verificationResult": {}}]']:
            with self.subTest(output=output):
                self.run_release("publish", success=False, PROVENANCE_OUTPUT=output)
        self.assertFalse((self.root / "state").exists())

    def test_changed_archives_with_updated_checksums_require_new_provenance(self):
        (self.dist / ARCHIVES[0]).write_bytes(b"changed after build")
        self.write_checksums()
        self.run_release("sign", success=False)
        self.assertFalse(any(c[:2] == ["cosign", "sign-blob"] for c in self.calls()))


if __name__ == "__main__":
    unittest.main()
