"""Check release subjects in successful `gh attestation verify --format json` output.

This release-only helper consumes verified statements on stdin, never raw bundles.
GitHub CLI is responsible for signatures, transparency proofs, and certificate policy.
"""

import hashlib
import json
from pathlib import Path
import sys


def verify_subjects(results, names):
    """Require one verified SLSA statement covering exactly the expected files."""
    if not isinstance(results, list) or len(results) != 1:
        raise ValueError("expected exactly one verified attestation")
    statement = results[0]["verificationResult"]["statement"]
    if statement["_type"] != "https://in-toto.io/Statement/v1":
        raise ValueError("expected an in-toto v1 statement")
    if statement["predicateType"] != "https://slsa.dev/provenance/v1":
        raise ValueError("expected SLSA v1 provenance")
    expected = []
    for name in names:
        path = Path(name)
        if path.is_symlink() or not path.is_file():
            raise ValueError("missing or invalid provenance subject file")
        with path.open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        expected.append({"name": name, "digest": {"sha256": digest}})
    subjects = statement["subject"]
    if not isinstance(subjects, list) or sorted(subjects, key=lambda s: s["name"]) != sorted(
        expected, key=lambda s: s["name"]
    ):
        raise ValueError("provenance subjects do not match the release files")


if __name__ == "__main__":
    try:
        verify_subjects(json.load(sys.stdin), sys.argv[1:])
    except (KeyError, TypeError, ValueError, OSError) as error:
        sys.exit(f"release: invalid verified provenance: {error}")
