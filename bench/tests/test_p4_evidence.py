from __future__ import annotations

import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "p4_evidence_check", ROOT / "scripts" / "p4_evidence_check.py"
)
assert SPEC is not None and SPEC.loader is not None
P4 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P4)


class ChecksumTests(unittest.TestCase):
    def test_missing_sbom_in_manifest_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp)
            archive = dist / "portensor-0.7.0-linux-x86_64.tar.gz"
            archive.write_bytes(b"archive")
            sbom = dist / "portensor-0.7.0.cdx.json"
            sbom.write_bytes(b"sbom")
            sums = dist / "SHA256SUMS"
            sums.write_text(
                f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n",
                encoding="utf-8",
            )
            audit = P4.Audit()
            P4.check_checksum_manifest(sums, dist, sbom, audit)
            self.assertTrue(
                any("must include the SBOM" in message for message in audit.errors),
                audit.errors,
            )

    def test_invalid_sbom_checksum_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp)
            archive = dist / "portensor-0.7.0-linux-x86_64.tar.gz"
            archive.write_bytes(b"archive")
            sbom = dist / "portensor-0.7.0.cdx.json"
            sbom.write_bytes(b"sbom")
            sums = dist / "SHA256SUMS"
            sums.write_text(
                f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n"
                f"{'0' * 64}  {sbom.name}\n",
                encoding="utf-8",
            )
            audit = P4.Audit()
            P4.check_checksum_manifest(sums, dist, sbom, audit)
            self.assertTrue(
                any("digest mismatch" in message for message in audit.errors),
                audit.errors,
            )


class SbomValidationTests(unittest.TestCase):
    def test_invalid_cyclonedx_json_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sbom = Path(tmp) / "portensor-0.7.0.cdx.json"
            sbom.write_text("{not valid json", encoding="utf-8")
            audit = P4.Audit()
            P4.validate_sbom(sbom, audit, "CycloneDX SBOM")
            self.assertTrue(
                any("cannot parse" in message for message in audit.errors),
                audit.errors,
            )


class ActionPinTests(unittest.TestCase):
    def test_floating_action_reference_is_an_error(self) -> None:
        audit = P4.Audit()
        P4.check_action_references(
            "      - uses: actions/checkout@v4\n",
            "ci.yml",
            audit,
        )
        self.assertTrue(
            any("not pinned to a full commit SHA" in message for message in audit.errors),
            audit.errors,
        )

    def test_pinned_action_reference_is_valid(self) -> None:
        audit = P4.Audit()
        P4.check_action_references(
            "      - uses: actions/checkout@"
            "11d5960a326750d5838078e36cf38b85af677262 # v4.4.0\n",
            "ci.yml",
            audit,
        )
        self.assertEqual([], audit.errors)


class RunnerDocumentationTests(unittest.TestCase):
    def test_missing_runner_documentation_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit = P4.Audit()
            P4.check_runner_documentation(
                "    runs-on: ubuntu-24.04\n    runs-on: windows-2022\n",
                Path(tmp) / "missing.md",
                audit,
            )
            self.assertTrue(
                any("runner documentation is missing" in message for message in audit.errors),
                audit.errors,
            )

    def test_documented_versioned_runners_are_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            doc = Path(tmp) / "release-runners.md"
            doc.write_text(
                "ubuntu-24.04 windows-2022 mutable ImageVersion\n",
                encoding="utf-8",
            )
            audit = P4.Audit()
            P4.check_runner_documentation(
                "    runs-on: ubuntu-24.04\n    runs-on: windows-2022\n",
                doc,
                audit,
            )
            self.assertEqual([], audit.errors)


if __name__ == "__main__":
    unittest.main()
