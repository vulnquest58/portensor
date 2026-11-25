from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "p4_external_evidence_check", ROOT / "scripts" / "p4_external_evidence_check.py"
)
assert SPEC is not None and SPEC.loader is not None
EXTERNAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXTERNAL)

TEMPLATE = ROOT / "docs" / "distribution" / "p4-2-external-evidence.template.json"


def valid_channel(name: str) -> dict[str, object]:
    channel: dict[str, object] = {
        "channel": name,
        "status": "accepted",
        "ownership": {
            "namespace": f"vulnquest58/{name}",
            "owner": "release-owner",
            "maintainer": "release-maintainer",
            "authorization_ref": f"ref://authorization/{name}",
            "two_factor_enabled": True,
            "two_factor_evidence_ref": f"ref://2fa/{name}",
            "recovery_owner_ref": f"ref://recovery/{name}",
            "least_privilege_ref": f"ref://access/{name}",
            "maintainer_responsibility_ref": f"ref://responsibility/{name}",
            "evidence_id": f"{name}-ownership",
            "reviewer": "release-reviewer",
            "reviewed_at": "2026-11-22",
            "decision": "accepted",
        },
        "token_approval": {
            "token_type": "fine-grained-publish",
            "scope": f"publish:{name}",
            "secret_storage_ref": f"ref://secret-store/{name}",
            "approver": "security-owner",
            "approval_ref": f"ref://approval/{name}",
            "rotation_owner": "release-owner",
            "revocation_ref": f"ref://revocation/{name}",
            "approved_at": "2026-11-22",
            "decision": "approved",
        },
        "clean_install": {
            "environment_id": f"clean-{name}-vm",
            "os": "Ubuntu 24.04",
            "architecture": "x86_64",
            "source_ref": f"ref://source/{name}",
            "installed_version": "0.7.0",
            "artifact_sha256": "a" * 64,
            "version_check": "pass",
            "localhost_gate": "pass",
            "transcript_ref": f"ref://transcript/{name}",
            "cleanup": "pass",
            "evidence_id": f"{name}-install",
            "reviewer": "release-reviewer",
            "reviewed_at": "2026-11-22",
            "decision": "accepted",
        },
    }
    if name in EXTERNAL.CONTAINER_CHANNELS:
        channel["container_digest"] = {
            "image_ref": f"ghcr.io/vulnquest58/portensor:{name}",
            "digest": "sha256:" + "b" * 64,
            "source_tag": "v0.7.0",
            "source_commit": "c" * 40,
            "inspect_ref": f"ref://inspect/{name}",
            "compose_file_sha256": "d" * 64,
            "compose_pull_check": "pass",
            "container_localhost_gate": "pass",
            "evidence_id": f"{name}-digest",
            "reviewer": "release-reviewer",
            "reviewed_at": "2026-11-22",
            "decision": "accepted",
        }
    return channel


def valid_packet() -> dict[str, object]:
    return {
        "schema": 1,
        "requirement": "P4-2",
        "packet_id": "P4-2-INTAKE-RELEASE-20261122-1",
        "release_version": "0.7.0",
        "evidence_location": "ref://evidence/p4-2",
        "packet_status": "accepted",
        "reviewer": "release-reviewer",
        "reviewed_at": "2026-11-22",
        "review_decision": "accepted",
        "secrets_included": False,
        "secrets_attested_absent": True,
        "channels": [valid_channel(name) for name in EXTERNAL.REQUIRED_CHANNELS],
    }


class ExternalEvidenceTests(unittest.TestCase):
    def test_template_is_structurally_valid_but_incomplete(self) -> None:
        data = json.loads(TEMPLATE.read_text(encoding="utf-8"))
        report = EXTERNAL.validate_packet(data)
        self.assertEqual([], report.errors)
        self.assertTrue(report.missing)
        self.assertTrue(any("packet.packet_status" in message for message in report.missing))

    def test_complete_packet_is_accepted(self) -> None:
        report = EXTERNAL.validate_packet(valid_packet())
        self.assertEqual([], report.errors)
        self.assertEqual([], report.missing)

    def test_missing_two_factor_evidence_is_incomplete(self) -> None:
        packet = valid_packet()
        packet["channels"][0]["ownership"]["two_factor_enabled"] = False
        report = EXTERNAL.validate_packet(packet)
        self.assertTrue(
            any("two_factor_enabled" in message for message in report.missing),
            report.missing,
        )

    def test_missing_container_digest_is_incomplete(self) -> None:
        packet = valid_packet()
        channels = packet["channels"]
        ghcr = next(item for item in channels if item["channel"] == "ghcr")
        ghcr.pop("container_digest")
        report = EXTERNAL.validate_packet(packet)
        self.assertTrue(
            any("container_digest" in message for message in report.missing),
            report.missing,
        )

    def test_invalid_container_digest_is_an_error(self) -> None:
        packet = valid_packet()
        channels = packet["channels"]
        ghcr = next(item for item in channels if item["channel"] == "ghcr")
        ghcr["container_digest"]["digest"] = "sha256:not-a-digest"
        report = EXTERNAL.validate_packet(packet)
        self.assertTrue(
            any("container_digest.digest" in message for message in report.errors),
            report.errors,
        )

    def test_embedded_secret_material_is_an_error(self) -> None:
        packet = copy.deepcopy(valid_packet())
        packet["channels"][0]["token_approval"]["token_value"] = "do-not-store"
        report = EXTERNAL.validate_packet(packet)
        self.assertTrue(
            any("secret material" in message for message in report.errors),
            report.errors,
        )

    def test_clean_install_version_must_match_release(self) -> None:
        packet = valid_packet()
        packet["channels"][0]["clean_install"]["installed_version"] = "0.6.0"
        report = EXTERNAL.validate_packet(packet)
        self.assertTrue(
            any("must match release_version" in message for message in report.errors),
            report.errors,
        )


if __name__ == "__main__":
    unittest.main()
