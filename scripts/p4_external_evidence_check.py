#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PACKET = ROOT / "docs" / "distribution" / "p4-2-external-evidence.template.json"
REQUIRED_CHANNELS = ("homebrew", "scoop", "chocolatey", "aur", "ghcr", "docker-hub")
CONTAINER_CHANNELS = {"ghcr", "docker-hub"}
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
SECRET_KEYS = {
    "api_key",
    "apikey",
    "authorization_header",
    "cookie",
    "password",
    "passwd",
    "private_key",
    "recovery_code",
    "secret",
    "secret_value",
    "session",
    "token_value",
}
PLACEHOLDER_VALUES = {
    "...",
    "blocked",
    "not executed",
    "not provided",
    "not verified",
    "pending",
    "template",
}


class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.missing: list[str] = []

    def error(self, message: str) -> None:
        self.errors.append(message)

    def incomplete(self, message: str) -> None:
        self.missing.append(message)


def is_placeholder(value: object) -> bool:
    if not isinstance(value, str):
        return True
    text = value.strip()
    if not text:
        return True
    lowered = text.lower()
    return (
        lowered in PLACEHOLDER_VALUES
        or (text.startswith("<") and text.endswith(">"))
        or "owner to provide" in lowered
        or "to be provided" in lowered
    )


def field_value(data: object, field: str, context: str, report: Report) -> object | None:
    if not isinstance(data, dict):
        report.error(f"{context} must be an object")
        return None
    if field not in data:
        report.incomplete(f"{context}.{field} is missing")
        return None
    return data[field]


def require_text(data: object, field: str, context: str, report: Report) -> str | None:
    value = field_value(data, field, context, report)
    if value is None:
        return None
    if not isinstance(value, str):
        report.error(f"{context}.{field} must be a string")
        return None
    if is_placeholder(value):
        report.incomplete(f"{context}.{field} is not completed")
        return None
    return value


def require_true(data: object, field: str, context: str, report: Report) -> None:
    value = field_value(data, field, context, report)
    if value is None:
        return
    if not isinstance(value, bool):
        report.error(f"{context}.{field} must be a boolean")
    elif value is not True:
        report.incomplete(f"{context}.{field} must be true")


def require_choice(
    data: object,
    field: str,
    expected: str,
    context: str,
    report: Report,
) -> None:
    value = require_text(data, field, context, report)
    if value is not None and value != expected:
        report.error(f"{context}.{field} must be {expected!r}; found {value!r}")


def require_date(data: object, field: str, context: str, report: Report) -> None:
    value = require_text(data, field, context, report)
    if value is not None and DATE_RE.fullmatch(value) is None:
        report.error(f"{context}.{field} must use YYYY-MM-DD: {value!r}")


def require_pattern(
    data: object,
    field: str,
    pattern: re.Pattern[str],
    description: str,
    context: str,
    report: Report,
) -> None:
    value = require_text(data, field, context, report)
    if value is not None and pattern.fullmatch(value) is None:
        report.error(f"{context}.{field} must be {description}: {value!r}")


def scan_secrets(value: object, context: str, report: Report) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_context = f"{context}.{key}"
            if str(key).lower() in SECRET_KEYS:
                report.error(f"{child_context} records secret material; use a storage reference only")
            scan_secrets(child, child_context, report)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            scan_secrets(child, f"{context}[{index}]", report)


def validate_ownership(channel: dict, context: str, report: Report) -> None:
    ownership = field_value(channel, "ownership", context, report)
    if ownership is None:
        return
    for field in (
        "namespace",
        "owner",
        "maintainer",
        "authorization_ref",
        "two_factor_evidence_ref",
        "recovery_owner_ref",
        "least_privilege_ref",
        "maintainer_responsibility_ref",
        "evidence_id",
        "reviewer",
    ):
        require_text(ownership, field, f"{context}.ownership", report)
    require_true(ownership, "two_factor_enabled", f"{context}.ownership", report)
    require_choice(ownership, "decision", "accepted", f"{context}.ownership", report)
    require_date(ownership, "reviewed_at", f"{context}.ownership", report)


def validate_token(channel: dict, context: str, report: Report) -> None:
    token = field_value(channel, "token_approval", context, report)
    if token is None:
        return
    for field in (
        "token_type",
        "scope",
        "secret_storage_ref",
        "approver",
        "approval_ref",
        "rotation_owner",
        "revocation_ref",
    ):
        require_text(token, field, f"{context}.token_approval", report)
    require_choice(token, "decision", "approved", f"{context}.token_approval", report)
    require_date(token, "approved_at", f"{context}.token_approval", report)


def validate_clean_install(
    channel: dict,
    release_version: str | None,
    context: str,
    report: Report,
) -> None:
    install = field_value(channel, "clean_install", context, report)
    if install is None:
        return
    for field in (
        "environment_id",
        "os",
        "architecture",
        "source_ref",
        "transcript_ref",
        "evidence_id",
        "reviewer",
    ):
        require_text(install, field, f"{context}.clean_install", report)
    installed_version = require_text(
        install, "installed_version", f"{context}.clean_install", report
    )
    if (
        installed_version is not None
        and release_version is not None
        and installed_version != release_version
    ):
        report.error(
            f"{context}.clean_install.installed_version must match release_version "
            f"{release_version!r}; found {installed_version!r}"
        )
    require_pattern(
        install,
        "artifact_sha256",
        SHA256_RE,
        "a lowercase SHA-256 digest",
        f"{context}.clean_install",
        report,
    )
    require_choice(install, "version_check", "pass", f"{context}.clean_install", report)
    require_choice(install, "localhost_gate", "pass", f"{context}.clean_install", report)
    require_choice(install, "cleanup", "pass", f"{context}.clean_install", report)
    require_choice(install, "decision", "accepted", f"{context}.clean_install", report)
    require_date(install, "reviewed_at", f"{context}.clean_install", report)


def validate_container(
    channel: dict,
    channel_name: str,
    context: str,
    report: Report,
) -> None:
    if channel_name not in CONTAINER_CHANNELS:
        return
    container = field_value(channel, "container_digest", context, report)
    if container is None:
        return
    for field in (
        "image_ref",
        "source_tag",
        "inspect_ref",
        "evidence_id",
        "reviewer",
    ):
        require_text(container, field, f"{context}.container_digest", report)
    require_pattern(
        container,
        "digest",
        DIGEST_RE,
        "a sha256: digest with 64 lowercase hex characters",
        f"{context}.container_digest",
        report,
    )
    require_pattern(
        container,
        "source_commit",
        COMMIT_RE,
        "a 40-character lowercase commit SHA",
        f"{context}.container_digest",
        report,
    )
    require_pattern(
        container,
        "compose_file_sha256",
        SHA256_RE,
        "a lowercase SHA-256 digest",
        f"{context}.container_digest",
        report,
    )
    require_choice(
        container,
        "compose_pull_check",
        "pass",
        f"{context}.container_digest",
        report,
    )
    require_choice(
        container,
        "container_localhost_gate",
        "pass",
        f"{context}.container_digest",
        report,
    )
    require_choice(
        container, "decision", "accepted", f"{context}.container_digest", report
    )
    require_date(container, "reviewed_at", f"{context}.container_digest", report)


def validate_packet(data: object) -> Report:
    report = Report()
    scan_secrets(data, "packet", report)
    if not isinstance(data, dict):
        report.error("packet root must be an object")
        return report

    schema = field_value(data, "schema", "packet", report)
    if schema is not None and schema != 1:
        report.error("packet.schema must be 1")
    require_choice(data, "requirement", "P4-2", "packet", report)
    require_text(data, "packet_id", "packet", report)
    release_version = require_text(data, "release_version", "packet", report)
    if release_version is not None and VERSION_RE.fullmatch(release_version) is None:
        report.error(f"packet.release_version is not a semantic version: {release_version!r}")
    require_text(data, "evidence_location", "packet", report)
    require_choice(data, "packet_status", "accepted", "packet", report)
    require_text(data, "reviewer", "packet", report)
    require_date(data, "reviewed_at", "packet", report)
    require_choice(data, "review_decision", "accepted", "packet", report)
    secrets_included = field_value(data, "secrets_included", "packet", report)
    if secrets_included is not None and secrets_included is not False:
        report.error("packet.secrets_included must be false")
    require_true(data, "secrets_attested_absent", "packet", report)

    channels = field_value(data, "channels", "packet", report)
    if not isinstance(channels, list):
        if channels is not None:
            report.error("packet.channels must be a list")
        return report

    seen: set[str] = set()
    for index, channel in enumerate(channels):
        context = f"packet.channels[{index}]"
        if not isinstance(channel, dict):
            report.error(f"{context} must be an object")
            continue
        name = require_text(channel, "channel", context, report)
        if name is None:
            continue
        context = f"channel[{name}]"
        if name not in REQUIRED_CHANNELS:
            report.error(f"{context} is not a required P4-2 channel")
            continue
        if name in seen:
            report.error(f"{context} is duplicated")
            continue
        seen.add(name)
        require_choice(channel, "status", "accepted", context, report)
        validate_ownership(channel, context, report)
        validate_token(channel, context, report)
        validate_clean_install(channel, release_version, context, report)
        validate_container(channel, name, context, report)

    for name in REQUIRED_CHANNELS:
        if name not in seen:
            report.incomplete(f"packet.channels is missing required channel: {name}")
    return report


def load_packet(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a P4-2 external evidence packet.")
    parser.add_argument(
        "--packet",
        type=Path,
        default=DEFAULT_PACKET,
        help="Path to the machine-readable P4-2 evidence packet.",
    )
    parser.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="Exit successfully for an incomplete but structurally valid packet.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print every incomplete field instead of the first 20.",
    )
    parser.add_argument("--json", action="store_true", help="Emit a machine-readable result.")
    args = parser.parse_args()

    try:
        data = load_packet(args.packet)
    except (OSError, json.JSONDecodeError) as error:
        print(f"P4-2 external evidence check: cannot read packet: {error}", file=sys.stderr)
        return 2

    report = validate_packet(data)
    if report.errors:
        status = "invalid"
    elif report.missing:
        status = "incomplete"
    else:
        status = "accepted"
    accepted = status == "accepted"
    exit_code = 0 if accepted or (args.allow_incomplete and not report.errors) else 1

    result = {
        "status": status,
        "packet": str(args.packet),
        "errors": report.errors,
        "missing": report.missing,
    }
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("P4-2 external evidence check")
        print(f"packet: {args.packet}")
        print(f"status: {status}")
        print(f"errors: {len(report.errors)}")
        for message in report.errors:
            print(f"  ERROR: {message}")
        print(f"missing: {len(report.missing)}")
        displayed = report.missing if args.verbose else report.missing[:20]
        for message in displayed:
            print(f"  MISSING: {message}")
        if len(displayed) < len(report.missing):
            print(
                f"  ... {len(report.missing) - len(displayed)} more missing; use --verbose to list all"
            )
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
