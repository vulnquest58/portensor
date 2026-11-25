#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_PATH = ROOT / "docs" / "p4-closure-evidence.json"
CHECKLIST_PATH = ROOT / "docs" / "p4-closure-checklist.md"
READINESS_PATH = ROOT / "docs" / "p4-release-readiness.md"
LOCAL_CHECK_PATH = ROOT / "bench" / "p4" / "p4-local-check.txt"
SUMS_PATH = ROOT / "dist" / "SHA256SUMS"
DIST_DIR = ROOT / "dist"
WORKFLOW_DIR = ROOT / ".github" / "workflows"
RELEASE_WORKFLOW = WORKFLOW_DIR / "release.yml"
CI_WORKFLOW = WORKFLOW_DIR / "ci.yml"
RUNNER_DOC = ROOT / "docs" / "release-runners.md"
TOOLCHAIN_PATH = ROOT / "rust-toolchain.toml"
ACTIONLINT_CONFIG = ROOT / ".github" / "actionlint.yaml"


REQUIRED_IDS = [f"P4-{number}" for number in range(1, 7)]
ALLOWED_STATUSES = {"local-ready", "external-pending", "blocked", "closed"}
LINK_CHECK_DOCS = [
    ROOT / "docs" / "p4-closure-checklist.md",
    ROOT / "docs" / "p4-release-readiness.md",
    ROOT / "docs" / "compatibility-policy.md",
    ROOT / "docs" / "decisions" / "0005-release-signing-and-provenance.md",
    ROOT / "docs" / "release-process.md",
    ROOT / "docs" / "security" / "production-signing-policy.md",
    ROOT / "docs" / "security" / "key-custody-procedure.md",
    ROOT / "docs" / "security" / "release-signature-verification.md",
    ROOT / "docs" / "security" / "p4-1-evidence-register.md",
    ROOT / "docs" / "security" / "p4-1-evidence-submission.md",
    ROOT / "docs" / "security" / "p4-1-clean-host-verification.md",
    ROOT / "docs" / "security" / "p4-1-acceptance-report.md",
    ROOT / "docs" / "distribution" / "registry-ownership.md",
    ROOT / "docs" / "distribution" / "package-maintenance-policy.md",
    ROOT / "docs" / "distribution" / "clean-install-verification.md",
    ROOT / "docs" / "distribution" / "p4-2-external-evidence-intake.md",
    ROOT / "packaging" / "README.md",
    ROOT / "docs" / "release-runners.md",
    ROOT / "docs" / "sbom.md",
    ROOT / "docs" / "p4-external-evidence-owners.md",
    ROOT / "docs" / "p4-external-blockers.md",
    ROOT / "docs" / "p4-signoff-readiness.md",
    ROOT / "docs" / "development-roadmap.md",
    ROOT / "SECURITY.md",
]
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
KEY_SUFFIXES = {".key", ".pem", ".p12", ".pfx", ".jks"}
PRIVATE_KEY_RE = re.compile(r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY")
ACTION_REF_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)(?:\s*#\s*(.*))?$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
LATEST_RUNNER_RE = re.compile(r"runs-on:\s*[^\n]*-latest\b")
RUNNER_LABELS = ("ubuntu-24.04", "windows-2022")


class Audit:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.notes: list[str] = []

    def error(self, message: str) -> None:
        self.errors.append(message)

    def warning(self, message: str) -> None:
        self.warnings.append(message)

    def note(self, message: str) -> None:
        self.notes.append(message)


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def read_text(path: Path, audit: Audit) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        audit.error(f"cannot read {display_path(path)}: {error}")
        return ""


def load_json(path: Path, audit: Audit) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        audit.error(f"cannot parse {display_path(path)}: {error}")
        return {}
    if not isinstance(value, dict):
        audit.error(f"{display_path(path)} root must be an object")
        return {}
    return value


def relative_path(value: str, audit: Audit, context: str) -> Path | None:
    if not isinstance(value, str) or not value:
        audit.error(f"{context}: path must be a non-empty string")
        return None
    path = Path(value)
    if path.is_absolute():
        audit.error(f"{context}: path must be relative: {value}")
        return None
    resolved = (ROOT / path).resolve()
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        audit.error(f"{context}: path escapes repository: {value}")
        return None
    return resolved


def check_schema(data: dict, audit: Audit) -> list[dict]:
    expected = {
        "schema": int,
        "phase": str,
        "as_of": str,
        "overall_status": str,
        "approved": bool,
        "checklist": str,
        "requirements": list,
        "supporting_validation": list,
        "final_closure_criteria": list,
        "approvals": dict,
    }
    for key, kind in expected.items():
        if key not in data:
            audit.error(f"evidence JSON missing top-level key: {key}")
        elif not isinstance(data[key], kind):
            audit.error(f"evidence JSON {key} must be {kind.__name__}")
    if data.get("schema") != 1:
        audit.error("evidence JSON schema must be 1")
    if data.get("phase") != "P4":
        audit.error("evidence JSON phase must be P4")
    if data.get("checklist") != "docs/p4-closure-checklist.md":
        audit.error("evidence JSON checklist path is not canonical")
    if data.get("overall_status") not in {"not_closed", "closed"}:
        audit.error("evidence JSON overall_status must be not_closed or closed")
    if data.get("reviewed_by") is not None or data.get("reviewed_at") is not None:
        audit.warning("evidence JSON has reviewer fields populated; verify sign-off evidence")

    requirements = data.get("requirements")
    if not isinstance(requirements, list):
        return []
    ids = [item.get("id") for item in requirements if isinstance(item, dict)]
    if ids != REQUIRED_IDS:
        audit.error(f"requirement IDs must be exactly {REQUIRED_IDS}; found {ids}")
    seen_paths: set[str] = set()
    repeated_paths: set[str] = set()
    for index, item in enumerate(requirements):
        if not isinstance(item, dict):
            audit.error(f"requirement {index} must be an object")
            continue
        context = str(item.get("id", f"requirement {index}"))
        for key, kind in {
            "id": str,
            "title": str,
            "status": str,
            "blocking": bool,
            "acceptance_criteria": list,
            "evidence": list,
            "remaining_evidence": list,
        }.items():
            if key not in item:
                audit.error(f"{context}: missing {key}")
            elif not isinstance(item[key], kind):
                audit.error(f"{context}: {key} must be {kind.__name__}")
        status = item.get("status")
        if status not in ALLOWED_STATUSES:
            audit.error(f"{context}: unknown status {status!r}")
        acceptance = item.get("acceptance_criteria")
        if not acceptance:
            audit.error(f"{context}: acceptance_criteria must not be empty")
        remaining = item.get("remaining_evidence")
        if status == "closed":
            if remaining:
                audit.error(f"{context}: closed requirement still has remaining evidence")
        elif not remaining:
            audit.error(f"{context}: open requirement must list remaining evidence")
        for evidence in item.get("evidence", []):
            if not isinstance(evidence, dict):
                audit.error(f"{context}: evidence entry must be an object")
                continue
            for key in ("path", "kind", "status"):
                if not isinstance(evidence.get(key), str) or not evidence.get(key):
                    audit.error(f"{context}: evidence {key} must be a non-empty string")
            path = relative_path(evidence.get("path", ""), audit, context)
            if path is None:
                continue
            if not path.is_file():
                audit.error(f"{context}: evidence file does not exist: {evidence['path']}")
            if evidence["path"] in seen_paths and evidence["path"] not in repeated_paths:
                audit.note(f"evidence path repeated across requirements: {evidence['path']}")
                repeated_paths.add(evidence["path"])
            seen_paths.add(evidence["path"])
    for index, item in enumerate(data.get("supporting_validation", [])):
        if not isinstance(item, dict):
            audit.error(f"supporting_validation {index} must be an object")
            continue
        for evidence_path in item.get("evidence", []):
            path = relative_path(evidence_path, audit, f"supporting_validation {index}")
            if path is not None and not path.is_file():
                audit.error(f"supporting_validation {index}: evidence file does not exist: {evidence_path}")
    return requirements


def check_checklist(data: dict, audit: Audit, requirements: list[dict]) -> None:
    text = read_text(CHECKLIST_PATH, audit)
    if not text:
        return
    rows: dict[str, tuple[str, str]] = {}
    for line in text.splitlines():
        if not line.lstrip().startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 6 or not re.fullmatch(r"P4-\d+", cells[0]):
            continue
        status = cells[-1].strip("` ")
        rows[cells[0]] = (cells[1], status)
    if sorted(rows) != REQUIRED_IDS:
        audit.error(f"checklist requirement IDs do not match: {sorted(rows)}")
    for item in requirements:
        requirement_id = item.get("id")
        if requirement_id not in rows:
            continue
        title, status = rows[requirement_id]
        if status != item.get("status"):
            audit.error(
                f"{requirement_id}: checklist status {status!r} != JSON status {item.get('status')!r}"
            )
        if title.strip().lower() != str(item.get("title", "")).strip().lower():
            audit.error(f"{requirement_id}: checklist title differs from JSON title")
    status_match = re.search(r"^Status:\s+\*\*(.+?)\*\*", text, re.MULTILINE)
    if status_match is None:
        audit.error("checklist is missing a Status line")
    elif data.get("overall_status") == "not_closed" and "not closed" not in status_match.group(1).lower():
        audit.error("checklist status does not say not closed")
    elif data.get("overall_status") == "closed":
        status_text = status_match.group(1).lower()
        if "not closed" in status_text or "closed" not in status_text:
            audit.error("checklist status does not say closed")
    if data.get("approved") is False and re.search(
        r"^\|\s*P4 reviewer\s*\|\s*[^|\s][^|]*\|", text, re.MULTILINE
    ):
        audit.error("checklist has a P4 reviewer but evidence JSON is not approved")

    readiness = read_text(READINESS_PATH, audit)
    if readiness and "not complete" not in readiness[:500].lower():
        audit.error("P4 readiness header does not say not complete")


def check_links(audit: Audit) -> None:
    for doc in LINK_CHECK_DOCS:
        if not doc.is_file():
            audit.error(f"link-check document missing: {doc.relative_to(ROOT)}")
            continue
        text = read_text(doc, audit)
        for raw_target in LINK_RE.findall(text):
            target = unquote(raw_target.strip().strip("<>")).split("#", 1)[0]
            if not target or target.startswith(("http://", "https://", "mailto:", "tel:", "file:")):
                continue
            if target.startswith("#"):
                continue
            resolved = (doc.parent / target).resolve()
            try:
                resolved.relative_to(ROOT.resolve())
            except ValueError:
                audit.error(f"{doc.relative_to(ROOT)}: link escapes repository: {raw_target}")
                continue
            if not resolved.exists():
                audit.error(f"{doc.relative_to(ROOT)}: broken link: {raw_target}")


def validate_sbom(path: Path, audit: Audit, label: str) -> dict | None:
    if not path.is_file():
        audit.error(f"{label} is missing: {display_path(path)}")
        return None
    sbom = load_json(path, audit)
    if sbom.get("bomFormat") != "CycloneDX":
        audit.error(f"{label} bomFormat must be CycloneDX")
    if sbom.get("specVersion") not in {"1.5", "1.6", "1.7"}:
        audit.error(f"{label} has an unsupported specVersion")
    components = sbom.get("components")
    if not isinstance(components, list) or len(components) < 100:
        audit.error(f"{label} has fewer than 100 components")
    else:
        audit.note(f"{label} components: {len(components)}")
    return sbom


def check_checksum_manifest(sums_path: Path, dist_dir: Path, sbom_path: Path, audit: Audit) -> None:
    if not sums_path.is_file():
        audit.error(f"{display_path(sums_path)} is missing")
        return
    listed: dict[str, str] = {}
    for line in read_text(sums_path, audit).splitlines():
        parts = line.split()
        if len(parts) != 2:
            if line.strip():
                audit.error(f"invalid SHA256SUMS line: {line}")
            continue
        digest, name = parts
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            audit.error(f"invalid SHA256SUMS digest for {name}")
        if name in listed:
            audit.error(f"duplicate SHA256SUMS entry: {name}")
        listed[name] = digest
        artifact = dist_dir / name
        if not artifact.is_file():
            audit.error(f"SHA256SUMS references missing artifact: {name}")
            continue
        actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
        if actual != digest:
            audit.error(f"SHA256SUMS digest mismatch: {name}")

    expected = sbom_path.name
    if not sbom_path.is_file():
        audit.error(f"SBOM artifact is missing: {display_path(sbom_path)}")
    if expected not in listed:
        audit.error(f"SHA256SUMS must include the SBOM: {expected}")
    elif sbom_path.is_file():
        actual = hashlib.sha256(sbom_path.read_bytes()).hexdigest()
        if actual != listed[expected]:
            audit.error(f"SHA256SUMS digest mismatch: {expected}")


def check_action_references(text: str, source: str, audit: Audit) -> None:
    for number, line in enumerate(text.splitlines(), start=1):
        match = ACTION_REF_RE.match(line)
        if match is None:
            continue
        reference = match.group(1)
        if reference.startswith(("docker://", "./")):
            continue
        if "@" not in reference:
            audit.error(f"{source}:{number}: action reference has no revision: {reference}")
            continue
        action, revision = reference.rsplit("@", 1)
        if SHA_RE.fullmatch(revision) is None:
            audit.error(
                f"{source}:{number}: {action} is not pinned to a full commit SHA ({revision})"
            )
        comment = (match.group(2) or "").strip()
        if not comment:
            audit.error(f"{source}:{number}: pinned action {action} is missing a version comment")
        elif re.match(r"(?:v\d|master\b|main\b|release\b)", comment) is None:
            audit.error(
                f"{source}:{number}: pinned action {action} has an unrecognized version comment"
            )


def check_workflow_action_pins(workflow_dir: Path, audit: Audit) -> None:
    for path in sorted(workflow_dir.glob("*.yml")) + sorted(workflow_dir.glob("*.yaml")):
        text = read_text(path, audit)
        check_action_references(text, display_path(path), audit)


def check_runner_documentation(release_text: str, doc_path: Path, audit: Audit) -> None:
    if not doc_path.is_file():
        audit.error(f"release runner documentation is missing: {display_path(doc_path)}")
        return
    doc = read_text(doc_path, audit)
    if LATEST_RUNNER_RE.search(release_text):
        audit.error("release workflow uses a floating runner label; use a versioned label")
    for label in RUNNER_LABELS:
        if label not in release_text:
            audit.error(f"release workflow is missing runner label: {label}")
        if label not in doc:
            audit.error(f"release runner documentation is missing label: {label}")
    if "mutable" not in doc.lower():
        audit.error("release runner documentation must describe image mutability")
    if "ImageVersion" not in doc:
        audit.error("release runner documentation must record the resolved ImageVersion limitation")


def check_local_evidence(audit: Audit, requirements: list[dict]) -> None:
    fields: dict[str, str] = {}
    if not LOCAL_CHECK_PATH.is_file():
        audit.error("local P4 evidence file is missing")
    else:
        for line in read_text(LOCAL_CHECK_PATH, audit).splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                fields[key.strip()] = value.strip()
        for key in (
            "gpg_fingerprint",
            "gpg_signature",
            "cosign_signature",
            "sbom",
            "checksum_manifest",
            "scope",
        ):
            if not fields.get(key):
                audit.error(f"local P4 evidence missing field: {key}")
        if fields.get("scope") != "p4 local tooling validation only":
            audit.error("local P4 evidence scope must be local tooling validation only")
        if fields.get("checksum_manifest") != "archives+sbom":
            audit.error("local P4 evidence must record checksum_manifest=archives+sbom")
        for key in (
            "external_key_custody",
            "registry_ownership",
            "clean_runner_execution",
            "ot_assessment_approval",
        ):
            if fields.get(key) != "not verified":
                audit.error(f"local P4 evidence must record {key}=not verified")

    version = "0.7.0"
    sbom_path = ROOT / "bench" / "p4" / f"rayscan-{version}.cdx.json"
    dist_sbom = DIST_DIR / f"rayscan-{version}.cdx.json"
    sbom = validate_sbom(sbom_path, audit, "CycloneDX SBOM")
    if sbom is not None:
        metadata_version = (
            sbom.get("metadata", {}).get("component", {}).get("version")
            if isinstance(sbom.get("metadata"), dict)
            else None
        )
        if metadata_version and metadata_version != version:
            audit.warning(f"SBOM metadata version is {metadata_version}, expected {version}")
        if dist_sbom.is_file() and sbom_path.read_bytes() != dist_sbom.read_bytes():
            audit.error("dist SBOM does not match the evidence SBOM")

    check_checksum_manifest(SUMS_PATH, DIST_DIR, dist_sbom, audit)

    sbom_evidence = None
    for item in requirements:
        if item.get("id") == "P4-4":
            for evidence in item.get("evidence", []):
                if evidence.get("kind") == "sbom":
                    sbom_evidence = evidence
    if sbom_evidence is None:
        audit.error("P4-4 has no SBOM evidence entry")
    elif sbom is not None:
        status = sbom_evidence.get("status", "")
        match = re.search(r"(\d+)-components", status)
        actual = len(sbom.get("components") or [])
        if match and actual != int(match.group(1)):
            audit.error("SBOM component count does not match evidence metadata")


def check_workflows(audit: Audit) -> None:
    release = read_text(RELEASE_WORKFLOW, audit)
    ci = read_text(CI_WORKFLOW, audit)
    toolchain = read_text(TOOLCHAIN_PATH, audit)
    release_tokens = [
        "GPG_PRIVATE_KEY",
        "COSIGN_PRIVATE_KEY",
        "gpg --verify",
        "cosign verify-blob",
        "cargo cyclonedx",
        "Validate CycloneDX SBOM",
        "actions/attest-build-provenance@",
        "actions/attest-sbom@",
        "id-token: write",
        "attestations: write",
        "sha256sum ./*.tar.gz ./*.zip ./*.cdx.json",
        "sha256sum -c SHA256SUMS",
        "grep -Fq \"  portensor-${version}.cdx.json\" SHA256SUMS",
        "rust-toolchain@",
    ]
    ci_tokens = [
        "actionlint",
        "cargo fmt --all -- --check",
        "cargo clippy --all-targets --all-features -- -D warnings",
        "cargo test --all-targets --all-features",
        "cargo build --release --locked",
        "cargo audit",
        "cargo-deny-action",
    ]
    for token in release_tokens:
        if token not in release:
            audit.error(f"release workflow missing required token: {token}")
    for token in ci_tokens:
        if token not in ci:
            audit.error(f"CI workflow missing required token: {token}")
    if "1.99.1" not in toolchain:
        audit.error("rust-toolchain.toml does not pin Rust 1.99.1")
    if "1.99.1" not in release or "1.99.1" not in ci:
        audit.error("workflows do not record the pinned Rust 1.99.1 toolchain")
    if LATEST_RUNNER_RE.search(ci):
        audit.error("CI workflow uses a floating runner label; use a versioned label")
    check_runner_documentation(release, RUNNER_DOC, audit)
    check_workflow_action_pins(WORKFLOW_DIR, audit)
    if ACTIONLINT_CONFIG.is_file():
        audit.note("actionlint custom-runner config present")
    else:
        audit.error(".github/actionlint.yaml is missing")

    for current, dirs, files in os.walk(ROOT):
        dirs[:] = [name for name in dirs if name not in {".git", "target", "dist"}]
        for name in files:
            path = Path(current) / name
            relative = path.relative_to(ROOT)
            if relative.parts[:2] == ("tests", "fixtures"):
                continue
            if path.suffix.lower() in KEY_SUFFIXES:
                audit.error(f"private-key-like file found in repository: {relative}")
    for directory in (ROOT / ".github", ROOT / "scripts", ROOT / "docs"):
        if not directory.exists():
            continue
        for current, dirs, files in os.walk(directory):
            dirs[:] = [name for name in dirs if name not in {".git", "target"}]
            for name in files:
                path = Path(current) / name
                if path.suffix.lower() in {".yml", ".yaml", ".sh", ".md", ".toml"}:
                    if PRIVATE_KEY_RE.search(path.read_text(errors="ignore")):
                        audit.error(f"private-key marker found in {path.relative_to(ROOT)}")


def check_closure(data: dict, requirements: list[dict], audit: Audit) -> None:
    statuses = {item.get("id"): item.get("status") for item in requirements}
    closed = [requirement_id for requirement_id in REQUIRED_IDS if statuses.get(requirement_id) == "closed"]
    all_closed = len(closed) == len(REQUIRED_IDS)
    approved = data.get("approved") is True
    overall_status = data.get("overall_status")
    if overall_status == "not_closed" and all_closed:
        audit.error("all requirements are closed but overall_status is not_closed")
    if overall_status == "closed" and not all_closed:
        audit.error("overall_status is closed but not all requirements are closed")
    if all_closed and not approved:
        audit.error("all requirements are closed but P4 is not approved; record sign-off")
    if approved:
        if not all_closed:
            audit.error("P4 is approved while requirements remain open")
        if overall_status != "closed":
            audit.error("P4 is approved but overall_status is not closed")
        if not data.get("reviewed_by") or not data.get("reviewed_at"):
            audit.error("P4 is approved without reviewer identity and date")
        approvals = data.get("approvals")
        if not isinstance(approvals, dict) or not approvals or any(value is None for value in approvals.values()):
            audit.error("P4 is approved without complete approval records")
    open_requirements = [requirement_id for requirement_id in REQUIRED_IDS if statuses.get(requirement_id) != "closed"]
    if open_requirements:
        audit.note(f"open requirements: {', '.join(open_requirements)}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate the P4 closure evidence package.")
    parser.add_argument("--require-closed", action="store_true", help="Fail unless all six requirements are closed.")
    parser.add_argument("--json", action="store_true", help="Emit a machine-readable result.")
    args = parser.parse_args()

    audit = Audit()
    data = load_json(EVIDENCE_PATH, audit) if EVIDENCE_PATH.is_file() else {}
    if not data:
        audit.error("P4 closure evidence JSON is missing or invalid")
    requirements = check_schema(data, audit) if data else []
    requirements = [item for item in requirements if isinstance(item, dict)]
    check_checklist(data, audit, requirements)
    check_links(audit)
    check_local_evidence(audit, requirements)
    check_workflows(audit)
    check_closure(data, requirements, audit)

    if args.require_closed:
        statuses = {item.get("id"): item.get("status") for item in requirements}
        if any(statuses.get(requirement_id) != "closed" for requirement_id in REQUIRED_IDS):
            audit.error("--require-closed requested but P4 is not closed")

    result = {
        "status": "closed" if not audit.errors and all(item.get("status") == "closed" for item in requirements) else "not_closed",
        "errors": audit.errors,
        "warnings": audit.warnings,
        "notes": audit.notes,
    }
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("P4 evidence audit")
        print(f"errors: {len(audit.errors)}")
        for message in audit.errors:
            print(f"  ERROR: {message}")
        print(f"warnings: {len(audit.warnings)}")
        for message in audit.warnings:
            print(f"  WARN: {message}")
        print(f"notes: {len(audit.notes)}")
        for message in audit.notes:
            print(f"  NOTE: {message}")
        print(f"P4 status: {result['status'].upper()}")
    return 1 if audit.errors else 0


if __name__ == "__main__":
    sys.exit(main())
