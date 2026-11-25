#!/usr/bin/env python3
"""Generate local package-manager metadata from verified release archives.

This tool does not publish, authenticate, contact registries, or create
production credentials. It renders package definitions for later clean-install
verification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tarfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DIST_DIR = ROOT / "dist"
DEFAULT_OUTPUT_DIR = ROOT / "dist" / "packages"
DEFAULT_TEMPLATE_DIR = ROOT / "packaging" / "templates"
CARGO_TOML = ROOT / "Cargo.toml"

VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
CHECKSUM_RE = re.compile(r"^([0-9a-fA-F]{64}) [ *]([^/\\]+)$")
PLACEHOLDER_RE = re.compile(r"@@([A-Z0-9_]+)@@")
PRIVATE_KEY_RE = re.compile(r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY")

TEMPLATES = {
    "homebrew/portensor.rb": "homebrew/portensor.rb.in",
    "scoop/portensor.json": "scoop/portensor.json.in",
    "chocolatey/portensor.nuspec": "chocolatey/portensor.nuspec.in",
    "chocolatey/tools/chocolateyinstall.ps1": (
        "chocolatey/tools/chocolateyinstall.ps1.in"
    ),
    "aur/PKGBUILD": "aur/PKGBUILD.in",
    "docker/compose.yaml": "docker/compose.yaml.in",
}


class PackagingError(Exception):
    """A package metadata input or template is invalid."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cargo_value(pattern: str) -> str | None:
    try:
        text = CARGO_TOML.read_text(encoding="utf-8")
    except OSError:
        return None
    match = re.search(pattern, text, re.MULTILINE)
    return match.group(1) if match else None


def default_version() -> str:
    value = cargo_value(r'^version\s*=\s*"([^"]+)"')
    if not value:
        raise PackagingError("cannot determine version from Cargo.toml")
    return value


def default_repo() -> str:
    value = cargo_value(
        r'^repository\s*=\s*"https://github\.com/([^/"]+/[^/"]+)"'
    )
    if not value:
        raise PackagingError("cannot determine repository from Cargo.toml")
    return value


def validate_version(version: str) -> str:
    if not VERSION_RE.fullmatch(version):
        raise PackagingError(
            f"version must be stable numeric SemVer (x.y.z): {version!r}"
        )
    return version


def validate_repo(repo: str) -> str:
    if not REPO_RE.fullmatch(repo):
        raise PackagingError(f"repository must be owner/name: {repo!r}")
    return repo


def release_base_url(repo: str, version: str, override: str | None) -> str:
    if override is None:
        return f"https://github.com/{repo}/releases/download/v{version}"
    value = override.rstrip("/")
    if not value.startswith("https://"):
        raise PackagingError("release base URL must use https")
    if PLACEHOLDER_RE.search(value):
        raise PackagingError("release base URL must not contain placeholders")
    return value


def load_sha256sums(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise PackagingError(f"missing checksum manifest: {path}")
    entries: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise PackagingError(f"cannot read checksum manifest {path}: {error}") from error
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        match = CHECKSUM_RE.fullmatch(line)
        if not match:
            raise PackagingError(f"{path}:{number}: malformed checksum line")
        digest, name = match.groups()
        if name in entries:
            raise PackagingError(f"{path}:{number}: duplicate entry for {name}")
        entries[name] = digest.lower()
    if not entries:
        raise PackagingError(f"{path}: checksum manifest is empty")
    return entries


def verify_artifact(path: Path, expected: str) -> None:
    if not path.is_file():
        raise PackagingError(f"missing release artifact: {path}")
    actual = sha256_file(path)
    if actual != expected:
        raise PackagingError(
            f"checksum mismatch for {path.name}: expected {expected}, got {actual}"
        )


def normalize_member(name: str) -> str:
    while name.startswith("./"):
        name = name[2:]
    return name


def archive_files(path: Path) -> set[str]:
    try:
        if path.name.endswith(".tar.gz"):
            with tarfile.open(path, "r:gz") as archive:
                return {
                    normalize_member(member.name)
                    for member in archive.getmembers()
                    if member.isfile()
                }
        if path.name.endswith(".zip"):
            with zipfile.ZipFile(path) as archive:
                return {
                    normalize_member(info.filename)
                    for info in archive.infolist()
                    if not info.is_dir()
                }
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as error:
        raise PackagingError(f"cannot inspect {path.name}: {error}") from error
    raise PackagingError(f"unsupported release archive format: {path.name}")


def validate_archive_layout(linux: Path, windows: Path) -> None:
    linux_files = archive_files(linux)
    if not {"bin/portensor", "bin/portensor-linux"} & linux_files:
        raise PackagingError(
            "Linux archive must contain bin/portensor or bin/portensor-linux"
        )
    for required in ("LICENSE", "packs/official-baseline/pack.toml"):
        if required not in linux_files:
            raise PackagingError(f"Linux archive is missing {required}")
    if not any(
        name.startswith("share/man/man1/") and name.endswith(".1")
        for name in linux_files
    ):
        raise PackagingError("Linux archive is missing share/man/man1 pages")

    windows_files = archive_files(windows)
    for required in (
        "bin/portensor.exe",
        "LICENSE",
        "packs/official-baseline/pack.toml",
    ):
        if required not in windows_files:
            raise PackagingError(f"Windows archive is missing {required}")


def render_template(text: str, values: dict[str, str]) -> str:
    missing = sorted(set(PLACEHOLDER_RE.findall(text)) - set(values))
    if missing:
        raise PackagingError(f"unresolved template placeholders: {', '.join(missing)}")
    rendered = PLACEHOLDER_RE.sub(lambda match: values[match.group(1)], text)
    if PLACEHOLDER_RE.search(rendered):
        raise PackagingError("rendered output still contains a placeholder")
    if PRIVATE_KEY_RE.search(rendered):
        raise PackagingError("rendered output contains private key material")
    return rendered


def validate_rendered(output_dir: Path) -> None:
    with (output_dir / "scoop" / "portensor.json").open(encoding="utf-8") as handle:
        scoop = json.load(handle)
    if not isinstance(scoop, dict) or scoop.get("version") is None:
        raise PackagingError("Scoop manifest is not a JSON object with version")

    ET.parse(output_dir / "chocolatey" / "portensor.nuspec")

    for relative in TEMPLATES:
        text = (output_dir / relative).read_text(encoding="utf-8")
        if PLACEHOLDER_RE.search(text):
            raise PackagingError(f"{relative}: unresolved placeholder")


def syntax_checks(output_dir: Path) -> list[str]:
    notes: list[str] = []

    bash = shutil.which("bash")
    if bash:
        completed = subprocess.run(
            [bash, "-n", str(output_dir / "aur" / "PKGBUILD")],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        if completed.returncode != 0:
            raise PackagingError(
                f"PKGBUILD syntax check failed: {completed.stderr.strip()}"
            )
        notes.append("PKGBUILD bash -n: pass")
    else:
        notes.append("PKGBUILD bash -n: skipped (bash unavailable)")

    ruby = shutil.which("ruby")
    if ruby:
        completed = subprocess.run(
            [ruby, "-c", str(output_dir / "homebrew" / "portensor.rb")],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        if completed.returncode != 0:
            raise PackagingError(
                f"Homebrew formula syntax check failed: {completed.stderr.strip()}"
            )
        notes.append("Homebrew ruby -c: pass")
    else:
        notes.append("Homebrew ruby -c: skipped (ruby unavailable)")

    pwsh = shutil.which("pwsh") or shutil.which("powershell")
    if pwsh:
        script_path = str(
            output_dir / "chocolatey" / "tools" / "chocolateyinstall.ps1"
        ).replace("'", "''")
        script = (
            "$errors = $null; "
            f"[System.Management.Automation.Language.Parser]::ParseFile("
            f"'{script_path}', [ref]$null, [ref]$errors) | Out-Null; "
            "if ($errors.Count -gt 0) { "
            "$errors | ForEach-Object { Write-Error $_.Message }; exit 1 }"
        )
        completed = subprocess.run(
            [pwsh, "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        if completed.returncode != 0:
            raise PackagingError(
                "Chocolatey PowerShell syntax check failed: "
                f"{completed.stderr.strip()}"
            )
        notes.append("Chocolatey PowerShell parse: pass")
    else:
        notes.append("Chocolatey PowerShell parse: skipped (pwsh unavailable)")

    try:
        import yaml
    except ImportError:
        notes.append("Compose YAML parse: skipped (PyYAML unavailable)")
    else:
        try:
            compose = yaml.safe_load(
                (output_dir / "docker" / "compose.yaml").read_text(encoding="utf-8")
            )
        except yaml.YAMLError as error:
            raise PackagingError(f"Compose YAML parse failed: {error}") from error
        if not isinstance(compose, dict) or "portensor" not in compose.get("services", {}):
            raise PackagingError("Compose file does not define the portensor service")
        notes.append("Compose YAML parse: pass")

    return notes


def generate(
    *,
    version: str,
    repo: str,
    dist_dir: Path,
    output_dir: Path,
    template_dir: Path,
    base_url: str | None = None,
    run_syntax_checks: bool = False,
) -> dict[str, object]:
    version = validate_version(version)
    repo = validate_repo(repo)
    base_url = release_base_url(repo, version, base_url)

    sums = load_sha256sums(dist_dir / "SHA256SUMS")
    linux_archive = f"portensor-{version}-linux-x86_64.tar.gz"
    windows_archive = f"portensor-{version}-windows-x86_64.zip"
    for archive in (linux_archive, windows_archive):
        if archive not in sums:
            raise PackagingError(f"SHA256SUMS has no entry for {archive}")
        verify_artifact(dist_dir / archive, sums[archive])
    validate_archive_layout(dist_dir / linux_archive, dist_dir / windows_archive)

    values = {
        "VERSION": version,
        "REPO": repo,
        "RELEASE_BASE_URL": base_url,
        "LINUX_ARCHIVE": linux_archive,
        "WINDOWS_ARCHIVE": windows_archive,
        "LINUX_SHA256": sums[linux_archive],
        "WINDOWS_SHA256": sums[windows_archive],
    }

    generated_files: dict[str, str] = {}
    template_files: dict[str, str] = {}
    for relative, template_relative in TEMPLATES.items():
        template = template_dir / template_relative
        if not template.is_file():
            raise PackagingError(f"missing package template: {template}")
        rendered = render_template(template.read_text(encoding="utf-8"), values)
        destination = output_dir / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(rendered, encoding="utf-8", newline="\n")
        generated_files[relative] = sha256_file(destination)
        template_files[template_relative] = sha256_file(template)

    validate_rendered(output_dir)
    notes = syntax_checks(output_dir) if run_syntax_checks else []

    manifest = {
        "schema": 1,
        "version": version,
        "repository": repo,
        "release_base_url": base_url,
        "artifacts": {
            "linux-x86_64": {
                "file": linux_archive,
                "sha256": sums[linux_archive],
            },
            "windows-x86_64": {
                "file": windows_archive,
                "sha256": sums[windows_archive],
            },
        },
        "generated_files": dict(sorted(generated_files.items())),
        "template_files": dict(sorted(template_files.items())),
        "notices": [
            "Local metadata generation only; no registry publication was performed.",
            "Registry ownership and clean-environment installs remain unverified.",
            "Generated metadata is not production signing or release evidence.",
        ],
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    return {
        "version": version,
        "repo": repo,
        "base_url": base_url,
        "linux_sha256": sums[linux_archive],
        "windows_sha256": sums[windows_archive],
        "output_dir": output_dir,
        "manifest": manifest_path,
        "generated_files": sorted(generated_files),
        "syntax_notes": notes,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", help="release version; defaults to Cargo.toml")
    parser.add_argument(
        "--repo",
        help="GitHub owner/name; defaults to Cargo.toml repository",
    )
    parser.add_argument("--dist-dir", type=Path, default=DEFAULT_DIST_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--template-dir", type=Path, default=DEFAULT_TEMPLATE_DIR)
    parser.add_argument(
        "--release-base-url",
        help="override the GitHub release download base URL",
    )
    parser.add_argument(
        "--syntax-check",
        action="store_true",
        help="run available local syntax checks after rendering",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        summary = generate(
            version=args.version or default_version(),
            repo=args.repo or default_repo(),
            dist_dir=args.dist_dir,
            output_dir=args.output_dir,
            template_dir=args.template_dir,
            base_url=args.release_base_url,
            run_syntax_checks=args.syntax_check,
        )
    except PackagingError as error:
        print(f"package-metadata: ERROR: {error}", file=sys.stderr)
        return 1

    print(f"package-metadata: version={summary['version']}")
    print(f"package-metadata: repository={summary['repo']}")
    print(f"package-metadata: release_base_url={summary['base_url']}")
    print(f"package-metadata: linux_sha256={summary['linux_sha256']}")
    print(f"package-metadata: windows_sha256={summary['windows_sha256']}")
    print(f"package-metadata: output={summary['output_dir']}")
    for relative in summary["generated_files"]:
        print(f"package-metadata: generated={relative}")
    for note in summary["syntax_notes"]:
        print(f"package-metadata: {note}")
    print("package-metadata: registry_ownership=not verified")
    print("package-metadata: clean_install_tests=not executed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
