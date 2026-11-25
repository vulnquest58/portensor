from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "generate_package_metadata", ROOT / "scripts" / "generate_package_metadata.py"
)
assert SPEC is not None and SPEC.loader is not None
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)

TEMPLATES = ROOT / "packaging" / "templates"


def write_linux_archive(path: Path, *, legacy: bool = False, no_binary: bool = False) -> None:
    members: list[tuple[str, bytes, int]] = []
    if not no_binary:
        if legacy:
            members.append(("bin/portensor-linux", b"linux binary", 0o755))
        else:
            members.append(("bin/portensor", b"linux binary", 0o755))
    members.extend(
        [
            ("LICENSE", b"MIT", 0o644),
            ("share/man/man1/portensor.1", b"man page", 0o644),
            ("packs/official-baseline/pack.toml", b"pack", 0o644),
        ]
    )
    with tarfile.open(path, "w:gz") as archive:
        for name, data, mode in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            archive.addfile(info, io.BytesIO(data))


def write_windows_archive(path: Path) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("bin/portensor.exe", b"windows binary")
        archive.writestr("LICENSE", b"MIT")
        archive.writestr("packs/official-baseline/pack.toml", b"pack")


def write_sums(dist: Path) -> tuple[str, str]:
    linux = dist / "portensor-0.7.0-linux-x86_64.tar.gz"
    windows = dist / "portensor-0.7.0-windows-x86_64.zip"
    linux_sha = hashlib.sha256(linux.read_bytes()).hexdigest()
    windows_sha = hashlib.sha256(windows.read_bytes()).hexdigest()
    (dist / "SHA256SUMS").write_text(
        f"{linux_sha}  {linux.name}\n{windows_sha}  {windows.name}\n",
        encoding="utf-8",
    )
    return linux_sha, windows_sha


def make_dist(tmp: Path) -> tuple[Path, str, str]:
    dist = tmp / "dist"
    dist.mkdir()
    write_linux_archive(dist / "portensor-0.7.0-linux-x86_64.tar.gz")
    write_windows_archive(dist / "portensor-0.7.0-windows-x86_64.zip")
    linux_sha, windows_sha = write_sums(dist)
    return dist, linux_sha, windows_sha


def generate(dist: Path, output: Path, **overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "version": "0.7.0",
        "repo": "vulnquest58/portensor",
        "dist_dir": dist,
        "output_dir": output,
        "template_dir": TEMPLATES,
    }
    values.update(overrides)
    return PACKAGE.generate(**values)


class PackageMetadataTests(unittest.TestCase):
    def test_valid_archives_render_all_package_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist, linux_sha, windows_sha = make_dist(Path(tmp))
            output = Path(tmp) / "packages"
            summary = generate(dist, output)

            self.assertEqual(summary["version"], "0.7.0")
            self.assertEqual(summary["linux_sha256"], linux_sha)
            self.assertEqual(summary["windows_sha256"], windows_sha)
            for relative in PACKAGE.TEMPLATES:
                self.assertTrue((output / relative).is_file(), relative)
            self.assertTrue((output / "manifest.json").is_file())

            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["version"], "0.7.0")
            self.assertEqual(manifest["artifacts"]["linux-x86_64"]["sha256"], linux_sha)

            scoop = json.loads(
                (output / "scoop" / "portensor.json").read_text(encoding="utf-8")
            )
            self.assertEqual(scoop["version"], "0.7.0")
            self.assertEqual(scoop["architecture"]["64bit"]["hash"], windows_sha)
            ET.parse(output / "chocolatey" / "portensor.nuspec")

    def test_legacy_linux_layout_is_supported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist, _, _ = make_dist(Path(tmp))
            write_linux_archive(
                dist / "portensor-0.7.0-linux-x86_64.tar.gz", legacy=True
            )
            write_sums(dist)
            output = Path(tmp) / "packages"
            generate(dist, output)
            formula = (output / "homebrew" / "portensor.rb").read_text(encoding="utf-8")
            self.assertIn('"bin/portensor-linux" => "portensor"', formula)
            pkgbuild = (output / "aur" / "PKGBUILD").read_text(encoding="utf-8")
            self.assertIn("$srcdir/bin/portensor-linux", pkgbuild)

    def test_missing_archive_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist, _, _ = make_dist(Path(tmp))
            (dist / "portensor-0.7.0-windows-x86_64.zip").unlink()
            with self.assertRaisesRegex(
                PACKAGE.PackagingError, "missing release artifact"
            ):
                generate(dist, Path(tmp) / "packages")

    def test_checksum_mismatch_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist, _, _ = make_dist(Path(tmp))
            (dist / "portensor-0.7.0-linux-x86_64.tar.gz").write_bytes(b"tampered")
            with self.assertRaisesRegex(
                PACKAGE.PackagingError, "checksum mismatch"
            ):
                generate(dist, Path(tmp) / "packages")

    def test_missing_checksum_entry_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist, linux_sha, _ = make_dist(Path(tmp))
            (dist / "SHA256SUMS").write_text(
                f"{linux_sha}  portensor-0.7.0-linux-x86_64.tar.gz\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                PACKAGE.PackagingError, "no entry for portensor-0.7.0-windows"
            ):
                generate(dist, Path(tmp) / "packages")

    def test_incomplete_archive_layout_is_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist, _, _ = make_dist(Path(tmp))
            write_linux_archive(
                dist / "portensor-0.7.0-linux-x86_64.tar.gz", no_binary=True
            )
            write_sums(dist)
            with self.assertRaisesRegex(
                PACKAGE.PackagingError, "must contain bin/portensor"
            ):
                generate(dist, Path(tmp) / "packages")

    def test_unstable_version_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist, _, _ = make_dist(Path(tmp))
            with self.assertRaisesRegex(
                PACKAGE.PackagingError, "stable numeric SemVer"
            ):
                generate(dist, Path(tmp) / "packages", version="0.7.0-rc.1")

    def test_unresolved_placeholder_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            PACKAGE.PackagingError, "unresolved template placeholders"
        ):
            PACKAGE.render_template("@@UNKNOWN@@", {})

    def test_rendering_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist, _, _ = make_dist(Path(tmp))
            output = Path(tmp) / "packages"
            generate(dist, output)
            first = (output / "manifest.json").read_bytes()
            generate(dist, output)
            second = (output / "manifest.json").read_bytes()
            self.assertEqual(first, second)

    def test_malformed_checksum_line_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist, _, _ = make_dist(Path(tmp))
            (dist / "SHA256SUMS").write_text(
                "not-a-checksum  portensor-0.7.0-linux-x86_64.tar.gz\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                PACKAGE.PackagingError, "malformed checksum line"
            ):
                generate(dist, Path(tmp) / "packages")


if __name__ == "__main__":
    unittest.main()
