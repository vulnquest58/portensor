# Package metadata

Status: **local templates and generator; no registry publication.** P4-2
remains `blocked` until ownership, account controls, maintainer responsibilities,
and clean-environment installs are verified.

This directory prepares package-manager metadata for the release archives. It
does not authenticate to package registries, create tokens, or publish
anything. Generated metadata is not evidence of production signing or registry
ownership.

## Channels

| Channel | Template | Generated metadata | Target |
|---|---|---|---|
| Homebrew | `templates/homebrew/portensor.rb.in` | `homebrew/portensor.rb` | Linux x86_64 tap formula |
| Scoop | `templates/scoop/portensor.json.in` | `scoop/portensor.json` | Windows x86_64 bucket manifest |
| Chocolatey | `templates/chocolatey/portensor.nuspec.in` | `chocolatey/portensor.nuspec` | Windows x86_64 package |
| Chocolatey | `templates/chocolatey/tools/chocolateyinstall.ps1.in` | `chocolatey/tools/chocolateyinstall.ps1` | Installed package script |
| AUR | `templates/aur/PKGBUILD.in` | `aur/PKGBUILD` | Arch Linux x86_64 package |
| Docker Compose | `templates/docker/compose.yaml.in` | `docker/compose.yaml` | GHCR image example |

The release URL package is generated from the repository declared in
`Cargo.toml`. The checksums are read from `dist/SHA256SUMS` and verified against
the local release archives before any metadata is written.

## Archive layout

The release workflow publishes the Linux binary as `bin/portensor`. Older local
`make dist` archives used `bin/portensor-linux`; the Homebrew and AUR definitions
accept both layouts and install the selected binary as `portensor`. Windows
archives use `bin/portensor.exe`. The generator rejects archives that contain no
Linux binary, no Windows executable, or no license/man/pack content.

`make dist` now writes the static musl binary as `bin/portensor` and keeps the
dynamic binary as `bin/portensor-linux` for local inspection.

## Generate and validate

```sh
make package-metadata
make package-check
```

`make package-metadata` writes to `dist/packages/`. `make package-check` also
runs available local syntax checks. Missing validators are reported as skipped,
not treated as passes.

Expected local scope:

- Linux and Windows archive presence and SHA-256 verification.
- Scoop JSON and Chocolatey XML parsing.
- AUR PKGBUILD shell syntax when `bash` is available.
- Homebrew Ruby syntax when `ruby` is available.
- Chocolatey PowerShell parse when PowerShell is available.
- Compose YAML parse when PyYAML is available.

Not verified locally:

- Registry account ownership or namespaces.
- 2FA, recovery, or least-privilege publishing access.
- Homebrew, Scoop, Chocolatey, AUR, or Docker Compose installation.
- `portensor --version` or the localhost gate from an installed package.
- Image publication or Compose pull.

Those checks are defined in
[clean-install verification](../docs/distribution/clean-install-verification.md)
and require a clean environment plus the external ownership evidence in
[registry ownership](../docs/distribution/registry-ownership.md). Record the
results in the [P4-2 external evidence packet](../docs/distribution/p4-2-external-evidence-intake.md)
and validate them with `make p4-external-evidence-check` before acceptance.

## Release constraints

- Do not publish generated metadata without explicit release authorization.
- Do not add registry tokens or credentials to this repository.
- Do not treat a successful local render as a clean install.
- Do not change checksums after generating metadata; regenerate it from the
  final signed release assets when production signing is available.
- Keep templates and generated metadata separate. Only templates are source
  files; generated output belongs under the ignored `dist/packages/` directory.
