# Clean-environment package installation verification

Status: **procedure ready; not executed.** No package channel is approved and
P4-2 remains `blocked`.

This procedure defines the clean-environment install evidence required for each
approved channel. It must be run only after the release owner authorizes the
release and the channel owner approves publication. Do not install or publish
from this development host as a substitute for an isolated test environment.

## Common requirements

Each clean environment must:

- Start from a fresh base image or dedicated host with no prior Portensor install.
- Use the approved release version and channel metadata.
- Record OS name, version, architecture, image or machine identifier, and date.
- Record the package source URL and installed package version.
- Pass `portensor --version` with the expected version.
- Pass the localhost gate or an equivalent container-aware check.
- Record the installed binary path, package checksum or registry digest, and
  uninstall/cleanup result.
- Capture commands, outputs, exit statuses, and evidence storage references.

Do not install registry tokens or production signing material in a test
environment. Use only public release artifacts and public package metadata.

Record each result in the
[P4-2 external evidence packet](p4-2-external-evidence-intake.md) and its
[machine-readable template](p4-2-external-evidence.template.json). Run
`make p4-external-evidence-check` before asking a reviewer to accept it.

## Homebrew on clean Linux

Preconditions: approved tap, formula merge, Linux x86_64 host, Homebrew
installed.

```sh
brew update
brew install <approved-tap>/portensor
brew test <approved-tap>/portensor
brew audit --strict <approved-tap>/portensor
portensor --version
python3 bench/localhost_gate.py --binary "$(command -v portensor)"
brew uninstall <approved-tap>/portensor
```

Record the resolved formula URL, formula commit, checksum, and installed version.
Do not claim macOS support unless a separate tested artifact exists.

## Scoop on clean Windows

Preconditions: approved bucket, manifest published, clean Windows x86_64 host,
Scoop installed.

```powershell
scoop bucket add <approved-bucket-name> <approved-bucket-url>
scoop install <approved-bucket-name>/portensor
portensor --version
python bench/localhost_gate.py --binary (Get-Command portensor).Source
scoop uninstall portensor
```

Record the bucket URL, manifest commit, URL, hash, and installed version. Verify
that the shim resolves to the packaged `bin\portensor.exe`.

## Chocolatey on clean Windows

Preconditions: approved package version, clean Windows x86_64 host with
Chocolatey, package published through the approved source.

```powershell
choco install portensor --version=<version> -y
choco info portensor --version=<version>
portensor --version
python bench/localhost_gate.py --binary (Get-Command portensor).Source
choco uninstall portensor -y
```

Record the package source, package checksum, package version, install log, and
shim path. Verify the installed package URL and checksum match the generated
metadata and release checksums.

## AUR on clean Arch Linux

Preconditions: AUR maintainer approval, package published, clean Arch Linux
x86_64 environment with base development tools.

```sh
git clone https://aur.archlinux.org/portensor.git
cd portensor
makepkg -si
portensor --version
python3 /path/to/portensor/bench/localhost_gate.py --binary "$(command -v portensor)"
sudo pacman -Rns portensor
```

Record the AUR commit, `PKGBUILD` hash, source archive checksum, built package
checksum, and installed version. Verify the package installs the binary, man
pages, license, and bundled official pack.

## GHCR image and Docker Compose

Preconditions: approved image digest, Docker Engine with Compose on Linux x86_64,
published `ghcr.io/vulnquest58/portensor:<version>` image.

```sh
docker compose -f dist/packages/docker/compose.yaml pull
docker compose -f dist/packages/docker/compose.yaml run --rm portensor --version
docker image inspect ghcr.io/vulnquest58/portensor:<version> --format '{{.Id}}'
```

For the localhost check, start a controlled listener on the host and run the
container on host networking, or use an approved container-aware equivalent of
`bench/localhost_gate.py`. Record the exact method and output; do not count a
container that cannot see the host loopback.

Record the image digest, Compose file hash, command, and scan result. Do not
claim support for Docker Desktop host-networking configurations that were not
tested.

## Result recording

Record accepted results in the
[P4-2 external evidence intake and approval packet](p4-2-external-evidence-intake.md).
Every channel result must include:

| Field | Requirement |
|---|---|
| Requirement ID | P4-2 |
| Evidence identifier | Stable channel-specific ID |
| Channel and version | Exact registry, package version, and release tag |
| Issuing organization or responsible owner | Channel owner and verifier |
| Date obtained | Clean-environment test date |
| Verification method | Exact commands and environment description |
| Verification result | Pass, fail, or limitation |
| Storage reference | Retained log, screenshot, or transcript reference |
| Reviewer and approval status | Independent reviewer and channel-owner approval |

## Current state

| Channel | Clean install | Clean-host evidence |
|---|---|---|
| Homebrew | Not executed | None |
| Scoop | Not executed | None |
| Chocolatey | Not executed | None |
| AUR | Not executed | None |
| GHCR / Docker Compose | Not executed | None |

Local metadata rendering and static syntax checks do not satisfy this table.
