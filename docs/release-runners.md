# Release runners and reproducibility limits

This document records the runner selection and immutability limits for the CI
and release workflows. It is required by the P4 local evidence audit.

## Runner labels

| Workflow | Jobs | Label |
|---|---|---|
| `.github/workflows/ci.yml` | `workflows`, `check`, `audit`, `deny` | `ubuntu-24.04` |
| `.github/workflows/ci.yml` | `windows` | `windows-2022` |
| `.github/workflows/release.yml` | `workflows`, `linux`, `sbom`, `publish` | `ubuntu-24.04` |
| `.github/workflows/release.yml` | `windows` | `windows-2022` |
| `.github/workflows/lab.yml` | `namespace-lab` | `self-hosted`, `linux`, `portensor-lab` |

Release jobs record `RUNNER_OS`, `ImageOS`, and `ImageVersion` in their logs.
Retain those logs with the release evidence.

## Reproducibility limits

GitHub-hosted runner images are mutable. A versioned label such as `ubuntu-24.04`
selects an image family, not an immutable image digest, and GitHub can update the
toolchain, system packages, and kernel within that family. The exact resolved
`ImageVersion` is only available at run time and cannot be selected with a static
workflow label.

This means the repository can pin action code, Rust, signing tools, and SBOM
generation, but it cannot make the hosted runner image itself fully reproducible.
P4-3 therefore remains external-pending until a clean release run records the
resolved image versions, commands, toolchain versions, artifact hashes, and
separate-host verification.

The self-hosted `portensor-lab` runner is used only for isolated lab tests and is
not a release builder.

## Action pinning

Every GitHub Action reference must be pinned to a full 40-character commit SHA
with a comment naming the corresponding release. Floating tags such as `@v4`,
`@v2`, and branch references such as `@master` are rejected by
`make p4-evidence-check`.

The current pins are:

| Action | Version | Pin |
|---|---|---|
| `actions/checkout` | v4.4.0 | `11d5960a326750d5838078e36cf38b85af677262` |
| `actions/upload-artifact` | v4.6.2 | `ea165f8d65b6e75b540449e92b4886f43607fa02` |
| `actions/download-artifact` | v4.3.0 | `d3f86a106a0bac45b974a628896c90dbdf5c8093` |
| `dtolnay/rust-toolchain` | master as of 2026-11-21 | `df2a88e9fe4098bad09cb42c3dec7187f15861fc` |
| `Swatinem/rust-cache` | v2.9.3 | `2201cc584a476d1b508be977bbe4b7d1c7a52e9c` |
| `sigstore/cosign-installer` | v3.10.1 | `7e8b541eb2e61bf99390e1afd4be13a184e9ebc5` |
| `actions/attest-build-provenance` | v2.4.0 | `e8998f949152b193b063cb0ec769d69d929409be` |
| `actions/attest-sbom` | v2.4.0 | `bd218ad0dbcb3e146bd073d1d9c6d78e08aa8a0b` |
| `softprops/action-gh-release` | v2.6.2 | `3bb12739c298aeb8a4eeaf626c5b8d85266b0e65` |
| `taiki-e/install-action` | v2.90.8 | `fe3acb53a98b62c772db35de75ce0e4595e7ca8c` |
| `EmbarkStudios/cargo-deny-action` | v2.1.3 | `094a77a254a15132dbeb0fb0744a2307f086e063` |

`rhysd/actionlint:1.7.12` is a versioned container image, not a GitHub Action.
The tag is fixed, but the image registry tag is mutable; the local actionlint
binary is also validated at version 1.7.12.

To update an action, verify the intended tag with `git ls-remote`, replace both
the SHA and the version comment, then run `actionlint` and
`make p4-evidence-check`.
