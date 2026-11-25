# ADR 0004: Endpoint-aware OS fingerprint reporting

- Status: Accepted for v0.7.x P4 validation
- Date: 2026-11-21
- Related: [P4 release readiness](../p4-release-readiness.md), [RedEye benchmark](../../bench/htb/redeye.md), [Phase 5 gate](../phase5-gate.md)

## Context

The Phase 5 multi-port OS stage sampled several open ports and then collapsed
them into one host family by majority vote. The result was useful for a
single-stack host but lost information when different endpoints terminated on
different stacks. The RedEye benchmark demonstrates the failure: ports `22` and
`80` are a Linux edge, while `443` is a Windows ADFS endpoint. The old summary
reported `Windows 10/11` for the whole host at 91.5% confidence because the
Windows sample won the vote, even though the Linux samples were strong and the
ports belong to different systems.

Operators need to see which endpoint produced each OS result, with family
confidence and stack evidence, while retaining a compact host summary for
single-OS hosts.

## Decision

1. Add a `Mixed` family to `OsFamily`.
2. Retain every successful per-port sample as an `OsEndpointGuess` containing:
   port, family, detail, confidence, inferred initial TTL, hops, evidence, and
   the service detected on that port when known.
3. Store the endpoint list on the host `OsGuess` as `endpoints`.
4. Host summary rules:
   - No named-family samples: preserve the best sample, report `unknown`, and
     keep all endpoints.
   - At least two named families with endpoint confidence >= 0.35: report
     `mixed`; confidence is the mean of the strong families' best endpoint
     confidence; host-level TTL/hops/evidence are omitted because no single
     stack applies; endpoints carry the details.
   - Otherwise: use the existing family vote, agreement dilution, and
     confidence rules, with an additional requirement that at least one sample
     is strong enough to support the winning family.
5. Enrich endpoint rows with the service name after service detection.
6. Per-port accuracy scoring, terminal tables, Markdown, HTML, and Nmap XML
   prefer the endpoint result when one exists. JSON exposes the full endpoint
   list automatically.
7. Windows role refinement still applies only when the host summary is
   Windows; mixed hosts have no single role.

## Consequences

- A Linux TLS front end with a Windows ADFS backend is represented honestly:
  the edge ports are Linux, the TLS/ADFS port is Windows, and the host summary
  is mixed.
- Single-OS hosts retain the existing consensus behavior and output shape,
  with additive endpoint data.
- A strong outlier can mark a host mixed. The 35% threshold is intentional:
  weak one-off guesses are penalized by the existing confidence model and do
  not trigger mixed mode.
- Consumers that only read host-level family/confidence still work; consumers
  that need port attribution can read `endpoints`.
- Scans with `--os-probes 1` cannot detect mixed hosts because only one
  endpoint is sampled.

## Validation

- Unit tests cover strong-family mixed detection, weak-outlier single-family
  consensus, unknown-sample voting, and all-unknown hosts.
- Endpoint tests verify port-to-family attribution and detail/confidence
  preservation.
- Output tests verify Markdown endpoint rows and per-port OS labels.
- The RedEye v2 rerun reports Linux on `22/80/3000` and Windows on `443`, with
  host summary `mixed OS: linux (22, 80), windows (443)` at 96% confidence. The
  raw Windows-like stack evidence is retained on every endpoint, so the old
  aggregate limitation is recorded as resolved.
