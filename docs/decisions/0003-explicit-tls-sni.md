# ADR 0003: Explicit TLS SNI override

- Status: Accepted for v0.7.x P4 validation
- Date: 2026-11-21
- Related: [P4 release readiness](../p4-release-readiness.md), [RedEye benchmark](../../bench/htb/redeye.md)

## Context

The scanner previously used the target IP literal for every TLS handshake and
for the bounded HTTP request sent over the encrypted channel. That is correct
for IP-addressed services but fails when one IP fronts multiple TLS virtual
hosts. During the RedEye benchmark, `443/tcp` reset without SNI and returned a
Windows ADFS certificate and `Microsoft-HTTPAPI/2.0` response only with
`ServerName` `sts.airways.htb`; `3000/tcp` similarly required
`chat.airways.htb` to reach Rocket.Chat instead of the default vhost.

A scan target is an IP after name resolution, so the target alone cannot select
the intended virtual host. Operators need a per-scan SNI override that is
independent of the target address and is used consistently for the handshake,
certificate matching, and the HTTP Host header.

## Decision

1. Add `--sni HOST` to `scan` and `sni` to the TOML config. CLI overrides TOML.
2. Validate and normalize the value before any probe:
   - trim whitespace and trailing dots;
   - lowercase ASCII;
   - require a fully qualified DNS hostname with at least one dot;
   - reject IP literals, wildcards, underscores, empty/oversized labels,
     leading/trailing hyphens, and names longer than 253 bytes.
3. Use the validated name for:
   - rustls `ServerName` in direct and STARTTLS handshakes;
   - certificate DNS SAN/CN matching, including single-label wildcards;
   - the HTTP `Host` header sent over direct TLS.
4. Record the explicit name as `tls.sni` in JSON and related reports.
5. Keep IP-based certificate matching when `--sni` is absent.
6. Reject `--sni` with `--no-tls` and `--ack`, because no TLS stage runs in
   those modes.
7. Do not persist or log credentials; a virtual-host name is scan metadata.

## Consequences

- One IP can be scanned once per virtual host without DNS changes, and each
  scan records the name that selected the certificate and application.
- A certificate mismatch is now meaningful against the intended vhost rather
  than automatically failing because the target is an IP.
- Users must provide a DNS name for vhosts; an IP literal is intentionally not
  accepted as SNI.
- Each virtual host needs its own scan invocation when services share an IP but
  expose different ports or names.

## Validation

- Unit tests cover SNI normalization/rejection and a committed public
  certificate fixture with several DNS SANs plus an IP SAN. The fixture has no
  private key.
- Tests verify that `geo`, `sts`, and `chat` names select matching certificates
  on the same IP, case-insensitive names match, unknown names do not, and
  no-SNI scans remain IP-based.
- The RedEye rerun uses `--sni sts.airways.htb` for `22,80,443` and
  `--sni chat.airways.htb` for `3000`, recording certificate, service, and
  timing evidence in `bench/htb/redeye.md`.
