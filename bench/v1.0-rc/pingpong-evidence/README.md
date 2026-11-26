# PingPong lab validation evidence

Authorized target: HTB PingPong `10.129.219.98/32`, Windows domain controller.
Scope is restricted to discovery, service/fingerprint checks, safe pack scripts,
and advisories. No exploitation or credential access was performed.

## Environment

- Debian 12.5 VM, kernel `6.1.0-18-amd64`.
- OpenVPN `tun0` `10.10.17.180/23`; target route via `10.10.16.1`.
- Binary: `/root/portensor-bin/portensor`, `portensor 1.0.0-rc.1`.
- SHA-256: `57cef8ecc54c286e57b187939b378576299f96f431232674a106db221c0b47d4`.

See `environment.txt` for the captured environment and scope.

## Results

- nmap full TCP inventory: 15 open ports and 65520 filtered in the initial
  baseline; the latest reordered run found 18 open ports and 65516 filtered.
  The target's full inventory is variable.
- Raw IPv4 SYN inventory (`--syn --connect-only`): 15/15 open after a cooldown
  (`portensor-inventory-syn-cooldown-15of15.json`). The reordered run's first
  inventory returned 0/15 because the target had just been full-scanned by the
  preceding nmap run.
- Latest RC scripted verification run: 6 open + 9 silent.
  - Open: `88,139,445,464,593,49674`.
  - Silent: `53,135,636,3269,49664,49669,55840,55981,55985`.
- Earlier scripted verification run: 5 open + 10 silent
  (`139,445,593,49669,49674` open).
- Scripts/advisories: 0 findings; service metadata was sparse on this target.

The difference between the two scripted runs is target rate/state sensitivity,
not a change in the raw SYN inventory. The RC binary still discovered all 15
ports in the connect-only inventory.

## RST cleanup validation

After RST cleanup was added, consecutive raw SYN connect-only runs 2 through 5
each returned 15/15 open. The first run immediately after a full nmap scan
failed once. These runs used the preceding `0.7.2` working build; the RC binary
later reproduced the 15/15 inventory after cooldown.

The validation script waits 120 seconds before its first inventory and retries
once after 120 seconds if the inventory returns zero open ports.

## Known limitation

A full 1-65535 raw SYN scan at `--rate 500 --connect-only` took 3m24s and found
only `49669` open (65534 filtered). Full-range raw SYN parity with nmap is not
achieved on this target. The full-range output is summarized in
`portensor-full-syn-summary.json`; the 15 MB source JSON remains at
`/root/portensor-evidence/portensor-full-syn.json` on the VM.

## P4 status

These results validate scanner behavior in an authorized lab. They do not close
the P4 external requirements: package-channel ownership, key custody, clean-host
verification, independent review/OT assessment, Windows Npcap raw-SYN
verification, and signed risk acceptance remain open.

## Files

- `environment.txt`, `environment-latest.txt`: VM, binary, network, VPN, and
  scope captures.
- `nmap-full.*`: initial independent full TCP baseline (15 open).
- `nmap-full-latest-18open.*`: latest independent full TCP baseline (18 open).
- `nmap-services.*`, `nmap-services-latest.*`: independent service baselines.
- `portensor-inventory-syn.json`: RC raw SYN connect-only inventory (15/15).
- `portensor-inventory-syn-reordered-0of15.json`: first inventory from the
  reordered run, before cooldown (0/15).
- `portensor-inventory-syn-cooldown-15of15.json`: post-cooldown RC inventory
  (15/15).
- `portensor-inventory-syn-post-nmap-failure.json`: immediate post-nmap failure
  capture (0/15).
- `portensor-open.json`, `portensor-open.html`: earlier RC scripted
  verification (5 open + 10 silent).
- `portensor-open-latest-6of9.json`, `portensor-open-latest-6of9.html`: latest
  RC scripted verification (6 open + 9 silent).
- `rst-test-2.json` through `rst-test-5.json`: consecutive RST-cleanup runs.
- `rst-verify.json`: verification-state evidence after RST cleanup.
- `rawtest*.json`: initial raw SYN probes before RST cleanup.
- `portensor-full-syn-summary.json`: summary of the full-range raw SYN run.
- `portensor-syn-tun-failure.stderr.log`: historical pre-fix ARP failure.
