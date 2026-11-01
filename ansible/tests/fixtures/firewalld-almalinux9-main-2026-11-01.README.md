# Captured AlmaLinux firewalld INPUT regression

`firewalld-almalinux9-main-2026-11-01.nft.json` is the exact JSON substring
recorded after `nftables=` in the `firewall_active` evidence from the project's
disposable AlmaLinux 9 native acceptance VM. It includes the complete ruleset,
not only the INPUT chains. No production server was queried for this fixture.

- Source main commit: `fd4f755b924303ff197690d32739fc0de160ff90`.
- GitHub Actions run: `41292423957`.
- Artifact ID: `13077539769`.
- Downloaded artifact SHA-256: `a0408060f11b22f287cc7cecce2fed97dbcc8c39ef3e86f8b7bccb25bcf24f50`.
- Exact fixture size: **28,758 bytes**, with no trailing newline.
- Fixture SHA-256: `9cbe025048fdacfbc5bf96a101afaa558818c8366912156becd354bda4aa0853`.

The original audit returned an incomplete firewall result despite a successful
ruleset query, running firewalld, and an unrestricted iptables INPUT policy.
The relevant unsupported clauses were `ct status in dnat`, zone `goto`, and
ICMPv6 payload matches that cannot match the evaluator's TCP/UDP packets.
The fixture contains no machine identity, credentials, private keys, or download
URLs; it preserves nft table flags, handles, counters and all rule expressions.

The behavioral regression executes the actual embedded audit against this
snapshot. It expects a conditional deny witness for the baseline, permission
for every destination port in the declared packet model after adding exactly
one unconditional accept to `filter_IN_public_pre`, and the original witness
after restoring the original snapshot. These are offline ruleset replays;
the separate native VM gate verifies the live firewalld change and restoration.
