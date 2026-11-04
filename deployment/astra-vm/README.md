# Real Astra VM scanner acceptance

The `Real Astra VM scanner acceptance` workflow boots the official public Astra
Linux SE **1.8.1 and 1.8.6 base amd64 cloud-init images** in QEMU. Each guest has
its own kernel, original release files and actual installed package database.
The Ubuntu runner is only the controller. No production scanner is patched and
no Linux identity is replaced for this acceptance.

`sources.json` pins image and full vendor OVAL bytes by the SHA-256 published by
the vendor's public Artifactory metadata API. The metadata URLs are recorded for
independent review. Updating a pin requires checking the new source and labelled
expectations; a changed remote file deliberately fails the workflow.

## What is exercised

1. A generated SSH host key is injected through cloud-init and independently
   pinned on the controller before boot. SSH requires that exact key.
2. The unchanged facts and package playbooks collect the actual guest state.
3. The full 18-rule HCP Astra baseline executes through the production OpenSCAP
   playbook. A bounded `/etc/passwd` mode change inside the disposable guest must
   produce native `pass → fail → pass`, matching the HCP report. Original mode is
   restored in `finally` and the owned VM is stopped even after failure.
   Every reported rule status and SCE observation is compared with the native
   ARF; the report's content checksum must match the retained compiled datastream.
4. After the real baseline → violation → restored cycle, the three **original**
   HCP OpenSCAP JSON reports are copied into the actual production
   `publishCapturedAssetReports` flow using the independently observed guest
   machine-id and pinned SSH fingerprint (the same captured binding for all
   three reports). The publisher must preserve every original rule finding.
   The production source-bound Python comparator
   `deployment/tests/measure_astra_baseline.py --restored` then checks
   identical 18-rule scope and stable source bundle, strictly increasing
   timestamps, a verified asset ID/generation, all three report SHA-256s and
   separate compiled-datastream SHA-256s. On both disposable native Astra
   guests, the expected one-rule `passed → failed → passed` must be observed,
   with **zero baseline-to-restored rule-status regressions**. Original raw
   reports, published identity-bound JSON, measured metrics, ARF and executed
   datastreams are kept as acceptance artifacts. This is stronger than unit
   fixtures but does **not** establish entire OS, SSH or firewall restoration.
5. The complete byte-pinned vendor OVAL XML is evaluated. The native runner
   parses the full exact source and obtains its **current real definition count**;
   it then requires every definition to have one evaluated result. The earlier
   8,284-definitions figure belongs only to the retained October 2026 snapshot,
   not automatically to the updated November source. An upstream source change
   must never be silently accepted without a reviewed size and SHA-256.
   The labelled CVE-2024-5535 definition's actual three package predicates are
   checked independently against the XML and `dpkg --compare-versions`. The
   older image must return `true`; the fixed image must return `false` for that
   definition. Installing OpenSCAP must not change those installed package
   versions. Other vulnerabilities in either image may remain.
   Version controls use installed dpkg records, excluding residual configuration
   from removed packages. A surviving labelled result cannot hide a failed
   native process or a result set missing other source definitions.
6. The actual web report normalizer must retain the finding, CVE identity,
   incomplete-evaluation status and absence of a misleading aggregate CVE score.

## Scope and evidence

The workflow runs on PRs before merging and on relevant `main` changes. It
requires a disposable GitHub-hosted runner, keeps its new working directory
under `RUNNER_TEMP`, exposes guest SSH only on `127.0.0.1`, and uses KVM when
available (otherwise TCG). Source images are read-only backing files for new
writable overlays. Only the owned guest is provisioned or modified.

Artifacts contain the protocol, actual guest identity and package versions,
scanner versions, ARF, normalized reports and command diagnostics. Private SSH
keys, cloud-init seed, backing image and writable guest disk are not uploaded.

These two base images do **not** validate Astra 1.7, other architectures, max
security level or mandatory access/integrity controls. A successful labelled
pair demonstrates detection and discrimination for that vendor definition; it
does not measure overall false-positive/false-negative rates. Full OVAL results
can legitimately be partial; the protocol preserves those reasons rather than
turning unavailable definitions into a clean scan. The 90-day source-age limit
is explicit for this reproducible pinned acceptance, not a production default.

Primary references: [official image catalogue](https://registry.astralinux.ru/download/),
[cloud-init image documentation](https://registry.astralinux.ru/descriptions/cloud/cloudinit/),
[image security levels](https://registry.astralinux.ru/about/), and the individual
publisher metadata URLs recorded in `sources.json`.
