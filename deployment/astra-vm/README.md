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
4. The complete pinned vendor OVAL file is evaluated, including 8,284 definitions.
   The labelled CVE-2024-5535 definition's actual three package predicates are
   checked independently against the XML and `dpkg --compare-versions`. The
   older image must return `true`; the fixed image must return `false` for that
   definition. Installing OpenSCAP must not change those installed package
   versions. Other vulnerabilities in either image may remain.
   Version controls use installed dpkg records, excluding residual configuration
   from removed packages. A surviving labelled result cannot hide a failed
   native process or a result set missing other source definitions.
5. The actual web report normalizer must retain the finding, CVE identity,
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
