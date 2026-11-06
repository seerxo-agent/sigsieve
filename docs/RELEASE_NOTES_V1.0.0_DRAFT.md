# SigSieve v1.0.0 — release notes draft

**Do not publish this draft.** Replace the candidate commit, run links,
archive digests and date only after the exact stable candidate has passed
every required release gate. The published Homebrew formula still installs
`v0.1.0-alpha.4` at the time of this draft.

SigSieve filters SSH agent requests so that forwarded connections see only
allowlisted identities. Optional destination binding restricts signing to
approved SSH destination host keys. Private keys remain in the upstream agent.

## Install

On macOS Apple Silicon, after the verified 1.0.0 formula is published:

```sh
brew install semihbugrasezer/sigsieve/sigsieve
sigsieve --version
```

Existing Homebrew users can then run `brew update && brew upgrade sigsieve`.
This upgrade must be tested against the published formula before these notes
are used. Installation needs no `sudo` or SSH-key changes. The formula builds
from source; its archive checksum is not GitHub binary build provenance.

Prebuilt archives will be limited to macOS Apple Silicon and Linux x86_64.
The Linux archive targets Ubuntu 24.04 / glibc 2.39 or newer. Linux arm64 is
source-only. Intel macOS and Windows have not been validated. macOS binaries
are not notarized. No crates.io package is published.

## Security and compatibility

The F-47 fix permits only one destination-bound signing attempt per verified
session ID and key within the existing 300-second, 256-entry window. A failed
or cancelled Touch ID request cannot be retried in the same session; make a
fresh connection. This is a bounded replay control, **not** protocol-level
replay prevention (F-22). A compromised remote host can still use an
explicitly allowed key while forwarding is active.

No independent external security review or audit has been performed. The
maintainer explicitly waived the external technical review gate (S11).
Design or implementation mistakes may remain despite internal AI-assisted
review, tests and fuzzing. The automation account has no repository write,
maintain or admin role, and release tag rules have no automation bypass, but
automation runs under the maintainer's macOS user and local owner credentials
are **not isolated** from that environment (S12 residual risk).

The `v1.0.0-rc.1` device test used one P-256 test key with Secretive 4.0.0
on macOS 27.2 arm64 against two localhost SSH servers. Positive and fresh
connection runs passed 13/13; a deliberately cancelled Touch ID prompt
refused the allowed destination as expected. Other Secretive versions,
devices, production services, the Homebrew-built binary and the final stable
binary have not been covered by that test. The macOS cross-user F-46 check
has not been run; Linux cross-user evidence does not establish it.

## Verification to fill before publication

- Source commit and tag: **PENDING**
- Exact-head CI, F-46, fuzz and release rehearsal links: **PENDING**
- macOS and Linux release verification, including checksums, SBOMs and
  provenance: **PENDING**
- Stable binary device test or explicit S5 decision: **PENDING**
- Published Homebrew formula install, alpha.4-to-1.0.0 upgrade, `brew test`
  and uninstall: **PENDING**
- Final archive and SBOM SHA-256 values: **PENDING**
- Published release immutability check: **PENDING**

The private vulnerability reporting channel was tested end to end on
2026-11-06 with a harmless, unpublished, closed test advisory (S10). Report
suspected vulnerabilities through [private vulnerability reporting](https://github.com/semihbugrasezer/sigsieve/security/advisories/new).
