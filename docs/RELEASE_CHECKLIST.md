# Release checklist

A source preview is not production security assurance. Releases in the
`0.1.0-alpha.*` series are explicitly experimental. Do not describe them as
independently audited, free of vulnerabilities, or a replacement for normal
SSH host-key verification and recovery access.

## Required for an experimental release

- No unresolved known CRITICAL/HIGH finding in the Core release scope;
  security fixes include regression evidence in [FINDINGS.md](FINDINGS.md).
- F-42: the attest job binds each downloaded artifact to the job that
  uploaded it (artifact ID, zip digest, archive SHA-256) and checks zip
  entries before extracting. Hosted evidence will come from the release
  rehearsal's `verify` job on the pull request, which runs attest's checks
  unmodified on the rehearsal's artifacts; it must pass on the candidate.
  `bash scripts/test-attest-inputs.sh` (needs GNU find; `gfind` on macOS)
  must pass too. F-42 stays a next-tag blocker: for the first tag after the
  fix, check in the release run's attest log that the binding step passed
  and that its three downloads were by ID, before publishing; until one
  release run shows this, a green attest job is not evidence of archive
  origin.
- A full re-run of a release run likely fails the binding on duplicate
  artifact names (fails closed, R-2). Re-run only the attest job (not yet
  tried on a hosted run), or push a new tag.
- On the exact candidate: format, clippy with warnings denied, debug and
  release tests with `SIGSIEVE_REQUIRE_SSHD=1`, and a release build pass.
- Hosted CI passes on macOS and Linux, including real sshd tests, umask 0002,
  peer-uid rejection, corpus mutation, dependency advisories and license checks.
  A run on an earlier commit is not acceptance evidence.
- Scan the publication snapshot for credentials, private keys, personal
  infrastructure references, build outputs and unintended author metadata.
  The CI `secret-scan` job (pinned gitleaks, history reachable from HEAD plus
  the tree) is defense in depth next to GitHub secret scanning and push
  protection. It does not replace that review.
- The MIT license, third-party notices, protocol references, supported
  platforms and untested integrations are accurate in the published snapshot.
- GitHub private vulnerability reporting is enabled and `SECURITY.md` links
  to the working reporting channel.
- The release tag exactly matches `Cargo.toml` and points at a commit on
  `main` (checked by `release.yml` and `verify-release.sh`); the release
  workflow requires full CI before building and keeps OIDC attestation
  separate from compilation.
- Tag rulesets for `refs/tags/v*` are active: creation restricted to
  repository admins, and updates, deletions and force pushes forbidden with
  no bypass.
- Files that ship in the archives (README, CHANGELOG) contain no wording that
  goes stale at tagging. Date the CHANGELOG heading before freezing the
  candidate commit, instead of writing "not yet tagged".
- Download the actual release archives, check their SHA256 sums and GitHub
  provenance, inspect license notices and execute at least the native binary.
- Open the packaged README and CHANGELOG: repository links must point to
  the exact source commit on GitHub. These online guides require internet
  access; the executable and bundled license notices remain local files.
- Publish release notes with the exact commit, CI links, supported platforms,
  checks performed and remaining limitations; mark alpha releases as pre-release.

## Required for a stable release (v1.0.0)

The experimental label stays until every gate below is **Met on the exact
stable release-candidate commit**. Evidence from `v0.1.0-alpha.4` or any
earlier commit is historical: it shows the gate can be met, but every
relevant gate must be revalidated against the candidate. A gate is never met
by Linux evidence for a macOS claim, or by an internal (AI-assisted) review
standing in for an external one.

**Non-waivable gates** (no maintainer exception): S1, S6, S7, S9, S10 and
S12, i.e. no open CRITICAL/HIGH finding, CI and security tests on the exact
candidate, release integrity, user-facing limitations, working
vulnerability reporting, and release-permission separation. Only S2, S3, S4,
S5, S8 and S11 may be met by an explicit, written maintainer decision that
names the gate, the residual risk and the user impact, and is repeated in
the release notes.

**External review is not an audit.** S11 is an external *technical review*.
It does not make SigSieve independently audited. The "not independently
audited" statement stays in the README, INSTALL and release notes, stable
or not, until a genuine independent security audit has been completed and
published.

Status for the published `v1.0.0` (2026-11-09), commit
`71ae5e95e666eeb3cb1b94b25ba6b0b8571eca35`. **Maintainer-reported** marks
evidence the maintainer ran and reported but that has no independently
checkable log in this repository or in Actions:

| # | Gate | Waivable | Status | Evidence / missing |
|---|---|---|---|---|
| S1 | No unresolved confirmed CRITICAL or HIGH finding in the supported threat model | No | Met (v1.0.0) | [FINDINGS.md](FINDINGS.md); no open CRITICAL/HIGH; internal reviews only |
| S2 | Every MEDIUM finding fixed, or accepted individually with user impact documented | Yes | Met (v1.0.0) | [FINDINGS.md](FINDINGS.md); none open |
| S3 | A written stable decision for F-22 and F-47: a fix, or an accepted limitation with its bound; no claim of protocol-level replay prevention | Yes (explicit risk acceptance) | Met (decision; recheck on the candidate) | Legitimate-flow measurement done 2026-11-03 (synthetic keys, localhost, OpenSSH 10.5p1 on macOS 27.2 arm64): at most one signature per (session id, key) and one user name per session; the F-47 replay yielded one signature per user-name variant. Maintainer decision: fix. One attempt per (session id, key) merged in PR #57 (`1e2523c`, 2026-11-04), F-46 verified; F-22 stays an accepted bound: at most one signature per recorded session and key while remembered (300 s, 256 entries; expiry, eviction, new sessions and a new instance allow more); no protocol-level replay prevention. Compatibility restriction: a cancelled or failed Touch ID prompt cannot be retried with the same key on the same connection (reconnect; [SSH_COMPATIBILITY.md](SSH_COMPATIBILITY.md#one-signature-per-session-and-key)). Not externally reviewed (see S11); non-OpenSSH clients and servers not measured |
| S4 | Platform evidence matches the support matrix claimed in the README and INSTALL | Yes (narrow the claimed matrix) | Met (v1.0.0, narrowed matrix) | macOS arm64 and Linux x86_64 release binaries verified (Linux by Actions, macOS maintainer-reported); macOS cross-user (F-46) **not verified**; Linux arm64 source-only; Intel macOS and Windows not validated |
| S5 | Every Secretive configuration advertised as supported is validated on a real device for the candidate | Yes (do not advertise it) | Met for one configuration (maintainer-reported for the 1.0.0 binary) | RC1: one P-256 test key, Secretive 4.0.0, macOS 27.2 arm64, localhost SSH servers, 2026-11-06: 13/13 positive checks, expected cancellation refusal, reconnect 13/13 ([SECRETIVE_INTEGRATION.md](SECRETIVE_INTEGRATION.md#recorded-real-device-results)). 1.0.0 binary: 13/13, maintainer-reported (the maintainer saw the terminal output; no published log). Other configurations unverified |
| S6 | CI and required security tests pass on the exact candidate (incl. MSRV, real OpenSSH, `F-46 status`) | No | Met (v1.0.0) | On `71ae5e9`: [CI](https://github.com/semihbugrasezer/sigsieve/actions/runs/42227739778), [F-46](https://github.com/semihbugrasezer/sigsieve/actions/runs/42231058235) VERIFIED (Linux), [fuzz](https://github.com/semihbugrasezer/sigsieve/actions/runs/42231052710) 4 × 3,600 s, 0 crashes, [rehearsal](https://github.com/semihbugrasezer/sigsieve/actions/runs/42231048170) |
| S7 | Release checksums, SBOMs, build provenance and SBOM attestations verified on macOS and Linux | No | Met (v1.0.0; macOS part maintainer-reported) | [Release run 42286504497](https://github.com/semihbugrasezer/sigsieve/actions/runs/42286504497); Linux [Verify release](https://github.com/semihbugrasezer/sigsieve/actions/runs/42291132708) PASS; macOS native `verify-release.sh` PASS maintainer-reported; checksums and `gh attestation verify` of both archives and SBOMs independently re-checked on macOS 2026-11-09 (no native smoke test) |
| S8 | Homebrew install, upgrade and uninstall tested against the **published** tap | Yes (do not advertise Homebrew) | Met for macOS arm64 (maintainer-reported) | Published tap 1.0.0 formula (tap `7fd385e`, source `sha256` `a2aabca…`): install, upgrade from `v0.1.0-alpha.4`, `brew test`, uninstall on macOS arm64, maintainer-reported, no independent log. Linux Homebrew not tested ([packaging/homebrew](../packaging/homebrew/README.md)) |
| S9 | Known limitations and recovery procedures documented for end users | No | Met (v1.0.0) | [LIMITATIONS.md](LIMITATIONS.md), [USAGE.md](USAGE.md) |
| S10 | Vulnerability reporting works and security maintenance has an owner | No | Met (2026-11-06) | A harmless TEST ONLY advisory was submitted privately by `seerxo-agent`, received and closed by owner; never published. The owner retains the private advisory evidence; [SECURITY.md](../SECURITY.md) |
| S11 | An external technical review completed, its findings fixed or individually assessed | Yes (state that none happened) | **Waived** (written maintainer decision 2026-11-05) | Decision: no external technical review before v1.0.0. Residual risk: design and implementation errors that internal (AI-assisted) review and automated tests missed, including in the F-47 fix and destination binding. User impact: users rely on the published tests, findings register and limitations only. Must be stated in the release notes of every v1 release. [EXTERNAL_VALIDATION.md](EXTERNAL_VALIDATION.md) |
| S12 | Release permissions separated: automation acts only through an account with no write, maintain or admin role on the repository (pull requests from its own fork); merges, `v*` tags and releases are made by the maintainer; `v*` tags are owner-created only and immutable; published releases are immutable. Local credential isolation is **not** claimed; this residual risk is stated in [LIMITATIONS.md](LIMITATIONS.md#verification-gaps-see-release_checklistmd) and the release notes | No | Closed by owner risk acceptance (2026-11-09); process deviation recorded | GitHub settings confirmed by the owner 2026-11-06 (tag ruleset admin-only creation bypass, no bypass on tag immutability, no `seerxo-agent` write/maintain/admin). Published release `v1.0.0` verified immutable token-free on 2026-11-09. **Deviation:** the `v1.0.0` tag was pushed with the owner's credentials during an agent-mediated workflow, not by a separate owner action; the creating tool is unconfirmed. Owner credentials remain reachable to automation under the same macOS user (no isolation claimed). The repository owner personally accepted this residual risk and approved publication on 2026-11-09; the private record stays with the owner |

A stable release candidate (`v1.0.0-rc.N`) may be tagged once S1, S3, S6,
S7 and S9 are met on that commit; it remains a pre-release. `v1.0.0`
itself needs every gate met or, for waivable gates only, a written decision.

## Release record: v1.0.0

Published 2026-11-09T13:02:38Z by the owner as a stable, immutable release
marked Latest: [v1.0.0](https://github.com/semihbugrasezer/sigsieve/releases/tag/v1.0.0).
Annotated, unsigned tag object `11597ef257faeddfdebc94cdc3e71194911bcfe3`
points to `71ae5e95e666eeb3cb1b94b25ba6b0b8571eca35` (merge of PR #62, on
`main`). The release notes are the record of evidence and limitations; the
former draft `RELEASE_NOTES_V1.0.0_DRAFT.md` is superseded and removed.

| Gate | Status |
|---|---|
| Version 1.0.0 in `Cargo.toml` and both lockfiles | Done |
| CI, F-46, rehearsal, fuzz on the exact commit | Done: runs 42227739778, 42231058235, 42231048170, 42231052710 |
| F-42 / F-45: attest binding by artifact ID; tag commit on `main` | Done: release run 42286504497 (Linux verify confirms the tag commit is on `main`) |
| S7: release verification | Linux run 42291132708 PASS; macOS native PASS maintainer-reported |
| S5: Secretive device test with the 1.0.0 binary | 13/13, maintainer-reported |
| S8: Homebrew upgrade from `v0.1.0-alpha.4` against the published tap | Maintainer-reported PASS (tap `7fd385e`) |
| Draft review | Owner-run draft check: exactly one draft, notes byte-identical to the reviewed file, 8 assets matching the verified manifest, attestation and `sigsieve 1.0.0`: PASS. An earlier unreviewed draft for the same tag was archived and deleted before publication |
| Release notes state no independent external review or audit (S11) and the local-credential limitation (S12) | Done |
| Post-publication, token-free | Done: not draft, not prerelease, immutable, Latest, tag → `71ae5e9`, 8 anonymous downloads and API digests match; notes identical except CRLF line endings added by the web UI |
| README / INSTALL / Homebrew packaging point at v1.0.0 | This documentation update |

## Candidate record: v1.0.0-rc.1

Annotated tag `v1.0.0-rc.1` points to
`c4fa7a5eeba0283dc14d73a87ff996b876050394`. GitHub Release was not
published for RC1. Its evidence is historical for the final stable source;
run IDs go into the release notes and the evidence record.
The candidate stays a pre-release. Runtime change since `v0.1.0-alpha.4`:
F-47 (one destination-bound signature per session id and key). Supported
prebuilt targets: macOS arm64 and Linux x86_64; Linux arm64 source-only;
Intel macOS and Windows not validated.

| Gate | Status |
|---|---|
| Version 1.0.0-rc.1 in `Cargo.toml` and both lockfiles | Done |
| Hosted CI on the exact candidate SHA, including `msrv (Rust 1.88)` | Done: run 42023039963 |
| `F-46 status` VERIFIED or NOT_APPLICABLE for the candidate | Done: run 42023334020 |
| Release rehearsal (`workflow_dispatch`) on the exact candidate SHA, including the OIDC-free `verify` job | Done: run 42023338126 |
| Coverage-guided fuzzing, 3,600 s per target, on the exact candidate SHA | Done: run 42023341824 |
| S1/S2: no open CRITICAL/HIGH/MEDIUM finding; S9: limitations reviewed for the candidate | Done for RC1; recheck stable candidate |
| F-42: the tag's `attest` job log shows the binding step passed and all three downloads were by ID | Done: release run 42090685138 |
| F-45: the tag commit is on `refs/heads/main` | Done: release run 42090685138 |
| S7: `scripts/verify-release.sh RUN_ID v1.0.0-rc.1` on macOS arm64 and the **Verify release** workflow on Linux report `RESULT: PASS` | Done: macOS native PASS; Linux run 42187936220 PASS |
| S5: real Secretive device test with the candidate binary, including a cancelled Touch ID prompt and reconnect | Done: 2026-11-06, scoped configuration in [SECRETIVE_INTEGRATION.md](SECRETIVE_INTEGRATION.md#recorded-real-device-results) |
| S8: Homebrew upgrade from `v0.1.0-alpha.4` to 1.0.0 against the published tap | Pending until the 1.0.0 formula is published |
| S10: one end-to-end private vulnerability report received and closed | Done: 2026-11-06 test advisory above |
| S12: maintainer confirms the `v*` tag ruleset bypass list and immutable releases (admin view) | Done: 2026-11-06 owner check; actual final release immutability pending |
| Release notes state "No independent external security review or audit has been performed." and that local credential isolation is not provided (S11, S12) | Pending final release notes |
| README / INSTALL point at the candidate only after it is published | RC1 GitHub Release not published; no RC1 install link claimed |

## Candidate record: v0.1.0-alpha.4

Published on 2026-11-02 from `5ea37b73ce7ed5dd33f3ac405c3ae4ad4da68751`
([release](https://github.com/semihbugrasezer/sigsieve/releases/tag/v0.1.0-alpha.4)).
The tag points at the tested candidate commit itself; `main` (`11cc3c1`)
contains it with the identical tree. Runtime code changes since `v0.1.0-alpha.3`: `run` exits
with 2 for an untrusted upstream, `--secretive` requires an absolute
`HOME`, destination-entry warnings, `doctor` / `connect` self-test labels
and hints (see CHANGELOG). Supported prebuilt targets stay macOS arm64 and
Linux x86_64; Linux arm64 is CI-tested but source-only; Intel macOS and
Windows are not validated. A gate is only ticked from evidence on the exact
candidate SHA; run IDs go into the release notes and the post-release
evidence record, not into this file.

| Gate | Status |
|---|---|
| Version 0.1.0-alpha.4 in `Cargo.toml` and both lockfiles | Done |
| Hosted CI on the exact candidate SHA, including `msrv (Rust 1.88)` | Done: run 41519403249 |
| `F-46 status` on the candidate's PR (VERIFIED or NOT_APPLICABLE) | Done: VERIFIED, run 41519403122 |
| Release rehearsal (`workflow_dispatch`) on the exact candidate SHA, including the OIDC-free `verify` job | Done: run 41527758832 |
| Coverage-guided fuzzing, 3,600 s per target, on the exact candidate SHA | Done: run 41527783557 (287,516,615 executions, no crash) |
| Separate-context internal (AI-assisted) security review of the release path and runtime changes | Done; not an external audit. No CRITICAL/HIGH/MEDIUM finding; LOW/INFO fixes are in the candidate |
| F-42: the tag's `attest` job log shows the binding step passed and all three downloads were by ID | Done: release run 41538765784 |
| F-45: the tag commit is on `refs/heads/main` (checked by `verify-release.sh` and `release.yml`) | Done: `verify-tag` in run 41538765784 and both verifications |
| `scripts/verify-release.sh RUN_ID v0.1.0-alpha.4` on macOS arm64 and the **Verify release** workflow on Linux report `RESULT: PASS`, including SBOM sidecars and attestations | Done: macOS locally; Linux run 41540423408 (dispatched from `main`, verifying the tag's assets) |
| README / INSTALL point at the new release only after it is published | Done in the post-release documentation PR |

## Candidate record: v0.1.0-alpha.3

Published on 2026-11-01 from `60c9b3777ce41cedc035c373836a8c0ea5c7e4cd`
([release](https://github.com/semihbugrasezer/sigsieve/releases/tag/v0.1.0-alpha.3),
[evidence](TESTING.md#release-evidence-v010-alpha3-2026-11-01)).

Runtime code is unchanged from `v0.1.0-alpha.2` (test-only changes under
`src/`). Supported prebuilt targets stay macOS arm64 and Linux x86_64;
Linux arm64 is CI-tested but source-only; Intel macOS and Windows are not
validated. A gate is only ticked from evidence on the exact candidate SHA.
Evidence for these gates (run IDs) goes into the release notes and the
post-release evidence record, not into this file: editing it would change
the candidate SHA the evidence must refer to.

| Gate | Status |
|---|---|
| Version 0.1.0-alpha.3 in `Cargo.toml` and both lockfiles | Done |
| Hosted CI on the exact candidate SHA, including `msrv (Rust 1.88)` | Done: run 41313813814 at `60c9b37` |
| Release rehearsal (`workflow_dispatch`) on the exact candidate SHA, including the OIDC-free `verify` job | Done: run 41319371149 |
| Coverage-guided fuzzing, 3,600 s per target, on the exact candidate SHA | Done: run 41319373654 |
| Separate-context internal (AI-assisted) security review of the release path | Done; not an external audit. It found F-43 and F-44, fixed before tagging |
| F-42: the tag's `attest` job log shows the binding step passed and all three downloads were by ID | Done: release run 41327036746 |
| `scripts/verify-release.sh RUN_ID v0.1.0-alpha.3` on macOS arm64 and the **Verify release** workflow on Linux report `RESULT: PASS`, including SBOM sidecars and attestations | Done: macOS locally; Linux run 41332325926 |
| README / INSTALL point at the new release only after it is published | Done after publication (2026-11-01) |

## Remaining assurance work

These remain explicit limitations of the alpha, not passing tests:

- A professional independent security audit is required before claiming
  production-grade security assurance.
- One owner-assisted Secretive signing and destination-binding check passed
  with a real key and two localhost SSH servers for `v0.1.0-alpha.2`; full
  Touch ID prompt counts, other versions and external services remain
  unverified. Protocol tests alone do not prove those integrations.
- 1Password and physical FIDO keys need separate interoperability testing.
- `v0.1.0-alpha.2` has a recorded four-target 3,600 s-per-target campaign
  on exact release commit `fc7484b` ([TESTING.md](TESTING.md#release-candidate-evidence-2026-10-28)).
  For every future release candidate, rerun coverage-guided fuzzing on its
  exact SHA; a successful campaign is not an audit.
- See [LIMITATIONS.md](LIMITATIONS.md) for availability limits, supported
  host-key types, trust in the local client/configuration, and allowed-key misuse.
- Record external expert findings and three real-user trials using the
  [external validation protocol](EXTERNAL_VALIDATION.md). Preparation and
  internal AI-assisted review do not complete those checks.

## Publication procedure

1. Verify and commit the reviewed Core snapshot. Keep unpublished feature
   branches and their history outside the first public snapshot.
2. Push the reviewed source to the public repository and inspect its exact-SHA CI.
   Run the **Release rehearsal** workflow on that commit: it builds both
   targets as `release.yml` does, checks that packaging is byte-identical
   twice, that the binary embeds no runner paths and the archive contents,
   that the CycloneDX SBOM sidecar is byte-identical when generated twice
   and lists every dependency cargo resolves for the target,
   and smoke-tests the extracted binary with `doctor` against a real
   `ssh-agent`. Its `verify` job runs the attest job's binding and file
   checks (read from `release.yml`) on the rehearsal's artifacts and checks
   the build job names `verify-release.sh` expects. It creates no tag,
   release or attestation.
3. Merge the accepted candidate to `main` with a merge commit (not squash or
   rebase, so the tested commit stays an ancestor of `main`), then tag the
   **tested candidate commit itself** (the PR head whose SHA the CI,
   rehearsal and fuzzing evidence names), not the merge commit. If the tag
   must be on the merge commit instead, re-run those gates on it first.
   `release.yml` refuses a tag whose commit is not on `main`.
   `release.yml` gates, builds deterministic
   macOS arm64 and Linux x86_64 archives, writes a CycloneDX SBOM sidecar
   per archive (not inside it; checked for completeness and given the
   deterministic `serialNumber` `actions/attest` requires by
   `scripts/finalize-sbom.py`), creates checksums, records provenance for
   archives and SBOMs, and adds an SBOM attestation for each archive.
4. Verify the tag's release run with `scripts/verify-release.sh RUN_ID TAG`
   on macOS arm64, and with the **Verify release** workflow (same script,
   GitHub-hosted Ubuntu 24.04) for Linux x86_64. Each checks that the run is
   that tag's successful release build on GitHub-hosted runners, the
   checksums, `gh attestation verify` bound to this repository, `release.yml`,
   the tag and its commit (self-hosted runners denied), the exact archive
   contents and binary type, and smoke-tests the extracted release binary
   with `doctor`. For every tag after `v0.1.0-alpha.2` it also requires both
   SBOMs and verifies their checksums, their provenance and the archives'
   SBOM attestations; a missing SBOM fails. Both must report
   `RESULT: PASS`; `INCOMPLETE` is not a pass.
5. Create a GitHub Release (marked pre-release for alpha and RC tags) and
   attach only those verified artifacts:
   both archives, both SBOMs and all four `.sha256` files. Link
   [VERIFY_OFFLINE.md](VERIFY_OFFLINE.md) in the release notes.
   Source installation must name the same immutable release tag.

The workflow does not automatically publish a release. Never rewrite an
already public release tag or force-push public history to repair a release;
issue a new version and explain the correction.
