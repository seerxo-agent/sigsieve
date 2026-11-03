# Security findings register

All reviews so far were performed by **internal AI agents in separate
contexts**. That is not an independent external audit; an external audit
remains required before making production-grade assurance claims (see
[RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md)).

Pre-publication revision IDs below identify historical local work; public
history starts from the reviewed Core snapshot. They are not public commit links.

Severity: CRITICAL / HIGH / MEDIUM / LOW / INFO. "Fix" is the commit on this
repository's history; "Test" is the regression test that fails without the
fix (where one exists).

## Summary

| ID | Severity | Title | Status |
|---|---|---|---|
| F-01 | HIGH | `connect`: ControlMaster reuse forwards the unfiltered agent | Fixed |
| F-02 | HIGH | `connect`: indirect ProxyCommand (env/sh -c/wrappers) forwards the unfiltered agent | Fixed (fail closed) |
| F-03 | LOW-MED | `connect`: RemoteForward / config can expose the unfiltered agent (incl. path-spelling bypass) | Fixed |
| F-04 | LOW-MED | `connect`: ProxyCommand children inherit unfiltered `SSH_AUTH_SOCK` | Fixed |
| F-05 | LOW | Idle connections lock out all clients (connection cap) | Fixed (eviction) |
| F-06 | LOW | Eviction could cut in-progress logins / evict a just-read request | Fixed |
| F-07 | LOW | `connect`: signals before ssh start ignored; SIGKILL without grace | Fixed |
| F-08 | LOW | Unquoted `SSH_AUTH_SOCK=` output; terminal escapes in comments; untruncated log names; newline injection in state file | Fixed |
| F-09 | LOW | `PermitLocalCommand`: LocalCommand receives the login agent | Fixed (refused) |
| F-10 | LOW | Forwards silently dropped by ClearAllForwardings | Fixed (warning) |
| F-11 | LOW | `IdentityAgent ${SSH_AUTH_SOCK}` / `$SSH_AUTH_SOCK` configs broke or lost login agent | Fixed |
| F-12 | INFO | Documentation wrongly claimed constrained upstream keys are bypassed | Fixed (docs) |
| F-13 | LOW | Accept loop slept 25 ms when idle (28 ms per new connection) | Fixed |
| F-14 | LOW | Deprecated `GenericArray` API would break `-D warnings` after `cargo update` | Fixed |
| F-15 | MEDIUM (process) | Fuzz seed corpus git-ignored; CI fuzz test would fail | Fixed |
| F-16 | LOW (diagnostic) | RSA binding host key reported as "bad signature" instead of "unsupported" | Fixed |
| F-17 | LOW | Active (non-idle) connections can still saturate an instance | Accepted, documented |
| F-18 | LOW | No timeout on upstream `connect(2)` (Linux full backlog) | Implemented: nonblocking connect + whole-exchange deadline; native Linux regression requires current CI |
| F-19 | LOW | Logging not rate-limited | Fixed: bounded details and suppression summaries; CLI privacy/flood regression |
| F-20 | INFO | Only the socket's immediate parent directory is checked | Hardened: trusted ancestor ownership/modes; extended ACL and same-uid limits remain |
| F-21 | LOW | Destination-binding mode: self-test did not prove binding is active | Fixed |
| F-22 | LOW | Replayed authorized bind+sign sequences trigger upstream signing / Touch ID | Mitigated: shared signing budget + bounded cache of one attempt per (session id, key); protocol-wide prevention not claimed |
| F-23 | INFO | Duplicate bind does not upgrade a forwarding entry to an auth entry | Accepted (matches OpenSSH, fails closed) |
| F-24 | MEDIUM (process) | Deployment-specific strings committed on the unpushed feature branch | Fixed: this release branch (`clean/core-candidate`) carries clean history only |
| F-25 | LOW (supply chain) | RUSTSEC-2026-0387: `crypto-bigint` 0.5.5 timing variability (via p256/p384/p521 0.13). Not exploitable here (verification of public data only), but the audit gate failed | Fixed: upgraded to p256/p384/p521 0.14, ed25519-dalek 3, sha2 0.11 (`crypto-bigint` 0.7.6) |
| F-26 | LOW | P-384/P-521 host-key verification only tested against signatures from the same crates | Fixed: `destination_binding_with_p384_and_p521_host_keys` verifies real OpenSSH signatures (mutation-checked) |
| F-27 | LOW | `release.yml` used `${{ env.HOME }}` (empty), so path remapping was broken | Fixed: remap in a shell step using `$HOME`; exercised by the tag-free rehearsal and the published `fc7484b` tag build. [Release build and native verification](TESTING.md#release-candidate-evidence-2026-10-28) |
| F-28 | INFO | CI installed unpinned cargo-audit/cargo-deny; THIRD_PARTY.md listed crates of another component; no uninstall docs | Fixed |
| F-29 | HIGH | `connect` verified only the destination's ProxyCommand; a wrapper on a ProxyJump (or relay) hop ran with the unfiltered login agent in its environment and could forward it (C-1) | Fixed: every hop verified |
| F-30 | MEDIUM | `Match exec` was detected only from `ssh -G -v` output, i.e. after ssh had run the command during connect's verification | Fixed: user ssh_config (and includes) scanned before ssh runs |
| F-35 | HIGH | CR between an Include keyword and path was treated differently from OpenSSH and hid included Match exec | Fixed in alpha.2: constrained configuration syntax and conservative glob scanning; unit and real-OpenSSH marker regressions |
| F-36 | LOW (protocol) | Non-RSA identities accepted RSA SHA-2 signature flags at the proxy boundary | Fixed: key-type validation before upstream; red/green mock-agent regression; not an authorization bypass |
| F-37 | LOW (policy) | connect accepted explicitly disabled host-key verification | Changed: refuse no/off/false on target and hops; red/green real OpenSSH regression |
| F-38 | LOW (policy) | Legacy RSA/SHA-1 (`ssh-rsa`, flag 0) signing passed through when the upstream allowed it | Fixed: exactly one SHA-2 flag required for RSA, returned algorithm checked; real OpenSSH regression |
| F-39 | LOW | A non-UTF-8 home directory was converted lossily, so the ssh_config pre-scan read a missing path and skipped the real `~/.ssh/config` | Fixed: byte-exact path from the password database; red/green unit regression |
| F-34 | HIGH | Missing or failed initial forwarding bind could expose the ordinary-publickey first-hop exception to a remote client | Fixed: hostbound required for every destination-bound signature; initial failure terminal; regression tests |
| F-33 | LOW (supply chain) | crypto-bigint 0.7.6 was yanked after the earlier local checks; public CI rejected it | Fixed: root and fuzz lockfiles updated to non-yanked 0.7.9 |
| F-32 | HIGH | SSH pre-scan disagreed with OpenSSH on quoted keywords and Include argument delimiters, permitting Match exec during verification | Fixed: conservative keywords, exact space/tab path parsing, UTF-8 validation; regression tests |
| F-31 | HIGH | Review of F-29/F-30: a relay's own `-F` was ignored for its nested hops; hop forwardings were not checked; quoting (`e'x'ec`) hid `Match exec`; X11 forwarding ran xauth with the login agent; unsafe `-F` paths reached ssh's ProxyJump shell command; concurrent stale-socket recovery could have two winners | Fixed (details below) |
| F-40 | LOW (availability) | A slow downstream reader could keep a reply write going indefinitely: SO_SNDTIMEO restarts on every partial transfer | Fixed: nonblocking reply writes under one whole-reply deadline; red/green regression |
| F-41 | LOW (diagnostic) | RSA binding self-test refused by algorithm policy instead of exercising destination enforcement | Fixed: valid RSA/SHA-2 probe; regression catches missing enforcement for RSA, ECDSA and Ed25519 |
| F-42 | LOW (supply chain) | Release attest job selects artifacts by name; a compromised job holding the Actions runtime token could replace an artifact before attestation | **Fixed; verified on the v0.1.0-alpha.3 tag run** (41327036746: binding step passed, three downloads by artifact ID): attest binds each artifact to its producing job's ID, zip digest and archive SHA-256 and checks zip entries before extraction (`scripts/test-attest-inputs.sh`); the rehearsal `verify` job passed (41319371149); manual `verify-release.sh` and native smoke test remain mandatory |
| F-43 | MEDIUM (release, fails closed) | Release SBOMs had no CycloneDX `serialNumber`, which the pinned `actions/attest` requires; the first tag's SBOM attestation step would have failed | **Fixed; verified on the v0.1.0-alpha.3 tag run** (41327036746: both SBOM attestations created): deterministic `urn:uuid` serial added by `scripts/finalize-sbom.py`, checked against the action's acceptance rule; regression `scripts/test-finalize-sbom.py` |
| F-45 | LOW–MEDIUM (supply chain) | A release tag was not bound to `main`: a tag on an unreviewed commit could get a release that verified | Fixed after v0.1.0-alpha.3: `verify-release.sh` gates on the tag commit being on `refs/heads/main`; `release.yml` checks it too (defense in depth); tag looked up as `refs/tags/` (RV-3); regression `scripts/test-verify-release-tag.sh` |
| F-44 | LOW (supply chain) | The release SBOM job did not check dependency completeness, unlike the rehearsal | **Fixed; ran on the v0.1.0-alpha.3 tag run** (41327036746): both workflows run the same completeness check through `scripts/finalize-sbom.py`; a dropped dependency fails the release SBOM step |
| F-46 | INFO (untested control) | The upstream peer-uid check, the only control that is not racy, had no test that makes it refuse | **Closed: verified on Linux** (PR #44, workflow run 41455680046): two-user test 4/4 passed, foreign agent received no request; mutant without the check 1 passed / 3 failed on their own assertions; merged commit `e77632d` has the tested tree (`verify-f46-evidence.sh`). macOS cross-user not tested. Pathname checks before `connect` remain advisory |
| F-47 | LOW | Duplicate-attempt cache (F-22) is bypassed by varying the userauth username: each variant of a replayed request is a new digest | **Mitigated on `main`, unreleased; independent review pending** (found 2026-11-03, internal review; reproduced against a recorded OpenSSH session: 5 username variants, 5 upstream signatures). Now one attempt per (session id, key) and window, the F-22 bound; legitimate OpenSSH flows measured first; RFC 4252 compatibility restriction [documented](SSH_COMPATIBILITY.md#one-signature-per-session-and-key). The original alpha.4 release notes claimed "at most one upstream signature per recorded session"; that was corrected by a [security erratum](https://github.com/semihbugrasezer/sigsieve/releases/tag/v0.1.0-alpha.4) on 2026-11-03 |


### Review scope

Earlier AI reviews checked host-key verification, strict parsing, forwarding
and configuration handling. Later findings F-32 and F-34 show that those
reviews did not establish the absence of high-severity defects. The current
register and executable regression tests supersede earlier review summaries.
None of these reviews is a professional independent audit.

### Internal review of `v0.1.0-alpha.2` source (2026-10-29)

A separate-context AI-assisted review of `src/` at `fc7484be` covered
protocol parsing, keys, policy, destination binding, proxy, resource limits,
upstream and sockets. It reported no new CRITICAL, HIGH, MEDIUM or LOW
finding. Like earlier reviews, it does not establish that no defects remain.
It recorded five INFO observations. None of them is an authorization bypass,
so they receive no F-number:

| Ref | Observation | Classification | Disposition |
|---|---|---|---|
| A-1 | In binding mode an RSA userauth `pkalg` is not tied to the sign-request flags; a mismatched pair costs one upstream signature (possibly one Touch ID prompt) that the server then rejects | Confirmed by code trace | Open, optional hardening; maintainer decision. OpenSSH's agent does not enforce this pairing either |
| A-2 | A session-bind signature is verified before cheaper state checks | Confirmed by code trace | Accepted (bounded by request budgets, F-17). Regression `binds_after_authentication_bind_leave_state_unchanged` pins the state outcome, so the order can be changed safely |
| A-3 | macOS socket creation sets close-on-exec in a second call | Suspected; no concurrent `exec` in the process | Accepted |
| A-4 | Sign responses are checked by algorithm name only | Confirmed; upstream agent is trusted | Accepted (F-38 downgrade check remains) |
| A-5 | `chmod` after `bind` follows symlinks | Out of scope (same-uid attacker, threat model scenario F) | Accepted |

## Details

### F-46 — INFO — upstream connect: pathname checks are racy, peer-uid rejection was untested (closed: verified on Linux)

Found by the internal (AI-assisted, not independent) alpha.4 lifecycle
review. Each upstream request runs `Upstream::connect` (`src/upstream.rs`):

1. `metadata(path)`, following symlinks: must be a Unix socket owned by the
   current uid;
2. `connect(path)`: resolves the path again;
3. `peer_uid` (`getpeereid` on macOS, `SO_PEERCRED` on Linux) on the
   connected descriptor: the agent process must run as the current uid.

Between steps 1 and 2 the path can be replaced (time-of-check to
time-of-use). Step 1 is therefore advisory: it gives a clear error for the
common mistakes (a regular file, someone else's socket). Step 3 is checked on
the descriptor actually used, so a swap to a socket served by **another**
user is still refused. A swap to another socket served by the **same** user
is not detected and is not meant to be: a same-uid attacker can already
replace the agent, which is out of scope (threat model scenario F).

What is tested: the path is re-evaluated for every request, and a file, a
dangling link or a misbehaving agent placed under an open connection fails
closed and recovers (`upstream_replaced_under_an_open_connection_fails_closed_then_recovers`);
a real `ssh-agent` killed (stale socket), its socket removed (no such path)
and restarted on the same path, with SigSieve configured with that path
(`lifecycle::real_agent_killed_and_restarted_under_a_running_proxy`). These
exercise steps 1 and 2; none of them exercises step 3 refusing.

Before PR #44, no executed test made step 3 refuse, because that needs an
agent running as a different uid, i.e. root; a mutation that removed step 3
passed the suite. No production code was changed to close this finding.

Now executed on Linux (see "Verification record" below): `tests/cross_user.rs`, run by
`scripts/cross-user-test.sh` from the workflow `cross-user.yml` on a
disposable GitHub-hosted Ubuntu runner. User B starts a mock agent
(`tests/support/xu-mock-agent.py`, which logs every request and, unlike
`ssh-agent`, does not check its client's uid); root then gives the socket
file to user A. Step 1 therefore passes, and only step 3 can refuse. As A,
the tests require that the library connection is refused with the peer-uid
error, that requests served by the proxy never reach the agent, and that
`sigsieve run` exits with 2. Each test first checks those preconditions
(socket owned by A, peer uid neither A nor root) and fails if they do not
hold. The workflow then removes step 3 and requires each of the three tests
to fail on its own assertion. In ordinary runs the three tests are reported
as *ignored*, never as passed; a same-uid control runs everywhere. macOS
(`getpeereid`) has no cross-user test.

How it runs: `cross-user.yml` triggers on pull requests that change the code
under test or the test itself. GitHub runs a `pull_request` workflow from the
pull request's own files, so it can verify F-46 before any merge. Its manual
`workflow_dispatch` trigger only becomes available once the file is on the
default branch; that is a separate dependency, not needed for the first
run. The job runs on `ubuntu-24.04`, a full GitHub-hosted VM, never a
container-based runner such as `ubuntu-slim`. The script refuses to run in a
container and outside GitHub Actions. Those checks guard against mistakes;
they do not prove the machine is disposable, and only the hosted VM label
does. The script never reuses an account. It creates two new, randomly
named users and, on exit, kills their processes, deletes both users and
removes its directory. The test output, the foreign agent's request log and
the uids of both runs are uploaded as the `f46-cross-user-evidence`
artifact.

The workflow's job condition skips pull requests from forks, and
`F-46 status` then reports NOT_VERIFIED (a failure) when the test applies,
so that a skipped job is not read as a pass. That condition lives in the workflow file, which a pull
request can edit, so it is not a security boundary. GitHub enforces the
limits outside that file:
- for a public repository, a fork's token is read-only and gets no
  secrets, whatever the file says;
- whether a fork's edited workflow runs without a maintainer's approval
  depends on the repository setting "Approval for running fork pull request
  workflows from contributors". Only "Require approval for all external
  contributors" stops it. Under the default (approval for first-time
  contributors only) a returning contributor's fork can run its own root
  code on the runner automatically, as it already can through `ci.yml`,
  which uses `sudo`. Maintainer decision (2026-11-02): the target policy
  is **"Require approval for all external contributors"**. It has **not
  been applied yet** (repository changes are on hold), so this control
  stays open until the setting is in place and confirmed. The setting does
  not restrict accounts with write access; credential access for those is
  a separate, open issue;
- a branch in the repository itself already needs write access.

The job uses no secret and only a `contents: read` token, which
`persist-credentials: false` keeps out of `.git/config`. Root can still
read the job's tokens (`GITHUB_TOKEN`, the Actions runtime token) from the
runner process; they allow reading this public repository and writing
caches and artifacts scoped to this run. Root on the runner reaches nothing
else that persists.

A pull request run tests GitHub's temporary merge of the head into the base.
The workflow first records that commit, its tree, its parents (the first
is the base actually tested, which can differ from the event's `base.sha`)
and the pull request head (`tested-commits.txt` in the artifact). It stops
unless the second parent is the pull request head. After merging,
`scripts/verify-f46-evidence.sh <merged commit> tested-commits.txt` accepts
only a merge commit whose tree equals the tested tree and whose second
parent is the tested head. Because the trees are equal, the workflow and
scripts that produced the evidence are also exactly the merged ones. A base
that moved after the run, a squash or rebase, or any other change makes it
fail. GitHub does not re-run `pull_request` workflows when only the base
moves, and nothing before the merge forces a re-run unless branch protection
requires this check and an up-to-date branch. Maintainer decision
(2026-11-02): do not make this check required yet, and first have a CI
layout that reports a result on every pull request. That layout is now in
the workflow: it runs on every pull request; a `scope` job decides from the
changed paths (`git diff --no-renames` against the base) whether anything
the test builds from, or the files that decide the status, changed; the
privileged `cross-user` job runs only then and never for forks; and the
`F-46 status` job always runs and reports **NOT_APPLICABLE** (pass),
**VERIFIED** (pass, cross-user and mutant runs passed) or **NOT_VERIFIED**
(fail: it applied but was skipped, failed or cancelled, or the scope could
not be decided). If a required check is added later, it must be
`F-46 status`, never `cross-user`, which is skipped when not applicable and
would count as passing. The decision is `scripts/f46-ci.sh` (regression
`scripts/test-f46-ci.sh`, run in `ci.yml`). Like the workflow, a pull
request can edit it, so VERIFIED is evidence only together with the run's
artifact and `verify-f46-evidence.sh`. Strict, up-to-date status checks
are considered after this layout has run. Recovery after such a merge: run the workflow by `workflow_dispatch`
on the merged commit; the verifier accepts dispatch evidence only for the
exact commit it tested. A pull request with merge conflicts gets no run at
all. The verifier checks the source binding only. That the run passed,
and that the artifact comes from this repository's run, are checked from
the run itself. Regression: `scripts/test-verify-f46-evidence.sh`.

F-46 is closed only on a single successful run of that workflow in this
repository that shows all of the following, and only once
`verify-f46-evidence.sh` accepts the merged commit:
1. the cross-user run: 4 tests executed and passed, none ignored, and the
   foreign agent received no request;
2. the mutant run (peer-uid check removed): each of the 3 cross-user tests
   failed on its own assertion and the foreign agent received requests;
3. the same-uid control passed in both runs.

#### Verification record (2026-11-02)
PR #44, head `969cdae`, workflow "Cross-user peer credential (F-46)" run
41455680046 on a GitHub-hosted `ubuntu-24.04` VM (kernel 7.0.0-1017-azure,
`systemd-detect-virt`: microsoft; users with uid 999 and 997):
- tested commit `8abf25e` (temporary merge; parents base `a218021`, head
  `969cdae`), tree `e76f2fe`;
- real run: `test result: ok. 4 passed; 0 failed; 0 ignored`; the foreign
  agent received 0 requests;
- mutant run (peer-uid check removed): `1 passed; 3 failed; 0 ignored`;
  failures "a foreign agent was used", "sigsieve run kept running with a
  foreign agent", "a request reached the foreign agent"; the foreign agent
  received 4 requests (3 identity requests, 1 sign request);
- `F-46 status`: VERIFIED; the same-uid control passed in both runs;
- merged as `e77632d` (merge commit, parents `a218021`, `969cdae`);
  `scripts/verify-f46-evidence.sh e77632d tested-commits.txt`: OK.

Closed on that evidence. Limits: Linux only (macOS `getpeereid` has no
cross-user test); a same-uid substitution remains out of scope (threat
model scenario F); the evidence artifact is kept by the maintainer.

### F-45 — LOW–MEDIUM — release tag not bound to `main` (fixed after v0.1.0-alpha.3)

Found by the internal (AI-assisted, not independent) pre-tag review of
`269cf91` (RV-1). `release.yml` ran for any `v*` tag whose name matched
`Cargo.toml`, and `scripts/verify-release.sh` checked only that the
attestation came from that tag's own `release.yml` at that tag's commit.
Someone able to push tags could tag an unreviewed commit, with its own
`release.yml`, and get a release that verifies; the `main` ruleset's
pull-request requirement would not apply. Only the maintainer can push to
the repository, and no tag ruleset existed.

Fix:
- `verify-release.sh` fails unless GitHub's compare of the tag commit with
  `refs/heads/main` is `identical` or `ahead`. This is the gate: a tag on a
  commit whose own `release.yml` drops the workflow check below still fails
  here. It resolves the tag as `refs/tags/TAG` and `main` as
  `refs/heads/main`, so a branch named like the tag, or a tag named `main`,
  cannot answer instead (RV-3, INFO; the old tag lookup failed closed).
- `release.yml`'s `verify-tag` job fetches `main` and fails unless the
  tagged commit is an ancestor of it (`git merge-base --is-ancestor`).
  This is defense in depth: it stops the reviewed workflow from building
  and attesting such a tag, but a tagged commit carries its own
  `release.yml`, which could omit the step. `gh attestation verify` alone
  does not check this; use `verify-release.sh` or the `VERIFY_OFFLINE.md`
  compare step.
- `docs/VERIFY_OFFLINE.md` shows both checks.
- `scripts/test-verify-release-tag.sh` (6 cases, stubbed `gh`; runs in CI)
  covers identical, ahead, diverged, behind, a failed and an empty compare,
  the `refs/tags/` lookup and a tag named `main`. Four mutations (the old
  lookup, no ancestry check, accepting `behind`, an unqualified `...main`
  (MR-2)) are each caught.
- The workflow step was run locally against a throwaway repository: a
  commit on `main` and an ancestor pass; an unmerged commit fails.

The commits of `v0.1.0-alpha.1` and `v0.1.0-alpha.2` are on `main`, so the
new check accepts them (the rest of `verify-release.sh` is unchanged; the
`v0.1.0-alpha.1` tag-push run 40248231106 was cancelled, so that tag never
had a run the script could pass). `v0.1.0-alpha.3` (`60c9b37`) is on `main`
(compare: `ahead`); its release run 41327036746 predates the `verify-tag` step,
so the workflow did not check this, and the tag was checked by hand before it
was pushed.

Residual: the check proves the commit was merged, not that the merge was
reviewed well. Rulesets are repository settings that an administrator can
change.

### F-43 / F-44 — release SBOM attestation input (fixed, verified on the v0.1.0-alpha.3 tag run)

Found by the internal (AI-assisted, not independent) pre-tag review of
`269cf91`, the first alpha.3 candidate.

F-43: `actions/attest` at the pinned `1e69f48` (v4.2.2) treats an
`sbom-path` file as CycloneDX only when `bomFormat`, `serialNumber` and
`specVersion` are all present (`src/sbom.ts`, `checkIsCycloneDX`; same in
its `dist/index.js`); otherwise the step fails with "Unsupported SBOM
format". cargo-cyclonedx 0.5.9 writes no `serialNumber` when
`SOURCE_DATE_EPOCH` is set, as both workflows do for reproducibility (it
writes a random one otherwise), and neither SBOM of rehearsal run
41055121744 had one; running the action's shipped
detection code on them gave that error. The rehearsal creates no
attestations, so it could not catch this. A tag of that candidate would
have failed in its attest job (fail closed, but it would have used up the
version).

F-44: the release SBOM job checked only format, package and a non-empty
component list; only the rehearsal compared the SBOM with `cargo tree`.
A faulty SBOM tool that dropped a dependency would have been attested.
(The check runs in the same untrusted job as the tool, so it catches
faults, not a malicious tool; see R-3.)

Fix: `scripts/finalize-sbom.py`, called identically by both workflows,
rewrites the checkout path, checks format, package, version and every
dependency `cargo tree --locked -e normal,build --target T` resolves,
refuses a generator-supplied serial (it would be random per run, so a run
without `SOURCE_DATE_EPOCH` fails), refuses NaN/Infinity (literal or
overflowing, such as `1e999`), duplicate JSON keys, components without a
string name and a dependency list naming only the root, adds `urn:uuid:` +
UUIDv5(URL namespace, repository/commit/version/target), then checks its own
encoded output before creating the output file: the action's 16 MiB size
limit, its format rule and an RFC 4122 serial pattern. (It also re-parses the
bytes strictly, but output the script encoded itself cannot fail that, so in
effect this is a size and format check.) A rejected SBOM leaves no file
behind. `scripts/test-finalize-sbom.py` (58 checks; runs in CI, the
rehearsal and the release SBOM job) covers determinism, the fixed output
layout including the exact `"bomFormat": "CycloneDX"` text
`verify-release.sh` greps for, every input changing the serial, SemVer
pre-release/build versions, and rejection of each of those inputs by the
check that names it, plus wrong package/version/format, generator serials,
bad arguments, and absent, malformed, foreign or SPDX-confusable serials.
Two separate-context internal reviews of the fix (AI-assisted, not
independent) found no fail-open issue; their LOW/INFO items are fixed. A
32-mutation sweep of the final script, including every surviving mutation
those reviews reported, caught 29; the three survivors of that sweep are
equivalent (`allow_nan=False` behind the finite-number parse check,
`UnicodeEncodeError` already a `ValueError`, and reading the ASCII
crate-name list as ASCII). A later review of the final commit found a
mutation the sweep did not include, the size boundary `<=` changed to `<`
(FB-1); a test now pins that an SBOM of exactly the limit is accepted. It
passes and gives byte-identical output on
Python 3.9 to 3.15 and under `LC_ALL=C`. Locally, the exact SBOM step text
of both workflows produced byte-identical SBOMs for both targets, which the
action's shipped detection code accepts; a cargo-cyclonedx shim that drops
`libc` makes the release step fail with nothing written.

Residual: the completeness check compares crate names, not versions (as the
rehearsal did); the SBOM job remains untrusted (R-3). The tag-only attest
step has still not run; the first tag's attest log and `verify-release.sh`
remain the proof.

### F-42 — LOW — attest job trusts artifacts by name (fixed, verified on the v0.1.0-alpha.3 tag run)

Found by the internal review of the SBOM branch (suspected, not
demonstrated). The release `attest` job downloads `sigsieve-<target>`
artifacts by name. `actions/upload-artifact` can overwrite an artifact of
the same name, so a job that obtained the workflow's Actions runtime token
(for example a compromised build or SBOM tool on a hosted runner, which has
passwordless sudo) could replace an archive and its checksum before the
attest job runs. The attest job's exact-contents check would pass and build
provenance would be recorded for the replaced file. Publishing stays manual,
and the exploit needs a compromised tool and runner-token extraction.

Fix (in `release.yml`; its tag-only path has not run yet):

- Each build target is its own job (a one-entry matrix sharing the
  unchanged build steps through a YAML anchor) instead of a leg of one
  matrix. Matrix legs share one set of job outputs, and a runner reports its
  own outputs, so a compromised runner of one leg could have rewritten the
  other leg's values.
- Each build job outputs its upload's artifact ID and zip digest (from
  `actions/upload-artifact`) and the archive's own SHA-256; the SBOM job
  outputs its artifact ID and digest.
- The attest job (now with read-only `actions: read`) validates those
  outputs, then requires the run's artifact list to contain exactly one
  artifact per expected name, with that ID, digest and run ID and not
  expired. It downloads each artifact by that single ID without a token
  (this run only), undecompressed, and hashes the zip against the producing
  job's digest before unpacking: `download-artifact`'s own digest check uses
  the server's listing and is skipped when that is empty. After the
  exact-contents check, each archive must match its build job's SHA-256, so
  a replacement with a self-consistent `.sha256` fails.
- Before extracting any zip (R-3 of the fix review; the SBOM job runs
  third-party tooling), every entry must be a regular file by its Unix mode
  whose name is exactly one of the expected names. Symlinks, directories,
  absolute paths, `..`, path separators, NUL bytes, duplicates, unexpected
  and missing names are rejected and nothing is extracted.
- Extraction no longer uses `unzip` (C-1 of the combined-branch review, LOW,
  suspected: the attest job holds the OIDC token while parsing zip bytes the
  SBOM job chose). The same Python `zipfile` object that performed the entry
  check writes only those regular-file entries, by their exact expected
  names, into a directory it creates, each opened with
  `O_CREAT|O_EXCL|O_NOFOLLOW`; zipfile checks each entry's CRC. Total
  output is capped at 256 MiB (declared sizes before anything is written,
  and the bytes actually written), so a crafted zip cannot fill the disk
  (review C1-1, INFO). Fixed.
- The release rehearsal mirrors the per-target job split and job names and
  adds a `verify` job (`contents: read`, `actions: read`; no OIDC, no
  attestation). It reads attest's two check scripts from the checked-out
  `release.yml` and runs them unmodified on the rehearsal's artifacts (with
  `GITHUB_REF_NAME` set to `rehearsal-<sha12>`), runs the synthetic test,
  and checks via the jobs API that the build jobs render the names
  `scripts/verify-release.sh` expects.
- `scripts/test-attest-inputs.sh` runs those steps from the workflow file
  against synthetic artifacts: the genuine case passes; a wrong ID, a digest
  mismatch, a replaced download, a replaced archive with a self-consistent
  checksum, a duplicate or missing artifact name, every empty or malformed
  output, the other target's outputs, another run's or an expired artifact,
  a wrong number of downloaded files, and each bad zip entry kind each fail
  with their own error.

Residual: a compromised build job can still replace its own target's
archive before uploading it (the binding proves which job uploaded an
artifact, not that the job was honest). The service is trusted to report
job outputs and artifact metadata faithfully. A full re-run of a release
run likely fails the binding: the run's artifact list may then hold
earlier attempts' artifacts under the same names (R-2). That fails closed;
re-run only the attest job (not yet tried on a hosted run), or push a new
tag. Hosted evidence will come from
the rehearsal `verify` job on the pull request once it has passed, which does not exercise
the attest job itself, the OIDC token or the tag trigger. F-42 therefore
stays a next-tag blocker until the first tag's attest log confirms the
binding: the binding step passed and all three downloads were by artifact
ID. The maintainer's
`scripts/verify-release.sh` run and native smoke test stay mandatory before
publishing.

The same review found that merging every `sigsieve-*` artifact into one
directory let the new SBOM job add or shadow an archive. That was fixed on
the same branch before merge, by downloading each artifact into its own
directory and checking its exact contents, so it has no separate entry.

### F-41 — LOW — RSA binding self-test gave false assurance

After legacy RSA/SHA-1 signing was refused (F-38), the `doctor`/`connect`
unbound allowed-key probe still used flags `0`. With RSA as the first exposed
identity, algorithm validation rejected that probe even when destination
binding was disabled. The self-test could therefore report binding verified
without detecting missing enforcement. This was a diagnostic gap, not an
observed authentication bypass.

The probe now selects `SSH_AGENT_RSA_SHA2_256` for RSA, retaining zero flags
for other key types. `binding_self_test_rejects_missing_enforcement_for_rsa_and_other_keys`
exercises the actual shared self-test against both proxy modes: it must catch
a filtering-only proxy when binding is expected, and pass against a binding
proxy without sending a sign request upstream. It failed before the fix and
passes for RSA, ECDSA P-256 and Ed25519. Agents and keys are synthetic.

### F-40 — LOW — slow reader extends the downstream write timeout

Replies were written with a blocking `write_all` and `SO_SNDTIMEO`. That
timeout bounds each wait for buffer space, and BSD/macOS restarts it whenever
the peer drains a little, so a client reading a few bytes at a time kept one
large reply (for example an identity list with a long comment) in progress
indefinitely. The connection stayed non-idle and could not be evicted, holding
one of the instance's client slots: the same outcome as F-17, without needing
a request. Found by an independent review of the resource code; the first
fix attempt (a deadline around blocking writes) was disproved by the test.
Fix: replies are written nonblocking by `write_frame_until` under one deadline
of `write_timeout` for the whole reply. Regression:
`slow_reader_cannot_extend_the_reply_write_deadline` (250 KB reply, client
reading 1 KB every 50 ms) received the whole reply before the fix and is cut
off after about one second with it.

### F-01 — HIGH — ControlMaster reuse
- **Component:** `src/cli.rs` (`connect`).
- **Preconditions:** connection sharing in ssh_config and an existing master
  with agent forwarding (e.g. started by `ssh -A host`).
- **Impact:** a multiplexed session asks the master to forward *its* agent —
  the unfiltered upstream — while SigSieve's `ForwardAgent` check passed.
- **Reproduction:** start a master with `-o ForwardAgent=yes`, then
  `sigsieve connect` with the same ControlPath; remote `ssh-add -l` showed all
  keys (reproduced against a local sshd with the fix removed).
- **Root cause:** `ssh -G` reports the client's ForwardAgent value, not what a
  master would forward.
- **Mitigation:** `-o ControlPath=none -o ControlMaster=no` first; verify no
  sharing remains in the effective config.
- **Fix:** `750d371`. **Test:** `existing_control_master_with_full_forwarding_is_not_reused` (real sshd; fails without the fix).
- **Residual:** none known for sharing.

### F-02 — HIGH — indirect ProxyCommand
- **Component:** `src/ssh.rs` (`proxycommand_is_ssh_relay`, `verify_ssh_plan`).
- **Preconditions:** a ProxyCommand that starts a nested ssh session indirectly
  (`/usr/bin/env ssh -A …`, `sh -c '…'`, `-W` inside a comment, wrappers) and
  an `IdentityAgent` pointing at the unfiltered agent (Secretive's documented
  setup).
- **Impact:** the nested ssh forwards the full agent to the bastion; setting
  `SSH_AUTH_SOCK` to the filtered socket does not prevent it (reproduced).
- **Root cause:** command-word heuristics are bypassable.
- **Mitigation:** fail closed — refuse every ProxyCommand except a plain
  `ssh … -W …` relay without shell syntax; ProxyJump allowed.
- **Fix:** `84592e3`. **Tests:** `only_plain_ssh_w_relays_are_accepted`, `connect_refuses_unsafe_effective_ssh_configuration`, `connect_with_real_ssh_config_overrides`.
- **Residual:** ProxyCommand users must use ProxyJump or the manual workflow.

### F-29 — HIGH — unverified proxy hops (audit C-1)
- **Component:** `src/ssh.rs` (`verify_proxy_chain`, `ssh_effective_config`).
- **Preconditions:** a ProxyJump (or `ssh -W` relay) hop whose own ssh_config
  has a wrapper ProxyCommand, LocalCommand or KnownHostsCommand, or a
  `Match exec`; and agent forwarding to some host in the user's config.
- **Impact:** each hop runs its own ssh, which reads ssh_config for that host,
  inherits the session environment (including the login agent) and does not
  receive connect's `-o` options. The F-02 check ran on the destination only,
  so a wrapper on the jump host ran inside the session and a nested
  `ssh -A` resolved to `forwardagent yes` with the unfiltered agent
  (reproduced). `--dry-run` reported "all checks passed".
- **Fix:** rebuild every hop's command as ssh does (ProxyJump: ssh.c's
  `ssh [-l] [-p] [-J rest] [-F file] -W '[%h]:%p' host`; relays: getopt-parsed
  ProxyCommand words), evaluate it with `ssh -G -v` and the session
  environment, and require a stdio relay, no local commands and recursively
  verified proxies; refuse KnownHostsCommand and `Match exec` everywhere,
  loops and chains over 8 hops. The relay check now parses ssh's argv, so
  `ssh -l -W bastion nc %h %p` (no relay) is refused, and a relay's `ssh`
  must resolve to the same program connect runs (it is verified with it).
- **Tests:** `connect_verifies_every_proxy_hop` (fails on the old code),
  `verified_proxyjump_still_connects_and_filters` (real sshd hop).
- **Residual:** options ssh does not expose in `ssh -G` (e.g. askpass,
  PKCS#11 providers) are out of scope. (The first fix let `Match exec` run
  once during verification; see F-30.)

### F-31 — HIGH — gaps found by the independent review of F-29/F-30
- **G1:** nested hops of an `ssh -F other -W` relay were evaluated with
  connect's `-F` instead of `other`; a hop2 ProxyCommand ran with the login
  agent. Fix: each hop is evaluated with the `-F` its own ssh reads
  (ProxyJump: the parent's; relay: its own command line's).
- **G3:** a hop's own forwardings (`ClearAllForwardings no` +
  `RemoteForward` of the agent) passed; live, the bastion listed hidden keys.
  Fix: every hop must report `clearallforwardings yes` and no forwards.
- **G5:** the `Match exec` scan stripped only double quotes. Fix: single
  quotes and backslashes too, then a word match (`Match host executor…` is no
  longer a false refusal); any quoted `Include` is refused.
- **G4:** `-X`/`-Y`/`ForwardX11 yes` made ssh run `XAuthLocation` with the
  login agent in `SSH_AUTH_SOCK`. Fix: `ForwardX11=no` is forced and verified.
- **G2:** ssh pastes `-F` unquoted into its ProxyJump shell command. Fix:
  `-F` paths with shell-relevant characters are refused when a hop needs them.
- **Recovery race:** concurrent recovery could remove a newer socket in the
  stat-then-unlink window (two winners, ~3% under load). Fix: check, recover
  and bind run under an exclusive `flock` on the socket directory.
- **Tests:** new cases in `connect_verifies_every_proxy_hop` (fail on the
  previous code); 400 consecutive `tests/socket.rs` runs without failure.
- **Residuals (documented):** `-q`/`-E` in your ssh arguments silence the
  `-v` second line of defence (the pre-scan is the primary check); PKCS#11 /
  security-key provider libraries are trusted like ssh itself.

### F-30 — MEDIUM — `Match exec` executed during verification
- **Component:** `src/sshconfig.rs`, `src/cli.rs` (`connect`).
- **Impact:** `ssh -G` runs `Match exec` commands while evaluating the
  configuration, so connect's verification executed the command once before
  refusing (reproduced with a marker command).
- **Fix:** before any `ssh -G` (the destination and every hop, with that
  hop's `-F`), scan the user configuration and its includes; any `Match`
  line mentioning `exec`, or an include the scan cannot resolve exactly as
  ssh would, is refused. Over-approximating by design.
- **Tests:** `sshconfig::tests::*`; `connect_verifies_every_proxy_hop`
  asserts the marker command never ran (fails with the scan disabled).
- **Residual:** the system-wide ssh_config is trusted (root-owned; its path
  depends on how ssh was built).

### F-03 / F-04 / F-09 / F-10 / F-11 — `connect` configuration leaks
- RemoteForward of the agent (any spelling) → `ClearAllForwardings=yes` first
  and verify no forwards remain (`ce53ee7`).
- ProxyCommand children inheriting `SSH_AUTH_SOCK` → login agent via
  `IdentityAgent=${SIGSIEVE_LOGIN_AGENT}`, `SSH_AUTH_SOCK` = filtered socket
  (`750d371`, `ce53ee7`).
- LocalCommand receives the login agent → `PermitLocalCommand yes` refused
  (`84592e3`).
- Silent forward dropping → warning (`84592e3`).
- `${SSH_AUTH_SOCK}`-based IdentityAgent configs → recognised (`ce53ee7`).
- **Tests:** `connect_refuses_unsafe_effective_ssh_configuration`, `connect_with_real_ssh_config_overrides`, `connect_forwards_only_the_filtered_socket_and_cleans_up`.

### F-05 / F-06 / F-17 — connection exhaustion
- 32 idle connections locked out all clients (reproduced) → evict the
  longest-idle connection (`750d371`); eviction then cut paused logins and
  could evict a just-read request (reproduced) → only evict after ≥ 5 s idle,
  drop requests on evicted connections (`ce53ee7`).
- **Tests:** `idle_connections_cannot_lock_out_new_clients`, `briefly_paused_connections_are_not_evicted`, `busy_connections_are_not_evicted_and_new_client_is_refused`.
- **Residual (F-17):** 32 *active* connections still saturate an instance
  (reproduced); `connect` uses one instance per host. Token budgets now bound
  connection/request churn and signing attempts. FIFO admission limits upstream
  I/O to four exchanges, including a deadline for queued requests. These bounds
  do not identify independent actors behind one forwarded socket or guarantee
  availability to a legitimate client when that endpoint is compromised.

### F-07 / F-08 — lifecycle and output hygiene
- Signals honoured before ssh starts; ssh stopped with SIGTERM then SIGKILL
  (`750d371`). Tests: `terminating_connect_stops_ssh_and_cleans_up`.
- Shell-quoted output, escaped comments, truncated extension names, newline
  rejection (`750d371`). Tests: `run_prints_shell_quoted_socket_path`,
  `doctor_escapes_control_characters_in_comments`.

### F-12 — documentation error
Early docs claimed upstream destination-constrained keys would be bypassed;
reproduction showed OpenSSH's agent refuses them on unbound connections
(fails closed). Corrected (`750d371`); test
`destination_constrained_keys_fail_closed_through_proxy`.

### F-13 — accept latency (found by benchmark)
Idle accept loop slept 25 ms → ~28 ms per new connection. Now waits with
`poll(2)` (`bd9045e`): ~72 µs. Measured in `tests/bench.rs`.

### F-14 / F-15 / F-16 — engineering defects found during hardening
- Deprecated API visible only with a newer lockfile (`ad1c843`).
- Seeds under a git-ignored path; a fresh clone would fail the fuzz test →
  moved to `fuzz/seeds` (`734ceaa`), verified with a fresh-clone test run.
- Misleading binding error for RSA host keys (`4075286`); test
  `forged_or_mismatched_bindings_are_rejected`.

### F-21 — LOW — binding self-test (fresh-context review)
In destination-binding mode, the `doctor`/`connect` self-test only proved
identity filtering. Now it also sends an allowlisted-key sign request on an
unbound connection and requires refusal (refused before the agent is
contacted, so no Touch ID). Test:
`doctor_verifies_destination_binding_without_reaching_the_agent`
(mutation-checked: fails if binding enforcement is removed).

### F-22 — LOW — replay triggers upstream prompts
A malicious remote host with a valid authentication binding to an allowed
destination can replay captured bind+sign sequences; each produces a useless
signature over a stale session but may trigger the upstream agent's user
presence prompt. A shared signing budget now limits attempts to a burst of 32
and refill of 4/s; the upstream's own confirmation policy still applies.
After full authorization, a destination-bound attempt is remembered by its
verified (session id, key) pair across connections, including failed
upstream attempts, so other bytes of the request (user name, RSA algorithm)
cannot buy another attempt (F-47; the flags were already excluded). Only 256 pairs for up to 300
seconds are kept; there is no cached signature response. New sessions,
eviction/expiry and a new instance can bypass this suppression. This is
bounded abuse reduction, not a replay-proof protocol.
Tests: `production_signing_budget_bounds_a_burst_without_changing_authorization`,
`destination_bound_duplicates_do_not_reach_upstream_on_another_connection`.

### F-47 — LOW — replay cache bypassed by username variation (mitigated on `main`, unreleased)
Found by an internal (AI-assisted) review on 2026-11-03, reproduced on the
source of `main` `11cc3c1` and re-verified on `dc88af7`. `parse_userauth_request` (`src/binding.rs`) reads
and ignores the username; the duplicate-attempt cache hashes the whole
request. A party that holds an authorized session's binds and userauth
request can replay them on new connections with a different username each
time. In a probe on the source of `main` `dc88af7` with the committed
recorded session (each replay on a new connection with both binds; mock
upstream): five identical replays gave one signature (the cache works),
five username variants gave five signatures (each a possible user-presence
prompt), every forwarded request carried the recorded session identifier,
and a variant without the binds was refused. The signatures are over the
original session identifier; this does not demonstrate authentication to a
different session; the impact is the same as F-22 (extra
upstream signing and prompts), now limited only by the shared signing budget
(burst 32, refill 4/s), not by the cache. The original alpha.4 release notes
stated "at most one upstream signature per recorded session"; that was
corrected by a [security erratum](https://github.com/semihbugrasezer/sigsieve/releases/tag/v0.1.0-alpha.4) on 2026-11-03. The claim was not
correct even before this finding (expiry, eviction and new instances, per F-22); this
variant removes the remaining per-window limit. Not measured: the production signing budget's effect and
real-agent prompts. Candidate fix (not implemented): cap signatures per
(session id, key) independently of the request bytes. Whether any
legitimate OpenSSH flow signs twice with one key in one session (for example
algorithm fallback) must be measured before choosing the cap;
the cap needs its own expiry and size bound, and it is bypassed by eviction
just like the current cache. It needs a regression test that fails without
the cap and real-OpenSSH login tests before release.

Mitigation (unreleased; independent review pending, release gate S3 open):
the duplicate-attempt cache is keyed on the verified (session id, key) pair
instead of the request bytes, with the same window, size and failure
handling (`src/proxy/resources.rs`). This also closes an RSA variant found
while measuring: `rsa-sha2-256` and `rsa-sha2-512` requests for one session
were two digests. A replayed session now yields at most one signature per
key and window, which is the F-22 bound; F-22 stays open. Legitimate OpenSSH
flows were measured first (2026-11-03, OpenSSH 10.5p1, macOS arm64): at most
one signature per session and key, none refused. RFC 4252 permits more, so
the cap is an intentional compatibility restriction, evaluated in
[SSH_COMPATIBILITY.md](SSH_COMPATIBILITY.md#one-signature-per-session-and-key).
Regression tests fail on the unfixed code (user-name, RSA-algorithm and
concurrent variants signed) and pass with the cap:
`f47_user_name_variants_of_a_recorded_session_get_no_further_signature`,
`rsa_algorithm_variants_share_one_signature_per_session`,
`concurrent_user_name_variants_admit_exactly_one_signature`,
`failed_upstream_attempt_blocks_its_session_not_recovery`,
`legitimate_flows_keep_working_under_the_session_key_cap`, and the
real-OpenSSH replay in `concurrent_real_sessions_interruption_and_replay`.

### F-24 — process — sensitive strings
A real host alias and a real-looking username were committed in two
unpushed commits on the feature branch (a doc line, a test vector and a seed
derived from it). Fixed in the tree (`2a63771`) and the commit scan is now a
hard gate. Public history was created from a clean Core snapshot; the old
internal feature history was not pushed. Do not publish those internal branches.
Existing public history and tags have not been rewritten.

### F-18 / F-19 / F-20 — resource and filesystem hardening

- **F-18:** `socket::connect_until` uses a nonblocking owned descriptor, poll
  and SO_ERROR for EINPROGRESS, and refuses full-queue Linux AF_UNIX EAGAIN
  immediately. `Upstream::request_until` uses the same absolute deadline for
  queue wait, connect, writes and the entire response; partial progress does
  not extend it. Cancellation is checked between nonblocking operations.
  Red/green: `trickling_reply_cannot_restart_the_request_deadline`. Native
  Linux backlog test: `full_unix_listen_queue_cannot_block_upstream_connect`;
  Linux kernel mechanism separately reproduced in a bounded offline container.
  Metadata calls/kernel/scheduler stalls remain outside hard real-time bounds.
- **F-19:** global 16 detail lines/s plus suppression summary; no payloads,
  session IDs or extension names. Regression: `hostile_requests_produce_bounded_logs_without_payloads`.
- **F-20:** private leaf plus canonical ancestor ownership/mode checks,
  permitting trusted sticky temporary directories. Red/green:
  `writable_ancestor_is_refused_even_with_a_private_socket_parent`.
  Portable Unix socket bind has no dirfd-relative API. No global fchdir or new
  privileges were added; same-uid mutation and extended ACL grants remain
  documented limits rather than claiming complete pathname race immunity.

### F-36 / F-37 — protocol and host-verification policy

RSA SHA-2 flags on ECDSA/Ed25519 formerly reached the mock upstream. They now
fail locally, as required by RFC 9987; RSA flags and zero-flag non-RSA signing
remain covered by positive tests. This was a protocol defect, not evidence of
an authorization bypass. Legacy RSA flag-zero SHA-1 was left upstream-dependent
here; F-38 closes it.

`connect` formerly accepted `StrictHostKeyChecking=no/off/false`; the real
OpenSSH dry run demonstrated acceptance. Target and every proxy hop now refuse
it. `ask`, `yes` and trust-on-first-use `accept-new` are preserved. This is an
explicit alpha compatibility change; no SSH setting is silently rewritten.

### F-39 — LOW — lossy home directory in the ssh_config pre-scan

`socket::home_dir` reads the home directory from the password database (as
ssh does for `~`) but converted it with `to_string_lossy`. A home whose name is
not valid UTF-8 became a different path containing U+FFFD; the pre-scan then
found no `~/.ssh/config` there and passed (missing files are skipped, as ssh
does), while ssh read the real file, so a `Match exec` in it went unchecked.
Preconditions: a non-UTF-8 home path in the password database; this is rare
and not attacker-controlled, so it is a fail-open correctness defect rather
than an exploitable bypass. Fix: build the path from the exact bytes
(`OsStr::from_bytes`). Regression: `home_dir_bytes_are_preserved_exactly`
fails on the lossy conversion and passes with the fix.

### F-38 — LOW — legacy RSA/SHA-1 signing

An RSA sign request with flags 0 asks for an `ssh-rsa` (SHA-1) signature, and
real `ssh-agent` produces one; `ssh-keygen -s -U -t ssh-rsa` demonstrated it
through SigSieve. The proxy now derives the one acceptable signature algorithm
from key type and flags (`KeyType::signature_alg`): RSA needs exactly one of
rsa-sha2-256/512, other types none. The upstream reply must use that algorithm,
so an agent that ignores the flags cannot return SHA-1 either, and
destination-bound userauth no longer accepts `ssh-rsa`. There is no silent
fallback or legacy switch; OpenSSH has disabled `ssh-rsa` by default since 8.8.
Compatibility cost: peers accepting only `ssh-rsa` (OpenSSH < 7.2) cannot use
RSA keys through SigSieve. Regressions: `rsa_requires_exactly_one_sha2_flag`,
`signatures_with_an_unrequested_algorithm_are_refused`,
`rsa_userauth_must_name_a_sha2_algorithm` and real OpenSSH
`rsa_sha1_signing_is_refused_while_sha2_works` (upstream control signs SHA-1).

### F-32 — HIGH — SSH configuration tokenization mismatch

OpenSSH accepts a quoted keyword followed immediately by its argument, such
as `"Match"exec`, and keeps `=` and non-space/tab characters inside Include
paths. The earlier scan merged quoted keywords or split those paths,
missing a `Match exec` that SSH then executed while probing configuration.
The verbose-output check detected execution too late. Reproduced with
throwaway configuration files and marker commands.

The scan now refuses quoted/escaped keywords and non-UTF-8 configuration,
handles the optional keyword `=` once, and splits Include paths on the same
ASCII space/tab delimiters as SSH. Regression tests cover direct and included
commands, `=` paths, NBSP and embedded CR/VT/FF. Real OpenSSH tests require
refusal before the marker command runs in both dry-run and connect modes.

### F-33 — LOW (supply chain) — withdrawn transitive dependency

The first public CI run rejected `crypto-bigint 0.7.6` as yanked, while
`cargo audit` reported no known advisory. The [upstream changelog](https://github.com/RustCrypto/crypto-bigint/blob/master/CHANGELOG.md)
records withdrawn 0.7.6–0.7.8 versions and the 0.7.9 correction. Both the Core
and fuzz lockfiles now select 0.7.9. The advisory/license policy is unchanged;
acceptance requires fresh cryptographic verification tests and exact-commit CI.

### F-34 — HIGH — forwarding-context loss in destination binding

The earlier authorization rule allowed ordinary `publickey` when only one
binding was recorded. A failed initial forwarding bind (for example an
unsupported RSA host key) left no binding, and a later valid authentication
bind could replace it. Older forwarding clients can also omit the initial
binding. OpenSSH's client source confirms forwarding can continue after a
bind failure. In the threat-model case where an attacker owns an allowed
host key, the attacker could sign another server's session identifier with
that key and reach the first-hop exception without a host key in the signed
userauth request.

The proxy now requires hostbound authentication for every destination-bound
signature, including single bindings. An initial failed bind is also terminal
for that connection. Existing valid state is retained after a subsequent
failure. Both regression conditions failed before their fixes; valid
single-binding hostbound requests and normal forwarded E2E flows remain tested.

Tests: `failed_bind_disables_signing_and_single_hop_requires_hostbound`,
`failed_initial_binding_cannot_be_replaced_by_an_authentication_bind`, and
`attacker_holding_a_permitted_host_key_cannot_redirect_forwarded_auth`.

### F-35 — HIGH — keyword delimiter mismatch in alpha.1 candidate

OpenSSH accepts a CR between `Include` and its path (also after whitespace or
`=`). The scanner used a narrower keyword delimiter and could skip the real
include. A throwaway `ssh -G` fixture executed the included marker command;
the new unit regression failed on the candidate.

Alpha.2 rejects control characters except LF/tab before parsing and requires
ASCII keywords. Include arguments with quotes, escapes or inline comments
are refused. Wildcard basenames must be ASCII and `?` is over-approximated as
`*` to avoid locale-dependent false negatives. Tests cover the CR variants
and require refusal before any marker runs in dry-run and connect modes.
Hostname canonicalization and state-dependent Match criteria are also refused
on the destination and every hop, keeping effective configuration independent
of DNS/network/final-pass changes. The alpha.1 build was cancelled and no
GitHub Release was published for it.
