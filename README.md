# SigSieve

**Least-privilege SSH agent forwarding for macOS and Linux.**

[![CI](https://github.com/semihbugrasezer/sigsieve/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/semihbugrasezer/sigsieve/actions/workflows/ci.yml)
[![Releases](https://img.shields.io/badge/GitHub-releases-blue)](https://github.com/semihbugrasezer/sigsieve/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

SigSieve is a small local proxy in front of your SSH agent. When you forward your agent to a remote machine, the remote side sees **only the keys you allow**, and you can optionally limit signing to approved destination host keys.

Your keys stay in your existing agent, such as [Secretive](https://github.com/maxgoedjen/secretive) or OpenSSH `ssh-agent`, which still does all signing. SigSieve never stores or exports a private key.

**Free and MIT-licensed. No account, telemetry, hosted service, or mandatory cloud dependency.**

> [!WARNING]
> **Not independently audited.** Automated security tests do not establish production-grade security assurance. Real Secretive filtering, signing and destination binding were checked with the `v1.0.0-rc.1` binary (and, maintainer-reported, the `1.0.0` binary) for **one** configuration only (one P-256 test key, Secretive 4.0.0, macOS 27.2 arm64, localhost test servers); other devices, Secretive versions and real services are not covered ([details](docs/SECRETIVE_INTEGRATION.md#recorded-real-device-results)). Read the [security model](docs/SECURITY_MODEL.md) and [known limitations](docs/LIMITATIONS.md) before using agent forwarding, and retain an ordinary SSH access path.

## Install

**macOS (Apple Silicon), with Homebrew:**

```sh
brew install semihbugrasezer/sigsieve/sigsieve
sigsieve --version   # sigsieve 1.0.0
```

**Linux x86_64**, or if you want GitHub build provenance: use the [verified prebuilt archive](docs/INSTALL.md#verify-and-install-a-published-archive). The guide checks the checksum, a pinned SHA-256 digest and the build provenance before it installs to `~/.local/bin`.

**Linux arm64 or an older Linux:** [build the tagged release from source](docs/INSTALL.md#install-the-tagged-version-from-source) (Rust 1.88 or newer; the checkout pins 1.99.1).

| Platform | Distribution |
| --- | --- |
| macOS ARM64 (Apple Silicon) | Homebrew (source build); prebuilt archive |
| Linux x86_64 (Ubuntu 24.04 / glibc 2.39 baseline) | Prebuilt archive |
| Linux ARM64 | CI-tested; build from source |
| Intel macOS / Windows | Not validated |

Requires OpenSSH **8.4+**. Installation needs no `sudo` and changes nothing in `~/.ssh` or your agent. The Homebrew formula is tested on macOS Apple Silicon only, and its source checksum is **not** GitHub build provenance. macOS binaries are **not notarized**, and there is no crates.io package. Uninstall Homebrew with `brew uninstall sigsieve && brew untap semihbugrasezer/sigsieve`; other methods and details are in [INSTALL.md](docs/INSTALL.md).

## Quick start

Want to try it without touching your own keys first? The [five-minute synthetic-key quickstart](docs/QUICKSTART.md) uses a throwaway agent.

Steps 1 to 3 only inspect your local agent and preview a connection. They **do not connect to a remote host or sign with your key**.

### 1. Pick the key to allow

List the **public** fingerprints in your agent.

OpenSSH agent (Linux or macOS):

```bash
upstream="${SSH_AUTH_SOCK:?Start or select an SSH agent first}"
SSH_AUTH_SOCK="$upstream" ssh-add -l
```

Secretive (macOS):

```bash
SSH_AUTH_SOCK="$HOME/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh" ssh-add -l
```

Copy one `SHA256:…` fingerprint:

```bash
fp='SHA256:REPLACE_WITH_YOUR_KEY_FINGERPRINT'
```

### 2. Check the setup with `doctor`

Run **one** of these, for the agent you chose in step 1.

OpenSSH agent:

```bash
sigsieve doctor --upstream "$upstream" --allow-fingerprint "$fp"
```

Secretive:

```bash
sigsieve doctor --secretive --allow-fingerprint "$fp"
```

A working setup looks like this (shortened; output from a synthetic test key):

```text
Upstream agent:     reachable (1 identities)
Approved identities: 1/1 available
  available  ED25519 SHA256:0TP3VIKSTssvhtKyXhKYxiAIkC7T8T6MSTgzc2hdGKA demo
Hidden identities:  0 (not shown)
Filtering:          verified (temporary socket exposed 1 identity, non-allowlisted sign request rejected)

Result: all checks passed
```

`doctor` also prints a `denied sign request` line. That is its self-test with a synthetic key that is never allowed: it is expected, and it is not one of your keys. A failed check prints `FAIL` with a `hint:` line that says what to fix (see [Troubleshooting](#troubleshooting-and-support)).

### 3. Preview the connection

Replace `build-host` with your SSH host alias, and again run **one** command.

OpenSSH agent:

```bash
sigsieve connect build-host --upstream "$upstream" --allow-fingerprint "$fp" \
  --dry-run -- -o StrictHostKeyChecking=yes
```

Secretive:

```bash
sigsieve connect build-host --secretive --allow-fingerprint "$fp" \
  --dry-run -- -o StrictHostKeyChecking=yes
```

`ssh` is not started. The plan should include:

```text
SigSieve connect dry run (ssh not started)
Forwarded agent:     filtered socket only (verified with ssh -G)
Connection sharing:  disabled for this session
Port forwardings:    disabled for this session
Host key checking:   StrictHostKeyChecking=true (unknown or changed host keys are refused)
Result: all checks passed
```

### 4. Connect

First verify the destination's host key through a trusted channel and review the plan. Then run the same command **without** `--dry-run`.

OpenSSH agent:

```bash
sigsieve connect build-host --upstream "$upstream" --allow-fingerprint "$fp" \
  -- -o StrictHostKeyChecking=yes
```

Secretive:

```bash
sigsieve connect build-host --secretive --allow-fingerprint "$fp" \
  -- -o StrictHostKeyChecking=yes
```

`connect` turns off connection sharing, port forwarding and X11 forwarding for the session. On the remote host, `ssh-add -l` should list only the identity you allowed. Disconnect when you no longer need forwarding, and keep an ordinary SSH access path.

With Secretive, a passing automated OpenSSH test **does not establish Touch ID behavior**; see [Secretive integration](docs/SECRETIVE_INTEGRATION.md) for caveats and the tested scope. With destination binding, a cancelled Touch ID prompt cannot be retried on the same connection: connect again.

Next steps: destination binding (`--allow-destination`), a stable filtered socket for `ssh_config`, and the full CLI are in [USAGE.md](docs/USAGE.md).

## What it protects

SSH agent forwarding can give processes on a remote machine access to identities exposed by your local agent for the lifetime of the connection. SigSieve reduces that exposure without moving or exporting a private key.

- **Explicit identity allowlist.** Permit keys by SHA-256 public-key fingerprint. Non-allowlisted identities are not listed or authorized for signing through the proxy.
- **Optional destination binding.** Restrict permitted signing to compatible, hostbound SSH authentication at approved destination host keys.
- **Fail-closed agent protocol.** Refuse unsupported operations, including adding/removing identities, locking/unlocking, PKCS#11 operations, and unknown requests.
- **Keep your agent.** Work with an existing Unix-socket SSH agent; SigSieve does not become a key store.
- **Operator-friendly CLI.** Inspect filtering with `doctor`, preview SSH connections with `connect --dry-run`, or serve a dedicated filtered socket with `run`.

## Modes and limits

SigSieve has two modes. Identity filtering is the default; destination binding must be explicitly configured and requires compatible SSH hostbound authentication.

| Capability | Identity filtering | Destination binding (`--allow-destination`) |
| --- | --- | --- |
| Public identities visible through the proxy | Allowlisted only | Allowlisted only |
| Identities permitted to sign through the proxy | Allowlisted only | Allowlisted only |
| Permitted signing | Arbitrary agent signing requests for an allowed key | Compatible SSH user authentication bound to approved destination host keys |
| Unsupported or mutating agent operations | Denied | Denied |

**Know the boundaries:**

- A compromised remote host may still use an **allowed** identity while forwarding is active. Filtering alone does not constrain which servers trust that key.
- Destination binding restricts **final destination host keys**, not remote usernames or every intermediate hop; it requires compatible OpenSSH hostbound authentication. Generic signing (for example, `git commit -S`) is intentionally refused in this mode.
- SigSieve cannot secure a compromised local user account or upstream agent, replace host-key verification, or guarantee a separate Touch ID prompt for each signature.
- A recorded-session replay limitation remains documented, and independent external auditing has not been done. The cross-user check is tested on Linux and on one GitHub-hosted macOS image.

For the full boundary and evidence, see the [security model](docs/SECURITY_MODEL.md), [threat model](docs/THREAT_MODEL.md), [SSH compatibility matrix](docs/SSH_COMPATIBILITY.md), and [known limitations](docs/LIMITATIONS.md).

## How it works

```text
Remote SSH process (untrusted)
            │
            │ agent request via SSH forwarding
            ▼
    SigSieve (on your computer)
    ├─ public-key fingerprint allowlist
    ├─ optional destination/session policy
    └─ agent-protocol checks
            │ permitted requests only
            ▼
    Your existing SSH agent
    (Secretive or OpenSSH ssh-agent)
            │
            └─ private keys remain with the upstream agent
```

SigSieve filters *requests*, not the security policy of the remote machine or the upstream agent. The upstream agent remains responsible for any user-presence or approval prompts.

## Do you need it?

| Your goal | Consider first |
| --- | --- |
| Access a host through a bastion without forwarding agent credentials | OpenSSH [`ProxyJump`](https://man.openbsd.org/ssh_config#ProxyJump) |
| Choose a key for your own local SSH login | `IdentityFile`, `IdentityAgent`, and `IdentitiesOnly` |
| Forward only a few exportable keys | A dedicated `ssh-agent` loaded with only those keys |
| Restrict keys in OpenSSH's own agent | OpenSSH [`ssh-add -h` destination constraints](https://www.openssh.org/agent-restrict.html) |
| Forward one non-exportable identity from an existing agent | Evaluate SigSieve's filtering and its limitations |

## Troubleshooting and support

Each failed `doctor` check prints a `hint:` line. Common cases:

| Message or symptom | What to do |
| --- | --- |
| `upstream agent unreachable` | Start your agent (Secretive, or `ssh-agent`), or fix the path given with `--upstream` / `SSH_AUTH_SOCK`. |
| `none of the allowlisted identities is present` | That fingerprint is not in this agent. List the keys again (step 1). |
| The Linux binary stops with a `GLIBC_…` "not found" error | Your distribution is older than the glibc 2.39 baseline: [build from source](docs/INSTALL.md#install-the-tagged-version-from-source). |
| Destination-bound authentication fails | See the [troubleshooting table](docs/USAGE.md#troubleshooting) and [SSH compatibility](docs/SSH_COMPATIBILITY.md). |

All messages: [USAGE.md troubleshooting](docs/USAGE.md#troubleshooting). Removal: [uninstall and recovery](docs/USAGE.md#uninstall-and-recovery).

Report what you find. Remove real fingerprints, hostnames, IP addresses, user names and private paths first.

- Works or fails with your OS, OpenSSH or agent: [compatibility report](https://github.com/semihbugrasezer/sigsieve/issues/new?template=compatibility_report.yml)
- Installation fails: [installation problem](https://github.com/semihbugrasezer/sigsieve/issues/new?template=installation_problem.yml)
- Something does not work as documented: [bug report](https://github.com/semihbugrasezer/sigsieve/issues/new?template=bug_report.yml) · Questions: [usage question](https://github.com/semihbugrasezer/sigsieve/issues/new?template=usage_question.yml)
- **Suspected security vulnerability: never a public issue.** Use [private vulnerability reporting](https://github.com/semihbugrasezer/sigsieve/security/advisories/new) ([SECURITY.md](SECURITY.md)).

## Verification and release integrity

The stable **[v1.0.0](https://github.com/semihbugrasezer/sigsieve/releases/tag/v1.0.0)** release (published 2026-11-09, immutable) is pinned to source commit [`71ae5e95e666eeb3cb1b94b25ba6b0b8571eca35`](https://github.com/semihbugrasezer/sigsieve/commit/71ae5e95e666eeb3cb1b94b25ba6b0b8571eca35), not the moving tip of `main`.

| Evidence | What was verified |
| --- | --- |
| [CI](https://github.com/semihbugrasezer/sigsieve/actions/runs/42227739778) | Rust tests and real OpenSSH integration on macOS arm64, Linux x86_64 and arm64, MSRV 1.88 |
| [F-46 Linux cross-user run](https://github.com/semihbugrasezer/sigsieve/actions/runs/42231058235) | Peer-credential restriction and its negative test on Linux, for the release commit |
| [F-46 Linux + macOS cross-user run](https://github.com/semihbugrasezer/sigsieve/actions/runs/42638071593) | Same test on Linux and on a GitHub-hosted macOS 26.7.2 arm64 VM (2026-11-09, `main` `dc05602`; runtime source identical to v1.0.0, built in CI, not the released binary; this test covers only the peer-credential check) |
| [Release rehearsal](https://github.com/semihbugrasezer/sigsieve/actions/runs/42231048170) | Build, reproducible packaging, smoke checks, SBOM generation, artifact-binding checks |
| [Fuzz campaign](https://github.com/semihbugrasezer/sigsieve/actions/runs/42231052710) | Four targets, 3,600 seconds each; 392,384,646 executions with no reported crash |
| [Release build](https://github.com/semihbugrasezer/sigsieve/actions/runs/42286504497) | Published artifacts, SHA-256 checksums, CycloneDX SBOMs, and provenance attestations |
| [Linux release verification](https://github.com/semihbugrasezer/sigsieve/actions/runs/42291132708) | Native archive and verification checks |
| macOS arm64 release verification, Homebrew upgrade, Secretive device test with the 1.0.0 binary | Maintainer-reported; see the [release notes](https://github.com/semihbugrasezer/sigsieve/releases/tag/v1.0.0) |

Evidence is **specific to the tested revision** and is not a security certification. Full test descriptions and historical results are in [TESTING.md](docs/TESTING.md); remaining findings are in [FINDINGS.md](docs/FINDINGS.md).

## Documentation and contributions

| Start here | Reference |
| --- | --- |
| Installation and first use | [Install](docs/INSTALL.md) · [Synthetic-key quickstart](docs/QUICKSTART.md) · [Usage and troubleshooting](docs/USAGE.md) |
| Security | [Security model](docs/SECURITY_MODEL.md) · [Threat model](docs/THREAT_MODEL.md) · [Limitations](docs/LIMITATIONS.md) · [Report a vulnerability](SECURITY.md) |
| Technical details | [Architecture](docs/ARCHITECTURE.md) · [SSH compatibility](docs/SSH_COMPATIBILITY.md) · [Testing](docs/TESTING.md) · [Protocol references](docs/REFERENCES.md) |
| Project | [Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md) · [Support](SUPPORT.md) · [Code of conduct](CODE_OF_CONDUCT.md) |

Contributions, reproducible bug reports, and independent security review are welcome. Please review [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request, and use the private reporting channel described in [SECURITY.md](SECURITY.md) for suspected vulnerabilities. Do not post real agent listings, hostnames, or private-key material in public issues.

---

**License:** [MIT](LICENSE). See [third-party notices](docs/THIRD_PARTY.md) for distribution and dependency information.
