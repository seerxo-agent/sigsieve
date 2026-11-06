# SigSieve

**Least-privilege SSH agent forwarding for macOS and Linux.**

[![CI](https://github.com/semihbugrasezer/sigsieve/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/semihbugrasezer/sigsieve/actions/workflows/ci.yml)
[![Releases](https://img.shields.io/badge/GitHub-releases-blue)](https://github.com/semihbugrasezer/sigsieve/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

SigSieve is an open-source, local SSH-agent filtering proxy. It lets you **forward selected SSH identities instead of your entire agent**, with optional restrictions on the destination host keys those identities may authenticate to.

Your existing agent—such as [Secretive](https://github.com/maxgoedjen/secretive) or OpenSSH `ssh-agent`—retains the private keys and performs signing. SigSieve enforces its policy in front of that agent; it does not store or export private keys.

**Free and MIT-licensed. No account, telemetry, hosted service, or mandatory cloud dependency.**

> [!WARNING]
> **Not independently audited.** Automated security tests do not establish production-grade security assurance. Real Secretive filtering, signing and destination binding were checked with the `v1.0.0-rc.1` binary for **one** configuration only (one P-256 test key, Secretive 4.0.0, macOS 27.2 arm64, localhost test servers); other devices, Secretive versions and real services are not covered ([details](docs/SECRETIVE_INTEGRATION.md#recorded-real-device-results)). Read the [security model](docs/SECURITY_MODEL.md) and [known limitations](docs/LIMITATIONS.md) before using agent forwarding, and retain an ordinary SSH access path.

## Why SigSieve?

SSH agent forwarding can give processes on a remote machine access to identities exposed by your local agent for the lifetime of the connection. SigSieve is designed to reduce that exposure without requiring you to move or export a private key.

- **Explicit identity allowlist.** Permit keys by SHA-256 public-key fingerprint. Non-allowlisted identities are not listed or authorized for signing through the proxy.
- **Optional destination binding.** Restrict permitted signing to compatible, hostbound SSH authentication at approved destination host keys.
- **Fail-closed agent protocol.** Refuse unsupported operations, including adding/removing identities, locking/unlocking, PKCS#11 operations, and unknown requests.
- **Keep your agent.** Work with an existing Unix-socket SSH agent; SigSieve does not become a key store.
- **Operator-friendly CLI.** Inspect filtering with `doctor`, preview SSH connections with `connect --dry-run`, or serve a dedicated filtered socket with `run`.

### How it works

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

## Install

For macOS Apple Silicon, install the published Homebrew formula:

```sh
brew install semihbugrasezer/sigsieve/sigsieve
sigsieve --version
```

For a prebuilt archive, follow the [verified installation guide](docs/INSTALL.md). Its pinned archive example checks the checksum, a separately pinned SHA-256 digest, and GitHub build provenance before installation. Check the version it names before running it.

| Platform | Distribution |
| --- | --- |
| macOS ARM64 (Apple Silicon) | Prebuilt archive; Homebrew source build |
| Linux x86_64 (Ubuntu 24.04 / glibc 2.39 baseline) | Prebuilt archive |
| Linux ARM64 | CI-tested; build from source |
| Intel macOS / Windows | Not validated |

The [tap](https://github.com/semihbugrasezer/homebrew-sigsieve) builds a pinned immutable tag from source and checks the source archive's SHA-256. Check `sigsieve --version` after installation or upgrade; the formula can advance separately from GitHub release assets. That checksum is **not** GitHub build provenance; use the prebuilt archives and the installation guide if you need provenance verification. Tested on macOS Apple Silicon only. Uninstall with `brew uninstall sigsieve && brew untap semihbugrasezer/sigsieve`.

The checkout pins Rust **1.99.1** for builds; the declared minimum supported Rust version is **1.88**. OpenSSH **8.4+** is required, with additional requirements for proxy hops and destination binding. There is **no crates.io package**, and macOS binaries are **not notarized**.

For a fully isolated demonstration without your own agent or remote hosts, start with the [five-minute synthetic-key quickstart](docs/QUICKSTART.md).

## First safe check with OpenSSH (Linux or macOS)

The following commands only inspect your local agent and preview an SSH connection. They **do not initiate a remote connection or request a real-key signature**.

```bash
upstream="${SSH_AUTH_SOCK:?Start or select an SSH agent first}"
SSH_AUTH_SOCK="$upstream" ssh-add -l

# Replace this placeholder with one of your agent's public fingerprints.
fp='SHA256:REPLACE_WITH_YOUR_KEY_FINGERPRINT'

sigsieve doctor --upstream "$upstream" --allow-fingerprint "$fp"
sigsieve connect build-host --upstream "$upstream" --allow-fingerprint "$fp" \
  --dry-run -- -o StrictHostKeyChecking=yes
```

Use an SSH alias in place of `build-host`. Verify the destination's host key through a trusted channel and inspect the dry-run plan before opening an actual connection. See [check, preview, connect, and cleanup](docs/USAGE.md#check-preview-connect).

## First session with Secretive (macOS)

If you use [Secretive](https://github.com/maxgoedjen/secretive), first inspect its **public** fingerprints locally:

```bash
SSH_AUTH_SOCK="$HOME/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh" ssh-add -l
```

Select one fingerprint and check the policy without connecting:

```bash
fp='SHA256:REPLACE_WITH_YOUR_KEY_FINGERPRINT'

sigsieve doctor --secretive --allow-fingerprint "$fp"
sigsieve connect build-host --secretive --allow-fingerprint "$fp" \
  --dry-run -- -o StrictHostKeyChecking=yes
```

After independently verifying the host key and reviewing the SSH plan, the corresponding real connection is:

```bash
sigsieve connect build-host --secretive --allow-fingerprint "$fp" \
  -- -o StrictHostKeyChecking=yes
```

A remote `ssh-add -l` should expose only the identity you allowed. Disconnect when forwarding is no longer needed. `connect` disables connection sharing, port forwarding, and X11 forwarding for the session. See [Secretive integration](docs/SECRETIVE_INTEGRATION.md) for caveats and device-test scope; **a successful automated OpenSSH test does not establish Touch ID behavior**.

## Protection and limits

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
- A recorded-session replay limitation remains documented; macOS cross-user testing and independent external auditing are not complete.

For the full boundary and evidence, see the [security model](docs/SECURITY_MODEL.md), [threat model](docs/THREAT_MODEL.md), [SSH compatibility matrix](docs/SSH_COMPATIBILITY.md), and [known limitations](docs/LIMITATIONS.md).

## Do you need it?

| Your goal | Consider first |
| --- | --- |
| Access a host through a bastion without forwarding agent credentials | OpenSSH [`ProxyJump`](https://man.openbsd.org/ssh_config#ProxyJump) |
| Choose a key for your own local SSH login | `IdentityFile`, `IdentityAgent`, and `IdentitiesOnly` |
| Forward only a few exportable keys | A dedicated `ssh-agent` loaded with only those keys |
| Restrict keys in OpenSSH's own agent | OpenSSH [`ssh-add -h` destination constraints](https://www.openssh.org/agent-restrict.html) |
| Forward one non-exportable identity from an existing agent | Evaluate SigSieve's filtering and its limitations |

## Verification and release integrity

The published **v0.1.0-alpha.4** release is pinned to source commit [`5ea37b73ce7ed5dd33f3ac405c3ae4ad4da68751`](https://github.com/semihbugrasezer/sigsieve/commit/5ea37b73ce7ed5dd33f3ac405c3ae4ad4da68751), not the moving tip of `main`. The `v1.0.0-rc.1` release candidate is pinned to [`c4fa7a5eeba0283dc14d73a87ff996b876050394`](https://github.com/semihbugrasezer/sigsieve/commit/c4fa7a5eeba0283dc14d73a87ff996b876050394); stable candidate checks must be repeated on its own commit.

| Evidence | What was verified |
| --- | --- |
| [Candidate CI](https://github.com/semihbugrasezer/sigsieve/actions/runs/41519403249) | Rust tests and real OpenSSH integration, including platform-specific checks |
| [F-46 Linux cross-user run](https://github.com/semihbugrasezer/sigsieve/actions/runs/41519403122) | Peer-credential restriction and its negative test; **not** a macOS cross-user test |
| [Release rehearsal](https://github.com/semihbugrasezer/sigsieve/actions/runs/41527758832) | Build, reproducible packaging, smoke checks, SBOM generation, artifact-binding checks |
| [Fuzz campaign](https://github.com/semihbugrasezer/sigsieve/actions/runs/41527783557) | Four targets, 3,600 seconds each; 287,516,615 executions with no reported crash |
| [Release build](https://github.com/semihbugrasezer/sigsieve/actions/runs/41538765784) | Published artifacts, SHA-256 checksums, CycloneDX SBOMs, and provenance attestations |
| [Linux release verification](https://github.com/semihbugrasezer/sigsieve/actions/runs/41540423408) | Native archive and verification checks |

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
