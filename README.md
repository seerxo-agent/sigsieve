# SigSieve

[![CI](https://github.com/semihbugrasezer/sigsieve/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/semihbugrasezer/sigsieve/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Forward only the SSH identities a remote host needs. Keep your existing agent and private keys.**

SigSieve is a local, open-source SSH agent filtering proxy for **macOS and Linux**. It exposes only identities explicitly permitted by SHA-256 fingerprint and, optionally, limits SSH authentication to approved destination host keys. Your existing agent (such as [Secretive](https://github.com/maxgoedjen/secretive) or OpenSSH `ssh-agent`) still performs signing. SigSieve neither exports private keys nor replaces your agent.

It is designed especially for forwarding non-exportable, Secure Enclave-backed identities from Secretive to a remote development or build host without exposing every identity in Secretive to that host.

> [!WARNING]
> **Experimental security software. Not independently audited.** The latest verified pre-release is [v0.1.0-alpha.4](https://github.com/semihbugrasezer/sigsieve/releases/tag/v0.1.0-alpha.4). Automated tests and internal AI-assisted reviews are **not** an independent security audit. A limited owner-assisted Secretive signing and destination-binding test passed on an **alpha.2** candidate; it has **not** been repeated for alpha.4, which changes runtime behavior. Real Secretive/Touch ID behavior in alpha.4, other devices, and external services remains unverified. Read the [security model](docs/SECURITY_MODEL.md) and [limitations](docs/LIMITATIONS.md), and keep ordinary SSH access available.

Free, MIT-licensed, local-first. No account, SaaS service, telemetry, or mandatory cloud infrastructure.

## How it works

```text
Existing agent          SigSieve                   OpenSSH              Remote host
(Secretive/ssh-agent) → filtered local socket → forwarded agent socket → allowed keys only
(all identities)          (allowlist)                                    (untrusted)
```

- **Allowlist by fingerprint:** only valid, explicitly allowlisted public keys can be listed or used through the filtered socket. An empty allowlist exposes nothing.
- **Optional destination binding:** approved keys may authenticate only to SSH sessions bound to allowed destination *host keys*, when compatible OpenSSH hostbound authentication is available.
- **Default-deny protocol handling:** mutation, key addition/removal, lock/unlock, PKCS#11, and unknown agent operations are refused instead of forwarded.
- **Existing agent stays in control:** Secretive or `ssh-agent` holds the key material and decides whether a permitted signature needs user confirmation.
- **Useful CLI:** `doctor` checks policy and filtering, `connect --dry-run` previews a connection, `connect` starts a filtered SSH session, and `run` serves a filtered local socket. See [CLI usage](docs/USAGE.md).

## Do you need it?

| Goal | Consider |
|---|---|
| Reach a server through a bastion without forwarding keys | OpenSSH [`ProxyJump`](https://man.openbsd.org/ssh_config#ProxyJump) first. |
| Select a key for your own SSH login | `IdentityFile`, `IdentityAgent`, `IdentitiesOnly`; these do **not** restrict all identities in a forwarded agent. |
| Forward a separately loaded subset of exportable keys | A dedicated `ssh-agent` containing only those keys. |
| Constrain keys already loaded into OpenSSH's agent | Native [`ssh-add -h` destination constraints](https://www.openssh.org/agent-restrict.html) (OpenSSH 8.9+). |
| Forward a non-exportable Secretive identity without exposing other identities | **SigSieve** may be useful; evaluate its limitations first. |

## Protection and limits

| | Identity filtering (default) | With `--allow-destination` |
|---|---|---|
| Remotely visible/usable identities | Allowlisted only | Allowlisted only |
| What an allowed identity may sign | Arbitrary data requested via the agent | Only compatible, hostbound SSH authentication for approved destination host keys |
| Agent mutations and unknown operations | Refused locally | Refused locally |

**Important:** A compromised remote host can still request signatures from an *allowed* identity while your forwarding session is active. In the default mode, it may use that identity at any server trusting the key. Destination binding narrows this to the approved destination keys; it does **not** prevent misuse at an approved destination, restrict usernames or intermediate hops, or guarantee a Touch ID prompt per signature. Hostbound mode also refuses generic signing such as `git commit -S` through the forwarded agent.

SigSieve cannot protect a compromised local account or upstream agent, replace SSH host-key verification, or safely promise compatibility with every server. Consult the [threat model](docs/THREAT_MODEL.md), [SSH compatibility matrix](docs/SSH_COMPATIBILITY.md), and [resource limits](docs/RESOURCE_LIMITS.md).

## Install

Download the **[v0.1.0-alpha.4 verified pre-release](https://github.com/semihbugrasezer/sigsieve/releases/tag/v0.1.0-alpha.4)** and follow the **[installation guide](docs/INSTALL.md)**. The guide checks SHA-256, pinned artifact digests, build provenance, and the source revision *before* installation; do not install an unverified CI artifact as though it were a release.

| Environment | Availability |
|---|---|
| macOS Apple Silicon (arm64) | Verified experimental release archive |
| Linux x86_64 (Ubuntu 24.04 / glibc 2.39 baseline) | Verified experimental release archive |
| Linux arm64 | CI-tested; source build only |
| Intel macOS / Windows | Not validated |

There is **no published Homebrew formula or crates.io package**, and macOS binaries are **not notarized**. For source builds, use the pinned release tag and commit in [INSTALL.md](docs/INSTALL.md), with `cargo install --locked --path .`; avoid assuming the tip of `main` is an immutable release. The repository pins Rust 1.99.1 for its release toolchain; its declared minimum supported Rust version is 1.88. OpenSSH 8.4+ is required, with additional requirements for proxy hops and destination binding.

## First safe check with OpenSSH (Linux or macOS)

Start with the [five-minute synthetic-key quickstart](docs/QUICKSTART.md) if you do not want to touch your real agent. With an existing OpenSSH agent, this check **does not connect to any remote host or sign using a real key**:

```bash
upstream="${SSH_AUTH_SOCK:?Start or select your SSH agent first}"
SSH_AUTH_SOCK="$upstream" ssh-add -l
fp='SHA256:REPLACE_WITH_YOUR_KEY_FINGERPRINT'

sigsieve doctor --upstream "$upstream" --allow-fingerprint "$fp"
sigsieve connect build-host --upstream "$upstream" --allow-fingerprint "$fp" \
  --dry-run -- -o StrictHostKeyChecking=yes
```

Replace the fingerprint with one from your local agent and `build-host` with an SSH alias whose host key you have **independently verified**. Inspect the dry-run plan before allowing a real connection. See [check, preview, connect, and cleanup](docs/USAGE.md#check-preview-connect).

## First session with Secretive (macOS)

After starting Secretive, get a *public* fingerprint locally:

```bash
SSH_AUTH_SOCK="$HOME/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh" ssh-add -l
```

Then set the fingerprint of the identity permitted on the remote host:

```bash
fp='SHA256:REPLACE_WITH_YOUR_KEY_FINGERPRINT'

sigsieve doctor --secretive --allow-fingerprint "$fp"
sigsieve connect build-host --secretive --allow-fingerprint "$fp" \
  --dry-run -- -o StrictHostKeyChecking=yes
```

Only after verifying your SSH alias, the host key, and the plan, an actual connection would be:

```bash
sigsieve connect build-host --secretive --allow-fingerprint "$fp" \
  -- -o StrictHostKeyChecking=yes
```

A remote `ssh-add -l` should list only the permitted identity. Disconnect to end forwarding. `connect` disables connection sharing, port forwarding, and X11 for that session. For destination-binding setup and behavior, follow the [usage guide](docs/USAGE.md) and [Secretive integration guidance](docs/SECRETIVE_INTEGRATION.md). Never post real agent listings, hostnames, connection plans, or private-key material in public issues.

## Evidence and compatibility

**Evidence is revision-specific, not a certification.** The [v0.1.0-alpha.4 release](https://github.com/semihbugrasezer/sigsieve/releases/tag/v0.1.0-alpha.4) is built from immutable commit [`5ea37b7`](https://github.com/semihbugrasezer/sigsieve/commit/5ea37b73ce7ed5dd33f3ac405c3ae4ad4da68751), not the changing `main` branch.

| Verification | Scope |
|---|---|
| Rust automated and real OpenSSH integration tests | Parsers, policy, resource limits, hostile agent replies, CLI lifecycle, real `ssh`/`sshd`, and a Linux cross-user peer-credential test. See [testing](docs/TESTING.md). |
| Coverage-guided fuzzing | Four targets, one hour each on the alpha.4 release commit: [recorded workflow](https://github.com/semihbugrasezer/sigsieve/actions/runs/41527783557). No crash reported; this does **not** prove absence of vulnerabilities. |
| Release artifacts and supply chain | [Release build](https://github.com/semihbugrasezer/sigsieve/actions/runs/41538765784), SHA-256, CycloneDX SBOM files, attestations, and [Linux verification](https://github.com/semihbugrasezer/sigsieve/actions/runs/41540423408). |
| Real Secretive / Touch ID | Owner-assisted alpha.2 candidate test only, **not** revalidated on alpha.4. See the [limited device record](docs/SECRETIVE_INTEGRATION.md#recorded-real-device-results). |
| External assessment | No independent security audit. Review [findings and remaining gaps](docs/FINDINGS.md). |

## Documentation and contributions

- **Get started:** [install](docs/INSTALL.md) · [quickstart](docs/QUICKSTART.md) · [usage and troubleshooting](docs/USAGE.md) · [example SSH config](examples/ssh_config)
- **Security:** [security model](docs/SECURITY_MODEL.md) · [threat model](docs/THREAT_MODEL.md) · [limitations](docs/LIMITATIONS.md) · [responsible disclosure](SECURITY.md)
- **Engineering:** [architecture](docs/ARCHITECTURE.md) · [test strategy](docs/TESTING.md) · [protocol references](docs/REFERENCES.md) · [changelog](CHANGELOG.md)
- **Community:** [contributing guide](CONTRIBUTING.md) · [governance](GOVERNANCE.md) · [code of conduct](CODE_OF_CONDUCT.md) · [support](SUPPORT.md) · [open issues](https://github.com/semihbugrasezer/sigsieve/issues)

Licensed under [MIT](LICENSE). Binary distribution includes [third-party notices](docs/THIRD_PARTY.md).