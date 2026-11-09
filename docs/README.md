# SigSieve documentation

SigSieve v1.0.0 is not independently audited. Read the security model and
limitations before forwarding an agent.

## Use

| Document | What it covers |
| --- | --- |
| [INSTALL.md](INSTALL.md) | Homebrew, verified prebuilt archives, source builds, uninstall |
| [QUICKSTART.md](QUICKSTART.md) | Five-minute walkthrough with a throwaway agent and synthetic keys |
| [USAGE.md](USAGE.md) | Commands, `ssh_config` setup, troubleshooting, alternatives |
| [SECRETIVE_INTEGRATION.md](SECRETIVE_INTEGRATION.md) | Using SigSieve with Secretive, and the tested device scope |
| [SSH_COMPATIBILITY.md](SSH_COMPATIBILITY.md) | Agent protocol support and how `connect` reads SSH configuration |
| [VERIFY_OFFLINE.md](VERIFY_OFFLINE.md) | Verifying release files without network access |

## Security

| Document | What it covers |
| --- | --- |
| [SECURITY_MODEL.md](SECURITY_MODEL.md) | The two modes, guarantees and the evidence behind them |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Attackers, trust boundaries and what is out of scope |
| [LIMITATIONS.md](LIMITATIONS.md) | Known limits and verification gaps |
| [FINDINGS.md](FINDINGS.md) | Every security finding and how it was resolved or accepted |
| [TESTING.md](TESTING.md) | Test layers and per-release evidence |
| [RESOURCE_LIMITS.md](RESOURCE_LIMITS.md) | Connection, message and timeout limits |

## Project

| Document | What it covers |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Components, request flow and dependencies |
| [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) | Release gates S1–S12 and release records |
| [THIRD_PARTY.md](THIRD_PARTY.md) | Third-party licenses and notices |
| [REFERENCES.md](REFERENCES.md), [RESOURCE_REFERENCES.md](RESOURCE_REFERENCES.md) | Protocol and resource-limit references |
| [archive/](archive/) | Historical plans and assessments from the alpha series, kept as a record |
