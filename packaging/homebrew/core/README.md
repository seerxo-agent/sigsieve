# homebrew/core candidate formula

`sigsieve.rb` here is a **candidate** for homebrew/core. It has **not been submitted**, and it will not be
until SigSieve meets Homebrew's notability rules
([Acceptable Formulae](https://docs.brew.sh/Acceptable-Formulae),
[Package Acceptance Policy](https://docs.brew.sh/Package-Acceptance-Policy#notability)). Users install from the
maintainer-owned tap, whose formula is `../sigsieve.rb`; this file does not change the tap.

## How CI checks it

`.github/workflows/homebrew-core-candidate.yml` runs only on pushes to the `homebrew/core-candidate` branch and on
manual dispatch, with read-only permissions and no secrets. On macOS (arm64), Linux x86_64 and Linux ARM64 it:

1. copies this file into a throwaway local tap and checks (by SHA-256) that `brew formula` loads exactly this file;
2. prints the dependency tree and which `ssh`/`ssh-agent` is in use;
3. runs `brew style` and `brew audit --strict --online` (must pass);
4. runs `brew audit --new --strict --online` in the local tap and in a copy inside the runner's homebrew/core
   checkout (non-blocking; full output in the job summary; notability and repository age are expected to fail);
5. runs `brew livecheck` and requires it to find `1.0.0`;
6. builds from source (`HOMEBREW_NO_INSTALL_FROM_API=1`), runs `brew test`, uninstalls and checks that `sigsieve` is gone.

Nothing is uploaded or published.

## Differences from the tap formula (`../sigsieve.rb`)

| | Tap formula | Candidate |
|---|---|---|
| Comments | Tap notes, "no `head` block" note | None (homebrew/core style) |
| `desc` | "SSH agent filtering proxy that exposes only allowlisted identities" | "SSH agent proxy that forwards only allowlisted keys" |
| OpenSSH | not declared | `on_linux { depends_on "openssh" }`: `connect` runs `ssh` and the test runs `ssh-agent`, `ssh-keygen`, `ssh-add`; macOS ships OpenSSH |
| Network | allowed in every phase | `deny_network_access!`, crates fetched in `def fetch` with `std_cargo_fetch_args` |
| Test | uses `ssh-agent` from `PATH`; socket at `agent/agent.sock` | on Linux puts Homebrew's OpenSSH first on `PATH` and asserts that it is the one used; `TMPDIR` set to `testpath` so `doctor`'s temporary socket stays inside the macOS test sandbox; shorter socket path `a/s` |

URL, SHA-256, licence, build (`cargo install` with `std_cargo_args`) and the test assertions are the same.
