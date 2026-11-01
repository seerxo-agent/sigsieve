# Install SigSieve v0.1.0-alpha.3

SigSieve is **experimental, unaudited security software**. Read the
[security model](SECURITY_MODEL.md) and [known limitations](LIMITATIONS.md)
before forwarding an SSH agent. Keep ordinary SSH access available.

The current verified binary pre-release is
[**v0.1.0-alpha.3**](https://github.com/semihbugrasezer/sigsieve/releases/tag/v0.1.0-alpha.3),
built from immutable commit
`60c9b3777ce41cedc035c373836a8c0ea5c7e4cd`. Its release files cannot be
changed after publication (GitHub immutable release).
Do not substitute a newer `main` archive or an unverified Actions artifact.

## Supported downloads

| Host | Archive target | Notes |
|---|---|---|
| macOS Apple Silicon (arm64) | `aarch64-apple-darwin` | Native release verification passed; no signed/notarized macOS distribution is claimed |
| Linux x86_64 | `x86_64-unknown-linux-gnu` | Built on Ubuntu 24.04, glibc 2.39 baseline; older distributions may need a source build |

Linux arm64 is tested in CI but has no prebuilt archive. Intel macOS and
Windows are not validated. OpenSSH 8.4+ is required; proxy-jump/relay sessions
require 8.7+.

Homebrew and crates.io installs are **not available**. An unpublished draft
formula lives in [`packaging/homebrew`](../packaging/homebrew/README.md) for
maintainer review only.

## Verify and install a published archive

Prerequisites: `gh` (GitHub CLI, authenticated if your setup requires it),
`tar`, `install`, and `shasum` (macOS) or `sha256sum` (Linux).
Use a recent GitHub CLI with `gh attestation verify` support for
`--signer-workflow`, `--source-ref`, `--source-digest`, and
`--deny-self-hosted-runners`. If a flag is unavailable, upgrade `gh`
rather than skipping provenance verification.

Run this in your terminal. It downloads only the matching release archive and
checksum to a temporary directory, **verifies the downloaded checksum and a
separately pinned SHA-256 digest as well as provenance before running the
binary**, and installs to `~/.local/bin` (not a system directory).

```sh
(
  set -eu
  repo=semihbugrasezer/sigsieve
  tag=v0.1.0-alpha.3
  commit=60c9b3777ce41cedc035c373836a8c0ea5c7e4cd
  case "$(uname -s)/$(uname -m)" in
    Darwin/arm64)
      target=aarch64-apple-darwin
      expected_sha=18a6cd645f99012fe128961a42c489495e816f1b3664c56b788dc61a50b6f5b2 ;;
    Linux/x86_64)
      target=x86_64-unknown-linux-gnu
      expected_sha=889a6a166402fe768b9ace765504dd83b9466fc2be3d1399725631664aa41169 ;;
    *) echo "No verified binary for this OS/architecture; build from source." >&2; exit 1 ;;
  esac
  name="sigsieve-$tag-$target"
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
  cd "$work"
  gh release download "$tag" -R "$repo" \
    -p "$name.tar.gz" -p "$name.tar.gz.sha256"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c "$name.tar.gz.sha256"
    printf '%s  %s\n' "$expected_sha" "$name.tar.gz" | shasum -a 256 -c -
  else
    sha256sum -c "$name.tar.gz.sha256"
    printf '%s  %s\n' "$expected_sha" "$name.tar.gz" | sha256sum -c -
  fi
  gh attestation verify "$name.tar.gz" --repo "$repo" \
    --signer-workflow "$repo/.github/workflows/release.yml" \
    --source-ref "refs/tags/$tag" \
    --source-digest "$commit" \
    --deny-self-hosted-runners
  tar -tzf "$name.tar.gz"  # optional: inspect archive entries
  tar -xzf "$name.tar.gz"
  "$name/sigsieve" --version
  mkdir -p "$HOME/.local/bin"
  install -m 755 "$name/sigsieve" "$HOME/.local/bin/sigsieve"
  "$HOME/.local/bin/sigsieve" --version
)
```

Expected version: `sigsieve 0.1.0-alpha.3`. Add `~/.local/bin` to your
`PATH` if you want to run `sigsieve` without its full path.

The release archive also contains `LICENSE`, `THIRD_PARTY_LICENSES.txt`,
`README.md`, and `CHANGELOG.md`. The packaged Markdown links are pinned to
its source revision. Inspect these files before using the program.
macOS code signing or notarization is **not** claimed. If macOS blocks
execution, do not blindly disable Gatekeeper; use a source build or ask for help.

The published `v0.1.0-alpha.3` archives' and SBOMs' SHA-256 values are:

```text
18a6cd645f99012fe128961a42c489495e816f1b3664c56b788dc61a50b6f5b2  sigsieve-v0.1.0-alpha.3-aarch64-apple-darwin.tar.gz
6c6e11c207021632759860db01e509e45306f3be08be21879f03931dc69bdc6e  sigsieve-v0.1.0-alpha.3-aarch64-apple-darwin.cdx.json
889a6a166402fe768b9ace765504dd83b9466fc2be3d1399725631664aa41169  sigsieve-v0.1.0-alpha.3-x86_64-unknown-linux-gnu.tar.gz
6216c8c6b57318a86fbef7aba8982cd75b6484ca27f74d15f625bca0b767e1a1  sigsieve-v0.1.0-alpha.3-x86_64-unknown-linux-gnu.cdx.json
```

Release evidence for `v0.1.0-alpha.3`: the
[release build](https://github.com/semihbugrasezer/sigsieve/actions/runs/41327036746)
(provenance and SBOM attestations), native macOS arm64 verification with
`scripts/verify-release.sh`, and the
[Linux x86_64 verification](https://github.com/semihbugrasezer/sigsieve/actions/runs/41332325926)
each passed.

The hardcoded digest prevents accepting an archive and checksum that have both
changed since this guide was reviewed. Checksums alone do not prove build
origin. The provenance check
binds the archive to this repository's `release.yml`, immutable tag ref and
source digest, while denying self-hosted runners. See the
[release verification procedure](RELEASE_CHECKLIST.md).

Each `v0.1.0-alpha.3` archive has a CycloneDX SBOM sidecar
(`$name.cdx.json` and `.sha256`) with its own build provenance, and an SBOM
attestation for the archive. To verify those, or to verify on a machine
without network access by using downloaded attestation bundles, see
[VERIFY_OFFLINE.md](VERIFY_OFFLINE.md). The earlier `v0.1.0-alpha.2`
release has no SBOM, because it was published before SBOM sidecars existed.

## Install the tagged version from source

Use this path for Linux arm64, older glibc distributions, or to avoid
prebuilt downloads. Requires a working Rust toolchain (the checkout pins
Rust 1.99.1) and OpenSSH. This installs **the release tag**, not the newer
`main` branch. It stops before building if the checked-out commit is not the
release commit:

```sh
(
  set -eu
  git clone https://github.com/semihbugrasezer/sigsieve.git
  cd sigsieve
  git checkout v0.1.0-alpha.3
  test "$(git rev-parse HEAD)" = 60c9b3777ce41cedc035c373836a8c0ea5c7e4cd
  cargo install --locked --path .
  "${CARGO_HOME:-$HOME/.cargo}/bin/sigsieve" --version
)
```

A source build is local compilation, not verification of the published
binary's provenance.

## First safe check and removal

Start with [identity filtering and a dry run](../README.md#first-safe-check-with-openssh-linux-or-macos)
or the [Secretive setup](../README.md#first-session-with-secretive-macos).
`doctor` does not request real-key signing; `connect --dry-run` does not
start a remote SSH session. Verify the SSH destination's host key through
a trusted channel before a real connection.

SigSieve does not edit SSH configuration or your upstream agent. To remove a
prebuilt installation, stop any SigSieve sessions and delete only
`$HOME/.local/bin/sigsieve`; for a Cargo installation use
`cargo uninstall sigsieve`. See [cleanup and recovery](USAGE.md#uninstall-and-recovery).
