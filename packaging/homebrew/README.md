# Homebrew formula (for the maintainer-owned tap)

`sigsieve.rb` is the formula for the published tap
[`semihbugrasezer/homebrew-sigsieve`](https://github.com/semihbugrasezer/homebrew-sigsieve)
(`brew install semihbugrasezer/sigsieve/sigsieve`). The tap's
`Formula/sigsieve.rb` must be a reviewed copy of this file. It is **not** in
homebrew-core.

SigSieve stays an **experimental, not independently audited** pre-release
whichever way it is installed. Packaging changes neither of those.

## What the formula does

- Builds `v0.1.0-alpha.4` from the GitHub source archive of the immutable tag
  (`refs/tags/v0.1.0-alpha.4`, commit `5ea37b73ce7ed5dd33f3ac405c3ae4ad4da68751`)
  with `cargo install --locked` (via Homebrew's `std_cargo_args`). It installs
  only the `sigsieve` binary; no service, no configuration file, no changes to
  `~/.ssh` or the user's agent.
- Has no `head` block on purpose, because that would build the untagged `main`
  branch.
- Its `test do` block never touches the user's SSH keys or agent:
  `--version` matches the formula version; `doctor` exits 1 with
  `Upstream agent: FAIL` against a missing socket; a malformed
  `--allow-fingerprint` exits 2 (`Configuration: INVALID`); and against a
  throwaway `ssh-agent` in the test directory holding a freshly generated
  synthetic ed25519 key, `doctor --allow-fingerprint` reports
  `Filtering: verified`. The agent is stopped at the end of the test.

### Source archive versus release binaries

The formula builds from source. It does **not** install the attested release
binaries. Homebrew checks only the archive's `sha256`; the GitHub-generated
source archive has **no provenance attestation**. Its integrity was checked
locally against the tag:

| Check (2026-11-03) | Result |
|---|---|
| Tag commit (`gh api repos/semihbugrasezer/sigsieve/commits/v0.1.0-alpha.4`) | `5ea37b73ce7ed5dd33f3ac405c3ae4ad4da68751` |
| `sha256` of `archive/refs/tags/v0.1.0-alpha.4.tar.gz` (two downloads) | `dfea4d33371a7d429c1cbc7e293e5345db7b69c9ad2cbc225f7ebd9d354e8ae7` |
| Extracted contents vs. `git archive --prefix=sigsieve-0.1.0-alpha.4/` of the tag commit | identical: 112 files by SHA-256, 1 symlink by target |

Users who need build provenance should install the attested binaries
(macOS arm64, Linux x86_64) as described in
[docs/INSTALL.md](../../docs/INSTALL.md).

### Toolchain

The repository pins Rust 1.99.1 in `rust-toolchain.toml`. Homebrew's `rust`
formula is not rustup and ignores that file; it builds with whatever Rust
Homebrew ships (1.99.1 on 2026-11-03). The declared minimum is Rust 1.88. A
future Homebrew Rust that the crate does not build with fails the build; it
does not produce a different binary silently.

## Test evidence (macOS arm64, Homebrew 7.0.12, 2026-11-03)

Run in a local, unpublished tap created with `brew tap-new --no-git`
(removed afterwards):

| Step | Result |
|---|---|
| `ruby -c sigsieve.rb` | Syntax OK |
| `brew style semihbugrasezer/sigsieve/sigsieve` | no offenses |
| `brew audit --strict --online --formula semihbugrasezer/sigsieve/sigsieve` | no problems |
| `brew install --build-from-source semihbugrasezer/sigsieve/sigsieve` | built in 22 s; `sigsieve --version` → `sigsieve 0.1.0-alpha.4` |
| `brew test semihbugrasezer/sigsieve/sigsieve` | pass, including `Filtering: verified` against the throwaway agent |
| `brew uninstall`, reinstall, `brew test` again, uninstall | pass; no `sigsieve` left on `PATH` |
| Wrong `sha256` in the formula | refused: "reports different checksum" |
| `brew install semihbugrasezer/sigsieve/sigsieve` without a prior `brew trust` | Homebrew 7 trusts the explicitly named formula and installs it |

Published tap, same day: the tap's formula equals this file at `main`
`f80ebd3`; from a clean state (no tap, install, trust or binary),
`brew install semihbugrasezer/sigsieve/sigsieve`, `brew test`,
`brew audit --strict --online`, uninstall, reinstall, `brew test` again, and
`brew uninstall` + `brew untap` (clean afterwards) all passed.

Not tested: Linux (Homebrew on Linux), Intel macOS, upgrade from an older
formula version (no earlier published formula exists), a freshly installed
macOS.

## The tap (maintainer)

1. The public repository `semihbugrasezer/homebrew-sigsieve` holds
   `Formula/sigsieve.rb` (a copy of this directory's formula) and a README that
   repeats the experimental status and links to
   [docs/INSTALL.md](../../docs/INSTALL.md).
2. Users install with
   `brew install semihbugrasezer/sigsieve/sigsieve` (or `brew tap
   semihbugrasezer/sigsieve` first). Uninstall:
   `brew uninstall sigsieve && brew untap semihbugrasezer/sigsieve`.
3. After each tap update, run the steps above against the published tap
   from a clean state.

## Updating for a new release

Do every step again for each release. Never reuse a digest or copy one from a
release page without checking it.

1. Use only a published, verified tag that the release checklist accepted
   ([docs/RELEASE_CHECKLIST.md](../../docs/RELEASE_CHECKLIST.md)). Never use
   `main` or an Actions artifact.
2. Resolve the tag commit:
   `gh api repos/semihbugrasezer/sigsieve/commits/TAG --jq .sha`.
3. Download `https://github.com/semihbugrasezer/sigsieve/archive/refs/tags/TAG.tar.gz`
   into an empty directory, compute `shasum -a 256`, and compare its extracted
   tree with `git archive --prefix=sigsieve-VERSION/ TAG` (every file's
   SHA-256 and every symlink's target must match).
4. Update `url`, `sha256` and the commit comment in `sigsieve.rb`; run the test
   table above in a local tap; then update the published tap by a reviewed
   commit.
5. Keep the experimental and not-independently-audited wording until the
   stable-release criteria are met.

## homebrew-core

homebrew-core accepts stable versions only and has its own notability rules;
see its [Acceptable Formulae](https://docs.brew.sh/Acceptable-Formulae)
policy. It is out of scope until a stable SigSieve release exists.
