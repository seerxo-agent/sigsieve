# SigSieve for macOS

A SwiftUI menu bar app for the `sigsieve` command line tool. You pick an SSH
server, choose which agent keys it may use, run the CLI's check, and connect in
Terminal. The design is in `DESIGN.md`.

The app is a convenience layer. The Rust CLI enforces: all filtering, key
binding and the setup checks happen in `sigsieve`, which re-checks when it
connects. The app has no copy of those checks, and a passing check in the
window is not a guarantee the connection will be allowed.

## Requirements

- macOS 13 or newer; Apple Silicon first.
- Xcode 26 or newer (the tests use Swift 6.2 exit tests).
- The `sigsieve` CLI, built from this repository (Rust 1.99.1, see
  `rust-toolchain.toml`).

## Build and run

From the repository root:

```bash
cargo build --release --locked
xcodebuild -project macos-app/SigSieve.xcodeproj -scheme SigSieve \
  -configuration Release -derivedDataPath macos-app/build build
open macos-app/build/Build/Products/Release/SigSieve.app
```

The app is ad hoc signed for local runs. It has no Developer ID, is not
notarized and is not distributed.

## Copyable command

The copyable command is for POSIX shells (sh, bash, zsh). fish and csh/tcsh
are not supported; open `/bin/sh` first and paste it there.

## Known_hosts limits

When you bind a server to its host key, the app lists keys from your known_hosts
file. What it can and cannot see:

- Only ASCII lines are read. A line with a non-ASCII byte is dropped and not
  offered.
- A key on an `@revoked` or `@cert-authority` line is never offered, even when
  it also appears on an unmarked line of another host.
- A non-ASCII byte in an `@revoked` or `@cert-authority` line empties the whole
  list, because that exclusion could not be applied.
- Only `~/.ssh/known_hosts` is offered. Marked lines are also read from
  `/etc/ssh/ssh_known_hosts`, `/etc/ssh/ssh_known_hosts2` and
  `~/.ssh/known_hosts2` (for `@revoked` and `@cert-authority` only).
- A custom `UserKnownHostsFile`, `GlobalKnownHostsFile`, `KnownHostsCommand` or
  `RevokedHostKeys` is not read, so an empty revocation result does not mean
  every source was checked.
- A listed key means only that it was found in local files, not that it was
  verified.

## Security status

The tests are not a substitute for an independent external security audit. That
audit is still outstanding.

## Tests

The Swift package `Packages/SigSieveKit` holds the app's logic. Its
integration tests run the real CLI against a throwaway `ssh-agent` with
synthetic keys; they never touch `~/.ssh`, your agent or your keys. From the
repository root:

```bash
cargo build --release --locked
SIGSIEVE_TEST_CLI=$PWD/target/release/sigsieve \
  swift test --package-path macos-app/Packages/SigSieveKit
```

Without `SIGSIEVE_TEST_CLI` the tests that need the CLI are skipped. With
`CI` set, a missing or non-executable `SIGSIEVE_TEST_CLI` fails the run.

## CI

`.github/workflows/macos-app.yml` runs on pushes and pull requests that change
`macos-app/`, the workflow itself, or the CLI it builds (`src/`, `Cargo.toml`,
`Cargo.lock`, `rust-toolchain.toml`). On
`macos-26` it selects Xcode 26.6 by path (the job fails on any other version),
checks the project opens under it, builds the CLI with Rust 1.99.1, runs the
package tests against that CLI, builds the app and lints its `Info.plist`. It
uploads nothing and uses no secrets.

CI builds with Xcode 26.6; local development has used Xcode 27.2. The workflow has
not run yet. Its first run happens when the branch is pushed, so it is unverified
until then.

## Manual checklist

Things no automated test here can see. Run on a real Mac before a release.

| # | Check | Status |
|---|-------|--------|
| 1 | With 500 keys in a throwaway agent selected in Settings, scrolling and typing in the key search show no visible stall. | not run (2026-11-18) |
| 2 | Light and Dark Mode both readable. | not run (2026-11-18) |
| 3 | Check with Secretive: the Touch ID wait shows "Waiting for agent…". | not run (2026-11-18): needs the owner's Mac with Secretive |
| 4 | Connect opens Terminal with the session; no Automation prompt appears; the launcher directory is gone afterwards. | not run (2026-11-18) |
| 5 | Pasting the copyable command into another terminal connects the same way. | not run (2026-11-18) |
| 6 | Editing the profile while a session is open does not affect it; the window says "applies to new connections". | not run (2026-11-18) |
| 7 | Editing `~/.ssh/config` after a passed check disables Connect on the next window open or when Connect is pressed. | not run (2026-11-18): needs the owner's real `~/.ssh/config`; the Kit side is covered by `configChangeAfterAPassingCheckClosesTheGate` |

A throwaway agent for item 1:

```bash
d=$(mktemp -d) && { /usr/bin/ssh-agent -D -a "$d/a.sock" >/dev/null & pid=$!; }
for i in $(seq 1 500); do ssh-keygen -q -t ed25519 -N '' -C "k$i" -f "$d/k$i"; done
SSH_AUTH_SOCK="$d/a.sock" ssh-add -q "$d"/k*[0-9]   # the 500 private keys, not the .pub files
# select $d/a.sock in Settings; afterwards:
kill "$pid"; rm -rf "$d"
```
