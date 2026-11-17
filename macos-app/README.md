# SigSieve for macOS

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
