# SigSieve for macOS: design

Status: design approved for planning (2026-11-09). Nothing is built yet.
Owner decisions are marked **(owner)**; choices left to the builder or made
while writing this document are marked **(builder call)**.

## Intent

SigSieve v1.0.0 is a command-line tool. Using it today means knowing your
agent's socket, copying `SHA256:` fingerprints, and typing long `sigsieve
connect` commands. The macOS app removes that typing: a user opens a small
menu bar window, picks a server, picks which key that server may see, checks
the setup, and connects in Terminal.

The app is a convenience layer, not a second security engine. Every check and
every connection runs the existing Rust CLI. The CLI stays the only component
that enforces filtering and destination binding **(owner)**.

Target user: a macOS developer who forwards an SSH agent (often Secretive),
from someone with one key to a DevOps engineer with 100+ keys and dozens of
servers **(owner)**.

## Goals

- A small, fast, native-feeling macOS menu bar app (SwiftUI `MenuBarExtra`),
  Light and Dark Mode, macOS 13 or newer, Apple Silicon first **(owner)**.
- Without typing a command, the user sees: which agent is connected, the keys
  in it (public fingerprints only), the servers from SSH configuration, and
  which keys each server may see **(owner)**.
- Per-server key policy ("profile"): each server remembers its own allowed
  keys and protection mode **(owner)**.
- "Check Connection" runs `sigsieve doctor` and `sigsieve connect --dry-run`
  and shows the result in plain language; the raw output stays available.
- "Connect in Terminal" opens Terminal running the exact `sigsieve connect`
  command for that profile, also shown in a copyable form **(owner)**.
- Works with 100+ keys and dozens of servers: scrollable fixed-height lists,
  search, no UI freezes **(owner)**.

## Non-goals (first version)

- No changes to the Rust CLI or to the released v1.0.0 **(owner)**.
- No `Disconnect` / session management unless the app can identify its own
  process reliably; otherwise it waits for a later phase **(owner)**.
- No code signing, notarization or public distribution; local builds only
  **(owner)**.
- No editing of `~/.ssh/config`, `known_hosts` or the agent **(owner)**.
- No key creation, import or deletion; no private key ever enters the app
  **(owner)**.
- No background daemon, launch agent or login item.

## Anti-goals (would make it a failure even if it "works")

- The app gives a sense of safety the CLI does not provide: for example
  reporting a host as "verified" because the user ticked a box **(owner)**.
- The app changes what an already running connection is allowed to do when
  the user edits a profile **(owner)**.
- A new server starts with any key allowed, or there is a "select all"
  **(owner)**.
- Server names, profile data or user input reach a shell as code
  (command injection) **(owner)**.
- The app kills a process it did not start **(owner)**.

## Architecture

```text
SwiftUI app (MenuBarExtra window)
  ├─ reads   ~/.ssh/config (via `ssh -G`, read only), agent key list (`ssh-add -l`)
  ├─ stores  profiles.json (Application Support)
  └─ runs    sigsieve doctor / connect --dry-run  (Process, argument array)
             Terminal → sigsieve connect          (launcher script, see below)
                         │
                   SigSieve Rust CLI  (all filtering, binding, checks)
                         │
             Secretive / OpenSSH agent (private keys stay here)
```

Location: `macos-app/` in the sigsieve repository, its own Swift package /
Xcode project, build and tests **(owner)**. The Rust crate and release
pipeline are untouched.

## Components and their rules

### CLI discovery (owner)

1. A user-chosen path, if set in Settings.
2. `/opt/homebrew/bin/sigsieve`, then `/usr/local/bin/sigsieve`.
3. `PATH` of a login shell is **not** sourced; the app searches the fixed
   list above plus `PATH` as given to the app **(builder call)**.

Before use, the app resolves symlinks, checks the file is executable and runs
`sigsieve --version`. It requires `sigsieve 1.x` with `x >= 0`; anything else
is shown as a blocking error, with the resolved path and version, and no check
or connection runs. The resolved path and version are always visible in
Settings.

### Running the CLI (all calls)

- `Process` with an argument array; never `/bin/sh -c`, never string
  concatenation **(owner)**.
- The child environment is built from scratch: `HOME`, `PATH`
  (`/usr/bin:/bin:/usr/sbin:/sbin` plus the CLI's directory), `LANG`, and
  `SSH_AUTH_SOCK` only when the OpenSSH agent is selected. `SIGSIEVE_UPSTREAM`,
  `SIGSIEVE_ALLOW` and `SIGSIEVE_DESTINATIONS` are never passed, so a value in
  the user's shell cannot silently replace the profile **(builder call;
  found while writing: the CLI reads these variables)**.
- Every call runs off the main thread with a timeout; Touch ID can take up
  to the CLI's `--upstream-timeout` (120 s default), so `doctor` and
  `--dry-run` get a timeout above that and a visible "waiting for agent"
  state.
- Exit codes are the source of truth: `0` passed, `1` a check failed, `2`
  invalid configuration. Parsed text is used only for display.

### Agent and keys

- Agent choice: Secretive (CLI flag `--secretive`) or the OpenSSH agent
  (`--upstream <socket>`, socket taken from the app's `SSH_AUTH_SOCK` or
  chosen by the user) **(owner: both supported)**.
- Key list: `ssh-add -l -E sha256` against that socket. Only public
  fingerprints, key type, size and comment are read. Lists are refreshed on
  demand and when the window opens, off the main thread **(builder call)**.
- Display: comment (truncated), type, short fingerprint; full fingerprint on
  hover and a copy button. Two keys with the same comment are told apart by
  fingerprint **(owner)**.
- Search over comment, type and fingerprint; fixed-height scroll list; must
  stay responsive at 500 keys **(owner: 100+; 500 is the builder's test
  bound)**.

### Servers

- Discovery: parse `Host` names from `~/.ssh/config` and its `Include` files
  (read only). Wildcard patterns (`*`, `?`, `!`) are not listed as servers.
  For each listed alias, `ssh -G <alias>` gives the effective `hostname`,
  `port` and `user` for display **(owner: read only, Include and wildcards
  handled; builder call: use `ssh -G` instead of re-implementing ssh_config
  semantics)**.
- Manual servers: the user can add an alias or `user@host` that discovery did
  not find **(owner)**. Input is validated: no leading `-`, no whitespace or
  control characters.
- Search over alias and hostname; fixed-height scroll list **(owner)**.

### Profiles (owner, with these rules)

- One profile per server: allowed key fingerprints, agent, protection mode
  (identity filtering, default; destination binding, advanced), and for
  binding the allowed host key fingerprints.
- A server without a saved profile has **no** key allowed. Connecting
  requires an explicit choice; there is no "select all".
- Stored at `~/Library/Application Support/SigSieve/profiles.json`:
  directory `0700`, file `0600`, written atomically (temporary file in the
  same directory, `fsync`, rename), with a top-level `"schemaVersion": 1`. An
  unknown or newer version is not overwritten; the app shows an error.
- It contains server names and fingerprints, which can be sensitive metadata;
  nothing else (no secrets).
- Profiles change nothing outside the app. The CLI does not read this file
  in this version. A later CLI `--profile` option may read the same
  documented format, as a separate, explicitly tested change **(owner)**.
- Editing a profile never affects a connection that is already running; the
  window says "applies to new connections" **(owner)**.

### Destination binding (advanced)

- Offered only when the server's host key is already in `known_hosts`
  (trusted by OpenSSH before). The app reads candidate fingerprints with
  `ssh-keygen -l -F <host>` (with the effective hostname and port from
  `ssh -G`) and shows them; the user picks which ones to allow. It never
  fetches a host key from the network to "verify" it **(builder call)**.
- If no `known_hosts` entry exists, binding is unavailable for that server,
  with the reason: connect once with identity filtering and verify the host
  key, then come back.
- The app shows the CLI's limits as facts in the profile: binding needs
  OpenSSH hostbound authentication; with Secretive, a cancelled Touch ID
  prompt means reconnecting.

### Check Connection

Runs, in order, with the profile's exact arguments:

1. `sigsieve doctor <agent> --allow-fingerprint FP… [--allow-destination HK…]`
2. `sigsieve connect <host> <agent> --allow-fingerprint FP… [--allow-destination HK…] --dry-run -- -o StrictHostKeyChecking=yes`

The result screen lists what the CLI reported (agent reachable, how many keys
shared and hidden, filtering verified, forwarding/X11/connection sharing off,
binding on or off) and keeps the raw output one click away. On failure it
shows the CLI's own `hint:` line. Identity filtering shows, as a result line,
that the shared key can sign for any server while connected (a fact about
the chosen mode, not a banner).

### Host key verification (owner)

- `StrictHostKeyChecking=yes` is always passed; an unknown host key is never
  accepted automatically.
- The app has no "I verified it" checkbox and never reports a host as
  verified. For a server not in `known_hosts`, it explains that OpenSSH will
  refuse the connection and links to how to add a host key after comparing
  its fingerprint with a trusted source.

### Connect in Terminal (owner, with these rules)

- The app writes a launcher to a fresh directory created with `mkdtemp` under
  the user's temporary directory, mode `0700`; the launcher file is `0700`.
- The launcher is generated so that no profile value is ever interpreted by
  the shell: each argument is written with single-quote POSIX quoting
  (`'` → `'\''`), and values are validated first (fingerprints match
  `^SHA256:[A-Za-z0-9+/]{43}$`, host input rules above). Unit tests cover
  quotes, spaces, `$()`, backticks, newlines and leading dashes.
- The launcher runs `exec <cli-path> connect <args…>` and deletes its own
  directory first (the script is already loaded), so nothing is left behind
  even if Terminal is closed. The app also removes stale launcher directories
  older than one hour at start.
- It is opened with `NSWorkspace` in Terminal. No AppleScript and no
  Automation permission **(builder call)**.
- The same command is shown in the window as copyable text, quoted the same
  way, so it can be pasted into any terminal.

### Disconnect (phase 2)

Not in the first version. It is added only if the app can reliably identify
a `sigsieve connect` process it started (its PID and start time) and confirm
it is still that process before signalling it. The app never lists or kills
SSH connections it did not start **(owner)**.

## Window layout (from the chosen mockup "A")

One menu bar window, about 380 pt wide, fixed maximum height:

1. Status row: agent, key count, CLI version; red or orange when something
   blocks checks.
2. Server picker: searchable list (or a "recent" section on top), plus
   "Add server…".
3. Keys for the selected server: searchable, scrolling list with a toggle per
   key, "N selected for this server · applies to new connections".
4. "Advanced": protection mode, allowed host keys for binding.
5. Check Connection → results; then Connect in Terminal and the copyable
   command.
6. Footer: Settings (agent, CLI path, profiles file location) and Quit.

The menu bar icon is a template image; it shows a small badge only for a
blocking error.

## Testing

- Swift unit tests: argument building for every profile shape; launcher
  quoting (injection cases); profile load/save (permissions, atomic write,
  schema version, unknown version not overwritten); ssh_config alias
  extraction including `Include` and wildcards; fingerprint and host input
  validation.
- Integration tests on macOS CI or locally, with a throwaway `ssh-agent`
  and synthetic keys: key listing, `doctor` pass and fail, `--dry-run` pass,
  CLI missing or wrong version.
- A 500-key synthetic agent for list performance.
- No test uses a real user key, host or the user's own agent.

## Left to the builder

- Swift package vs. Xcode project, module layout, and how the app bundle and
  `Info.plist` (`LSUIElement`) are produced for local runs.
- Exact visual details within the mockup's structure and macOS conventions.
- How results are parsed for display (exit codes stay the source of truth).
- CI job for building and testing `macos-app/` (a separate workflow is fine;
  it must not touch the release workflows).

## Open for later phases

- CLI `--profile` reading `profiles.json` (Rust change, separate review).
- Disconnect / session list.
- Signing, notarization and distribution (Apple Developer account, cost).
- Intel macOS.
