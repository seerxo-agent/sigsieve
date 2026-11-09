# SigSieve for macOS: design

Status: approved for implementation planning (2026-11-09), on the basis of
the reported change summary. Not yet approved for coding; nothing is built
yet.
Owner decisions are marked **(owner)**; choices left to the builder or made
while writing this document are marked **(builder call)**.

## Intent

SigSieve v1.0.0 is a command-line tool. Using it today means knowing your
agent's socket, copying `SHA256:` fingerprints, and typing long `sigsieve
connect` commands. The macOS app removes that typing: a user opens a small
menu bar window, picks a server, picks which keys sessions on that server may
use through the forwarded agent, checks the setup, and connects in Terminal.

Two agents are involved in every connection, and the app keeps them apart in
its wording **(owner)**:

- The **login agent** authenticates you to the selected server. It is the
  profile's own, unfiltered agent, exactly as with plain `ssh`. ssh may offer
  that server any public key in it. The app's key selection does not limit
  this.
- The **forwarded agent** is what processes on the server can reach. It is
  the filtered one. The key selection applies to it and to nothing else.

The app therefore never says a server "sees" or "cannot see" a key. The
question it asks is: "Which keys may sessions on this server use through the
forwarded agent?"

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
  in it (public fingerprints only), the server aliases from SSH
  configuration, and which keys sessions on each server may use through the
  forwarded agent **(owner)**.
- Per-server key policy ("profile"): each server remembers its own forwarded
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
- No `ssh -G` and no display of a server's effective hostname, port or user;
  the app lists aliases only **(owner)**.
- No Swift copy of the CLI's security checks (the `Match exec` scan, the ssh
  plan verification); those stay in the CLI **(owner)**.

## Anti-goals (would make it a failure even if it "works")

- The app gives a sense of safety the CLI does not provide: for example
  reporting a host as "verified" because the user ticked a box, or implying
  that the key selection limits which keys the server is offered at login
  **(owner)**.
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
  ├─ reads   ~/.ssh/config (Host aliases only, read only), agent key list (`ssh-add -l`)
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
  (`/usr/bin:/bin:/usr/sbin:/sbin` plus the CLI's directory), `LANG`,
  `TMPDIR`, and `SSH_AUTH_SOCK` as described below. `SIGSIEVE_UPSTREAM`,
  `SIGSIEVE_ALLOW` and `SIGSIEVE_DESTINATIONS` are never passed, so a value in
  the user's shell cannot silently replace the profile **(builder call;
  found while writing: the CLI reads these variables)**.
- `TMPDIR` is where the CLI creates the filtered agent socket; without it the
  CLI falls back to the shared `/tmp`. The app does not copy `TMPDIR` from its
  own environment. It asks macOS for the per-user temporary directory
  (`confstr(_CS_DARWIN_USER_TEMP_DIR)`), resolves symlinks, and passes it only
  if all of these hold: the path is absolute, it is a directory, it is owned
  by the current user, its mode gives group and others no access, and it
  contains only characters the CLI accepts in a socket path (ASCII letters,
  digits and `/._-`). If any check fails, checks and connections are blocked
  with an error naming the path and the failed rule. There is no fallback to
  `/tmp` **(owner)**.
- **The same environment is used for the checks and for the Terminal
  launcher**, so a passing check describes the connection that follows
  **(builder call; found in review)**. The launcher starts the CLI with
  `/usr/bin/env -i` and exactly these variables; the copyable command shows
  the same `env -i …` prefix, so pasting it into any terminal reproduces it.
- One documented difference: `TERM`. The Terminal launcher and the copyable
  command also pass `TERM`, taken from the terminal they run in
  (`TERM="$TERM"`), because the interactive session needs a terminal type.
  `doctor` and `--dry-run` have no terminal and do not get it. `TERM` does
  not take part in any CLI check or in how ssh evaluates its configuration,
  so the check still describes the connection **(owner)**.
- Login agent (what authenticates you to the selected server itself): the
  CLI takes it from `SSH_AUTH_SOCK` and passes it to ssh as `IdentityAgent`.
  The app sets `SSH_AUTH_SOCK` to the profile's upstream agent: the Secretive
  socket for Secretive, the chosen socket for the OpenSSH agent. This matches
  how a Secretive user's plain `ssh` already logs in; the filtered agent is
  what gets forwarded. An `IdentityAgent` in the user's ssh_config still
  wins, as in plain ssh, and `--dry-run` reports which one is used
  **(builder call)**. The login agent is not filtered: at login ssh may
  offer the selected server any public key in it, as plain `ssh` does. The
  result screen shows the login agent and the forwarded agent as two
  separate lines.
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

- Discovery: read `Host` aliases from `~/.ssh/config` and its `Include`
  files (read only). Wildcard patterns (`*`, `?`, `!`) are not listed as
  servers. Only the alias is shown. The effective hostname, port and user are
  not shown in the first version **(owner)**.
- The app never runs `ssh` to read configuration: no `ssh -G`, so no command
  from the user's configuration (`Match exec`) can run because of the app
  **(owner; replaces an earlier draft that ran `ssh -G` behind a Swift copy
  of the CLI's `Match exec` scan)**.
- Alias reading is for display only and decides nothing about safety. If it
  misses an alias, the user adds it by hand; if it lists one ssh would not
  use, the CLI reports that at check time. An `Include` the app cannot
  resolve is skipped and named in a one-line notice.
- The CLI's rules for ssh configuration (`Match exec`, ProxyCommand,
  forwardings and the rest of SSH_COMPATIBILITY.md) are enforced by the CLI
  during Check Connection and again at connect. The app does not reimplement
  them; on refusal it shows the CLI's own explanation **(owner)**.
- Manual servers: the user can add an alias or `user@host` that discovery did
  not find **(owner)**. Input is validated: no leading `-`, no whitespace or
  control characters.
- Search over alias; fixed-height scroll list **(owner)**.

### Profiles (owner, with these rules)

- One profile per server: fingerprints of the keys the forwarded agent may
  use, agent, protection mode (identity filtering, default; destination
  binding, advanced), and for binding the allowed host key fingerprints.
- A server without a saved profile has **no** key forwarded. Connecting
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

What it means (CLI semantics, see docs/USAGE.md and SSH_COMPATIBILITY.md):
`--allow-destination` names the servers the **forwarded** key may log in to
**onward from** the selected server, for example `github.com` when you run
`git` on a build host. It does not protect the login to the selected server
itself, which uses your own agent locally. The window says this in one line
**(builder call; corrected after review: an earlier draft bound to the
selected server's own key, which would have looked like protection without
being useful)**.

- The profile stores a list of allowed destinations: a name for display and
  one or more host key fingerprints each. Default: none (binding off).
- Picker source: entries the user already trusts in `~/.ssh/known_hosts`
  (fingerprints via `ssh-keygen -l -f ~/.ssh/known_hosts`, names shown when
  the file is not hashed), plus manual entry of a `SHA256:` host key
  fingerprint with a name. Manual entry shows how to obtain a fingerprint
  from a trusted source. The app never fetches host keys from the network.
- `known_hosts` lines marked `@revoked` or `@cert-authority` are never
  offered: a revoked key must not be allowed, and a certificate authority
  key is not a host key. The app reads the file itself, drops marked lines
  (and comments), and passes only the remaining lines to `ssh-keygen -l`
  **(owner)**.
- A `known_hosts` entry is a source of fingerprints, not proof that the host
  was verified. The picker labels these entries "from your known_hosts" and
  nothing stronger.
- The app shows the CLI's limits as facts in the profile: binding needs
  OpenSSH hostbound authentication on the onward server; RSA host keys are
  refused at authentication; with Secretive, a cancelled Touch ID prompt
  means reconnecting.

### Check Connection

Runs, in order, with the profile's exact arguments:

1. `sigsieve doctor <agent> --allow-fingerprint FP… [--allow-destination HK…]`
2. `sigsieve connect <host> <agent> --allow-fingerprint FP… [--allow-destination HK…] --dry-run -- -o StrictHostKeyChecking=yes`

The result screen lists what the CLI reported (agent reachable, how many keys
forwarded and hidden, filtering verified, login agent, forwarded agent,
forwarding/X11/connection sharing off, binding on or off) and keeps the raw output one click away. On failure it
shows the CLI's own `hint:` line. Identity filtering shows, as a result line,
that the shared key can sign for any server while connected (a fact about
the chosen mode, not a banner).

### From check to connect

Connect in Terminal (and the copyable command) is enabled only after Check
Connection passed for exactly the current inputs: profile contents, agent,
CLI path and version, the verified `TMPDIR`, and the SSH configuration. Any
change clears the result and disables Connect until the next check
**(answered by the owner's flow: "if the checks pass, I review the plan,
then connect")**.

SSH configuration changes are detected from the files the app read for
alias discovery (`~/.ssh/config` and the `Include` files it resolved): the
app records each file's path, size and modification time at check time and
compares them again when the window opens and when Connect is pressed
**(owner)**.

This gate keeps the window honest; it is not the security boundary. The
real `sigsieve connect` runs every check again itself, in the same code path
as `--dry-run`, immediately before it starts ssh, and refuses if one fails.
A stale result in the app, or a change the app did not notice, therefore
cannot produce an unchecked connection. The result screen says so in one
line: "SigSieve checks again when it connects" **(owner)**.

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
- The launcher runs `exec /usr/bin/env -i <variables…> TERM="$TERM"
  <cli-path> connect <args…>` (see "Running the CLI") and deletes its own
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
3. Forwarded keys for the selected server, under the heading "Keys sessions
   on this server may use (forwarded agent)": searchable, scrolling list
   with a toggle per key, "N forwarded to this server · applies to new
   connections". One line below names the login agent and says it is not
   filtered.
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
- `known_hosts` picker: `@revoked` and `@cert-authority` lines never appear
  as selectable host keys, including when the same key also appears on an
  unmarked line of another host, and with hashed host names.
- Environment: the built environment contains exactly the documented
  variables; `SIGSIEVE_*` values in the app's own environment are not passed
  on; the launcher and the copyable command differ from the check
  environment by `TERM` only.
- `TMPDIR` verification: a directory owned by another user, one with group
  or other access, a relative path, a symlink to an unsafe directory and a
  path with unsupported characters are each refused, with no fallback to
  `/tmp`.
- The Swift app never runs `ssh` or `ssh -G` directly. In a real connection
  ssh is started only by `sigsieve connect`. The test fails if the app's
  process runner is asked to run anything but the CLI, `ssh-add` and
  `ssh-keygen`.
- Check validity: changing the profile, agent, CLI path or version, `TMPDIR`
  or a discovered SSH configuration file (size or modification time) clears
  a passed result and disables Connect.
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
- Showing a server's effective hostname, port and user. This needs the
  `Match exec` scan to stay in the CLI (for example a CLI subcommand that
  prints them), not a Swift copy.
- Disconnect / session list.
- Signing, notarization and distribution (Apple Developer account, cost).
- Intel macOS.
