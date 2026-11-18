# SigSieve for macOS: UI redesign

Status: design direction approved by the owner (2026-11-18), with the four
acceptance conditions below. Next: the implementation plan.

Decisions the owner made are marked **(owner)**. Choices made while writing this
document, which the owner can overrule, are marked **(builder call)**. The
existing `macos-app/DESIGN.md` stays the authority for behaviour. This document
changes only how that behaviour is laid out.

## Intent

The app works and passed CI and the manual checks that could be run. The owner
will not release it with its current look. Today everything is in one narrow
menu bar panel with a fixed-height scroll area, lists that scroll inside it, and
an "Advanced" disclosure.

Within a second of opening the app, the owner wants to see **(owner)**:

1. which server this is,
2. which keys sessions on that server may use through the forwarded agent,
3. which protection is in effect, and whether the setup has been checked.

The target is a calm, native, modern macOS app **(owner)**. The references are
Raycast for typography and spacing and System Settings for native controls.
The owner asked for it simple: drafts 2 and 3 were rejected as "çok karmaşık".

## Goals

- A separate, resizable main window. Servers are in a sidebar and the selected
  server is on the right **(owner)**. This is mockup 1 in
  "Approved mockup" below.
- The words "Identity filtering only" and "Destination binding" are always
  visible for the selected server, and the difference between them is never
  hidden **(owner)**.
- The key list is the centre of the window. A key cannot be added by a stray
  click **(owner)**.
- A Check result shows a short result line first, then the approved warning
  texts in full, then the technical details, which are collapsed **(owner)**.
- Check and Connect sit in a fixed bottom bar. Connect is disabled unless the
  current inputs passed a check **(owner)**.
- Settings opens in its own window and never replaces the main window
  **(owner)**.
- The menu bar icon opens the main window and shows a brief status **(owner)**.

## Non-goals

- No change to the Rust CLI, the check gate, profile storage format or any
  security rule, and no change to any existing SigSieveKit file **(owner)**. The
  one approved exception (2026-11-18) is a new display helper,
  `Profiles/ForwardedKeys.swift`: it only builds the displayed key list and
  matches saved fingerprints to the agent's keys by SHA256 fingerprint. It never
  treats a missing key as usable, never reinterprets the policy and never
  authorises a connection. The freeze is lifted for the UI layer only,
  and the release blockers are unchanged **(owner)**.
- No new features. Every control maps to an `AppModel` operation that exists
  today. The exceptions are the server-guarded `setForwardedKeys` and `setMode`
  (a sheet's draft is applied only to the server it was opened for), and a
  check reset when a forwarded key vanishes from or reappears in the agent: the
  gate's inputs do not include the agent's keys, so without it a passed check
  would outlive the key it was made with **(owner)**.

## Anti-goals: the redesign has failed if

- anything looks ready, green or connectable before a check passed for exactly
  the current inputs;
- destination binding looks like a cosmetic switch. The owner rejected a toggle
  for it **(owner)**;
- an approved warning text is shortened, hidden behind a click or reworded
  **(owner)**;
- the app says a server "sees", "cannot see" or has keys "hidden" from it.
  `DESIGN.md` forbids this wording. The question stays "Which keys may sessions
  on this server use through the forwarded agent?";
- it has colour for decoration, large warning boxes, nested scrolling or raw CLI
  output on the main screen **(owner)**;
- colour on key badges reads like a security level **(owner)**.

## Constraints

- Existing tests stay green. CI (`.github/workflows/macos-app.yml`) builds the
  app and runs the SigSieveKit tests. View code has no unit tests today, and
  this work adds none for layout.
- Manual checklist items 1 (500 keys, search, no stall), 2 (light and dark mode)
  and 7 (reopening after a config `touch` clears the result) are re-run after
  implementation. The window-reopen trigger for item 7 must still fire.
- Fictional names only in any committed screenshot or text.

## Approaches

1. **Rewrite the view layer on the existing `AppModel` (chosen).** The model,
   gate and Kit stay. New views fill a `Window` scene, the `MenuBarExtra` keeps
   only a status and "Open SigSieve", and Settings moves to a `Settings` scene.
   This is the smallest change and leaves every security path untouched.
2. Restyle the current panel in place. Rejected: the owner asked for a separate
   resizable window with a sidebar, and a 380 pt panel cannot show it.
3. Introduce a view-model per screen. Rejected: no screen needs state that
   `AppModel` does not already publish, so this adds layers without changing
   what the user sees.

The owner picked the layout (mockup 1 of three). The implementation approach is
a builder call, since only one approach fits.

## The design

### Approved mockup

Mockup 1 in `variants-v5.html`, from the 2026-11-18 visual companion session.
It is not committed, being a throwaway brainstorm file. In words: a sidebar with
server names, and a detail pane with the name, the address and agent, one
protection line, the key list, the check result, and a bottom bar.

```
┌────────────┬──────────────────────────────────────────────┐
│ ● ● ●      │ production                                   │
│ [search]   │ deploy@203.0.113.7 · Secretive ▾             │
│ production │ ⛉ Identity filtering only   Change…          │
│ staging    │                                              │
│ build-box  │ Keys sessions on this server may use (fwd)   │
│            │ ┌──────────────────────────────────────────┐ │
│            │ │ Development Key  ECDSA · SHA256:…     ⧉  │ │
│            │ │ Backup Key       ED25519 · SHA256:…   ⧉  │ │
│            │ └──────────────────────────────────────────┘ │
│            │ Edit Keys…                                   │
│            │ 2 forwarded … · Login uses Secretive, unf.   │
│            │                                              │
│            │ ✓ Check passed · 16:53                       │
│            │ Forwarded key can sign for any server while… │
│            │ SigSieve checks again when it connects       │
│            │ ▸ Details                                    │
│ + Add      ├──────────────────────────────────────────────┤
│            │ <status text>      [Check Again] [Connect ▶] │
└────────────┴──────────────────────────────────────────────┘
```

### Scenes

- **Main window**: `Window("SigSieve", id: "main")` with a
  `NavigationSplitView`. It is resizable, with a minimum of about 640×460 pt
  (builder call). It opens at launch and from the menu bar. It is a single
  window, so a second "Open" brings the existing one forward.
- **Menu bar**: the existing `MenuBarExtra` and its icon, including the error
  badge from `MenuBarIcon`. Its content is described under "Menu bar" below.
- **Settings**: a second `Window("Settings", id: "settings")` scene opened with
  `openWindow`, plus a ⌘, command **(builder call)**. A SwiftUI `Settings`
  scene would need `SettingsLink` (macOS 14) or a private selector on macOS 13,
  and the deployment target stays 13.0.
- The app stays `LSUIElement` at launch. While the main window is open it
  appears in the Dock and in ⌘Tab (`NSApp.setActivationPolicy(.regular)`);
  when the main window closes it goes back to the menu bar only (`.accessory`)
  **(owner)**. Opening the main window also calls `NSApp.activate` so it comes
  to the front.

### Sidebar

- One row per server from the existing `model.filteredServers` source (aliases
  plus saved profiles), selected through `model.selectedServer`. The sidebar
  uses `.searchable`, bound to `serverQuery`.
- Rows show the server name only. **No per-server check dots (builder call).**
  The app keeps one check at a time, and changing the selected server clears it.
  This is existing gate behaviour and is not to be changed. A dot on another
  server would show a result the gate no longer honours, which breaks the first
  anti-goal. Mockup 1 showed dots; this document drops them.
- "+ Add Server" at the bottom opens a small sheet with the existing field and
  its error text. It calls `addServer`.
- "Include not read: …" (verbatim, existing) appears as a caption under the
  list when `discovery.skippedIncludes` is not empty.
- The last selected server is remembered in UserDefaults (key
  `selectedServer`) and selected again at launch if it still exists; otherwise
  nothing is selected **(builder call)**. Selecting it at launch goes through
  the normal `selectedServer` path, so the check starts idle.
- If the search filters out the selected server, the detail pane stays on it.
- With nothing selected, the detail pane shows a centred "Choose a server."

### Detail pane (one `ScrollView`; no inner scrolling)

Top to bottom:

1. **Blocking errors**, only when present: the existing `StatusRow` messages,
   word for word, each a red-icon line of selectable text. They are not in a
   box.
2. **Header**: the server name as a title, then the address. After the address
   is the agent name, a `Menu` built from the existing `agentOptions`. Choosing
   one calls `setAgent`. Next to it is the agent state: "· N keys", "· no keys",
   or the "Agent not reachable: …" text. These are the existing `StatusRow`
   strings, moved here.
3. **Protection line**: a shield symbol, "Identity filtering only" or
   "Destination binding", and a "Change…" link that opens the Protection sheet.
   In filtering mode, the line "Forwarded key can sign for any server while
   connected" sits directly under it at all times, not only after a check
   (acceptance condition 3).
4. **Keys**: the existing heading "Keys sessions on this server may use
   (forwarded agent)". Below it is a bordered group with one row per forwarded
   key: comment (or "(no comment)"), type and short fingerprint in monospace, a
   copy-fingerprint button. There is no Remove on the row: every change to the
   forwarded keys goes through "Edit Keys…" and Save **(owner)**. Rows are not
   toggles, so a row click does nothing. The key badge is a neutral grey `key` symbol.
   - Then the "Edit Keys…" link.
   - Then the existing captions "\(n) forwarded to this server · applies to new
     connections" and "Login uses \(agent), unfiltered."
   - With no key forwarded, the group shows "No keys forwarded" and the
     "Edit Keys…" link stays.
   - A forwarded fingerprint that is not in the agent's current key list (agent
     unreachable or empty, or the key removed from it) still gets a row: short
     fingerprint, "Not in the agent" (new text) in secondary text, and copy
     **(builder call)**. Today such keys are invisible; the redesign
     must never hide part of the forwarding policy.
5. **Binding section**, only in binding mode:
   - The existing policy problem text, when there is one.
   - The heading "Onward servers the key may log in to". The list shows the
     name, type, short fingerprint and "· from your known_hosts" where that
     applies, with a Remove button. "Add Host Key…" opens a sheet. Host-key
     Remove and the Add buttons in the Add Host Key and Add Server sheets keep
     today's immediate save: they are explicit single actions, and each clears
     the check. This is the only exception to Save-only editing **(owner)**.
   - The existing caption "Destination binding names the servers the forwarded
     key may log in to onward from this server, for example github.com. It does
     not protect the login to this server itself."
   - The existing "SigSieve does not verify that these host keys belong to the
     server."
   - The heading "Limits" and the three existing limit lines. They stay visible
     on the main screen because the owner asked for security limits to be shown
     plainly.
6. **Check result**, only when `checkState` is `.finished` and, for a pass, only
   when `canConnect`, as today:
   - A pass shows the line "Check passed · HH:mm" in green with
     `checkmark.circle.fill`. Below it, in filtering mode, is "Forwarded key can
     sign for any server while connected" at body size. Then comes "SigSieve
     checks again when it connects" in secondary text.
   - A failure shows the existing title (for example "sigsieve connect --dry-run
     failed") in red with `xmark.octagon.fill`. Below it are the CLI hint and
     then the existing known_hosts paragraph.
   - In both cases, last comes a **"Details"** `DisclosureGroup`, collapsed by
     default. It holds the result lines as label/value pairs, the raw output as
     selectable monospace text (no fixed height, no inner scroll view) and, for
     a pass, the copyable command and its copy button.
   - The existing "Some Include files cannot be tracked; SigSieve checks again
     when you connect." and `connectError` (red, selectable) sit directly under
     the result.
   - The time is the time the check finished. That timestamp is new view state
     in `AppModel`, stored next to `checkState`, and it is cleared with it.

### Bottom bar (fixed, outside the scroll view)

- On the left is a status text: `inputsProblem` when there is one; otherwise
  "Checking…" or "Waiting for agent…" with a small spinner while running.
  Otherwise it says "Check before connecting." (new text) when not checked, and
  "Fix the problem above, then check again." (new text) after a failure. It is
  empty after a pass.
- On the right is **Check Connection**, which reads "Check Again" once a result
  exists. It is disabled while running or when `inputsProblem` is set.
- Then **Connect in Terminal**, the default action. It is disabled unless
  `canConnect`.

### Sheets

- **Edit Keys…** lists every agent key with the existing search field. That
  field is needed for agents with 500 keys. Each row has a checkbox, the comment
  and the fingerprint. Cancel discards the changes and **Save** stores them.
  - This changes behaviour: today each click is saved immediately. The new model
    method is `setForwardedKeys(selection:)`, one `edit` call that replaces the list.
  - Forwarded fingerprints that are not in the agent appear at the top of the
    sheet under "Not in the agent", checked, so they are kept unless the user
    unticks them. Save never drops a key the user did not see **(builder
    call)**.
  - Saving resets the check through the existing `inputsChanged` path.
- **Protection** (from "Change…") has two radio options, each with its full
  explanation:
  - "Identity filtering only", with "Forwarded key can sign for any server while
    connected".
  - "Destination binding", with the existing binding caption and the three
    limit lines.
  - Cancel and **Save** follow, and Save calls `setMode`. Today the mode is a
    picker that saves at once. No new explanatory sentences are added.
- **Add Host Key…** contains the existing known_hosts list and manual entry,
  word for word, as today:
  - "Add a host key"
  - both caveats
  - RSA rows disabled
  - the fingerprint help paragraph
  - the "Enter a name…" error
  - It saves each Add immediately, as today.
- **Add Server**: as in "Sidebar".

### Settings window

One `Form` with `.formStyle(.grouped)` (System Settings style), 500 pt wide,
no tabs **(owner decision 2026-11-19)**:

- **Default agent for new servers.** A menu `Picker` ("Secretive", "OpenSSH
  agent"). Choosing Secretive applies it at once (nothing is saved if it is
  already the default). Choosing OpenSSH saves nothing; it only reveals the
  row "Agent socket path" with a text field and "Use". While OpenSSH is chosen
  but the default is not that socket, the caption "Not saved yet. The default
  agent is unchanged." shows. The existing socket error texts are unchanged.
  The section footer is "Existing servers keep their own agent."
- **SigSieve CLI.** The row "Path (optional, absolute)" with the field (prompt
  "Found automatically when empty") and "Save", the existing error, then
  read-only rows for CLI and Version. Values are selectable, monospaced,
  right-aligned and wrap instead of truncating.
- **Profiles file**, as a read-only row.

The socket and CLI path are saved only by pressing "Use" or "Save". Return in
either field saves nothing. Invalid input shows the existing message and keeps
the working setting.

### Menu bar

The `.window` style panel is about 260 pt wide and holds:

- the selected server and its check state in words: "Check passed 16:53" only
  when `canConnect`, "Checking…" while running, "Check failed" after a failure,
  otherwise "Not checked"; or "No server selected";
- any blocking error, as a single line with the existing text;
- "Open SigSieve" (default), "Settings…" and "Quit SigSieve".

It never starts a check or a connection.

### Refresh triggers

`refresh()` runs when the main window appears and whenever it becomes key, as
the menu panel's did. The observer should be scoped to the main window, so that
Settings becoming key does not refresh. It must still fire on every reopen,
because manual item 7 depends on it. "Open SigSieve" also calls `refresh()`
explicitly, since a window that is already key does not become key again.

### Visual style

- System font and system colours only. Use `.secondary` for captions, and
  `.green` and `.red` only for check outcomes and errors. The warning line uses
  an orange `exclamationmark.triangle`, with the text in the primary colour.
- There are no custom backgrounds; the sidebar uses the standard sidebar
  material.
- Group boxes use `.background(.background)` with a hairline border and 8 pt
  corners, in the System Settings style.
- Spacing is generous: about 20 pt padding in the detail pane and 20 pt between
  sections.

## Acceptance conditions (owner, 2026-11-18)

The plan turns each into explicit acceptance criteria with a test or a manual
check.

1. **Save and Check.** Unsaved changes in a sheet change nothing: the profile,
   the check result and Connect stay as they were until Save. Save goes through
   `edit`; if any input the gate compares changed, the earlier passed check is
   cleared and Connect is disabled until a new check passes.
2. **Missing keys.** A forwarded key that disappears from the agent stays in
   the profile, but is never shown as usable: no comment or type, "Not in the
   agent", secondary style. When it reappears it is matched to the profile by
   its SHA256 fingerprint only, never by comment or type.
3. **Warnings.** No security warning is inside the collapsed "Details". In
   filtering mode, the fact that identity filtering is not destination binding
   is visible at all times (protection line plus its warning line).
4. **Window lifecycle.** Tested manually on macOS: Dock and ⌘Tab presence with
   the window open and absent after closing it; reopening from the menu bar
   (including when already open); opening and closing Settings; restoring the
   last selected server, including when it no longer exists.

## Removed from the approved mockup

- **Address line in the header** (mockup: "deploy@203.0.113.7 · Secretive").
  Removed during Task 3 by controller ruling: the app holds only the server
  alias, and resolving the real user and host would need `ssh -G`, which App
  code may not run. The header shows the server name and the agent. The owner
  reviews this during visual acceptance (2026-11-18).

## New user-facing texts (need owner approval)

- "Check before connecting."
- "Fix the problem above, then check again."
- "No keys forwarded"
- "Choose a server." This text already exists, as the `inputsProblem` text.
- "Onward servers the key may log in to"
- "Not in the agent"
- Menu bar states "Check failed", "Not checked", "No server selected"
  (required by "Menu bar"; listed 2026-11-18)
- "Identity filtering only", "Check Again", and the " · HH:mm" suffix of
  "Check passed" (required by the sections above; listed here 2026-11-18)
- "The agent's keys changed during the check before connecting. Check again."
  (connect error; added 2026-11-18 by ledger ruling in Task 2)
- "See above."
- "Existing servers keep their own agent."
- "Open SigSieve", "Quit SigSieve", "Edit Keys…", "Change…", "Add Host Key…",
  "+ Add Server", "Details"

Every security warning keeps its current wording.

## Left to the builder

- Exact sizes, spacing and SF Symbol choices, within "Visual style".
- How the sheets are wired. The sheets are presented from the detail view.
- Whether "Add Server" is a sheet or an inline field in the sidebar footer.
