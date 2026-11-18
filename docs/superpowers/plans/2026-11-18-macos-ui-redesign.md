# SigSieve macOS UI Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the 380 pt menu bar panel with a resizable main window (sidebar of servers, detail pane, fixed bottom bar), a separate Settings window and a small menu bar status panel. Behaviour, gate and security rules stay as they are.

**Architecture:** The views are new SwiftUI files under `macos-app/App/Views/` on top of the existing `AppModel`. `AppModel` gains a few small additions: `setForwardedKeys`, `checkFinishedAt` and a remembered selection. The logic that decides which forwarded keys show as "Not in the agent", and how a sheet's selection becomes the new key list, is a pure additive helper in SigSieveKit with unit tests. No existing Kit file changes.

**Tech Stack:** SwiftUI and AppKit, macOS 13.0 deployment target, Swift Testing, Xcode 26.6. The project uses file-system-synchronized groups, so new files under `App/` need no `project.pbxproj` edit.

**Spec:** `docs/superpowers/specs/2026-11-18-macos-ui-redesign-design.md`. It is the authority on layout. `macos-app/DESIGN.md` remains the authority on behaviour.

## Global Constraints

- Owner limit on the Kit exception (2026-11-18): `ForwardedKeys.swift` only builds the displayed key list and matches saved fingerprints to the agent's keys by SHA256 fingerprint. It never treats a missing key as usable, never reinterprets the policy and never authorises a connection; nothing in the gate, `CheckInputs` or `CommandBuilder` may call it.
- No change to the Rust CLI or to any existing file under `macos-app/Packages/SigSieveKit/Sources/`. The only Kit change is one new file, `Profiles/ForwardedKeys.swift`, plus its test file.
- `MACOSX_DEPLOYMENT_TARGET = 13.0` stays. No API newer than macOS 13 without an `if #available` fallback. No `SettingsLink`.
- Every existing user-facing security text keeps its exact wording, as listed in the spec, "Detail pane".
- No App string may say a server "sees", "cannot see" or has keys "hidden". The question stays "Keys sessions on this server may use (forwarded agent)".
- `SourceRulesTests` assertions may be updated only to follow a moved text or call: change the file path and the indentation inside the pinned string. An assertion is never deleted or weakened.
- Colour: `.green` and `.red` only for check outcomes and errors; an orange `exclamationmark.triangle` for the warning icon. Key badges use a neutral grey `key` symbol.
- No nested scrolling in the main window: exactly one `ScrollView` in the detail pane, and `List` only in the sidebar and in the Edit Keys and Add Host Key sheets.
- New texts are exactly the spec's "New user-facing texts" list. Add nothing else without a ledger ruling.
- Fictional names only: production, staging, build-box, 203.0.113.7, `.invalid`.
- Commit locally after each task. Never push.

## Owner acceptance conditions (from the spec)

| # | Condition | Proven by |
|---|-----------|-----------|
| AC1 | Unsaved sheet changes change nothing; Save that changes gate inputs clears a passed check | Task 1 tests, Task 2 source-rule test, Task 4 draft state, manual M1 |
| AC2 | Missing key stays in profile, never looks usable, re-matched by SHA256 fingerprint only | Task 1 tests, Task 3 rows, manual M2 |
| AC3 | No warning inside "Details"; filtering ≠ binding always visible | Task 3 source-rule tests, manual M3 |
| AC4 | Window lifecycle (Dock/⌘Tab, reopen, Settings, restored selection) | Task 5, manual M4a–M4e |

## Review Focus

1. **Agent unreachable or empty while keys are forwarded.** Every forwarded key shows as "Not in the agent". Edit Keys still shows and keeps them. Owned by Task 1 test `allMissingWhenAgentEmpty` and Task 4 manual step.
2. **500 keys in the Edit Keys sheet.** Search stays responsive and Save keeps the agent's order for new keys. Owned by Task 1 test `newKeysAppendInAgentOrder` and manual item 1 re-run (Task 6).
3. **A remembered selection that no longer exists or is not a valid `HostInput`.** Nothing is selected and nothing crashes. Owned by Task 2's source-rule assertion (`HostInput(stored)` and `servers.contains(host)`) and manual M4e.
4. **Long values in the header.** A long OpenSSH socket path or a long server name must not hide the key count; the path truncates in the middle and shows in full in `.help`. Owned by Task 3, step "header truncation".
5. **Reopening the window after `touch ~/.ssh/config`.** The result is cleared (manual item 7). This includes "Open SigSieve" while the window is already key. Owned by Task 5 refresh wiring and manual item 7 re-run.

---

### Task 1: Forwarded-key helper in SigSieveKit

**Files:**
- Create: `macos-app/Packages/SigSieveKit/Sources/SigSieveKit/Profiles/ForwardedKeys.swift`
- Test: `macos-app/Packages/SigSieveKit/Tests/SigSieveKitTests/ForwardedKeysTests.swift`

**Interfaces:**
- Produces:
  ```swift
  public enum ForwardedKeyRow: Hashable, Identifiable, Sendable {
      case inAgent(AgentKey)
      case notInAgent(Fingerprint)
      public var id: Fingerprint { get }
  }
  public enum ForwardedKeys {
      /// One row per forwarded fingerprint, in profile order; matched to agent keys by fingerprint only.
      public static func rows(forwarded: [Fingerprint], agentKeys: [AgentKey]) -> [ForwardedKeyRow]
      /// The new forwardedKeys after a sheet's Save: kept keys in their current order, then
      /// newly selected agent keys in agent order. Fingerprints not in the agent are kept iff selected.
      public static func applying(selection: Set<Fingerprint>, to current: [Fingerprint], agentKeys: [AgentKey]) -> [Fingerprint]
  }
  ```

- [ ] **Step 1: Write the failing tests** in Swift Testing (`@Test`, `#expect`), following the style of `AgentKeysTests.swift`. Use fixed fingerprints such as `Fingerprint("SHA256:" + String(repeating: "A", count: 43))!`.
  - `matchesByFingerprintOnly`: agent key K1 has fingerprint F1 and comment "Development Key". Forwarded is `[F1, F2]`, and the agent holds K1 plus K3, where K3 has fingerprint F3 and the same comment "Development Key". The result is `[.inAgent(K1), .notInAgent(F2)]`.
  - `reappearingKeyUsesAgentData`: forwarded `[F1]`, agent `[]` gives `[.notInAgent(F1)]`. With the agent holding K1 (comment "renamed"), the result is `[.inAgent(K1)]`.
  - `allMissingWhenAgentEmpty`: forwarded `[F1, F2]`, agent `[]` gives two `.notInAgent` rows in order.
  - `unchangedSelectionIsIdentical`: current `[F2, F1]`, selection `{F1, F2}` gives `[F2, F1]` (same order, so the gate inputs are equal).
  - `newKeysAppendInAgentOrder`: current `[F2]`, agent `[K1, K2, K3]`, selection `{F3, F2, F1}` gives `[F2, F1, F3]`.
  - `deselectedRemoved`: current `[F1, F2]`, selection `{F2}` gives `[F2]`.
  - `missingKeyKeptOnlyIfSelected`: current `[F9]`, where F9 is not in the agent. Selection `{F9}` gives `[F9]`; selection `{}` gives `[]`.
  - `openAndSaveKeepsMissingKeys`: current `[F1, F9]`, agent `[K1]` (F9 missing). `applying(selection: Set(current), to: current, agentKeys:)` returns `[F1, F9]` exactly: opening Edit Keys and pressing Save without changes never drops a missing key (owner condition).
  - `selectionOfUnknownFingerprintIgnored`: current `[]`, agent `[K1]`, selection `{F9}` gives `[]`. Only keys the sheet showed can be added.

- [ ] **Step 2: Run** `swift test --package-path macos-app/Packages/SigSieveKit --filter ForwardedKeysTests`. Expected: build FAIL, because `ForwardedKeys` is not defined.

- [ ] **Step 3: Implement** the two functions in `ForwardedKeys.swift`. Use a dictionary from fingerprint to `AgentKey`. Never compare comments or types.

- [ ] **Step 4: Run** the same command. Expected: 8 tests pass. Then run the full suite: `SIGSIEVE_TEST_CLI="$PWD/target/release/sigsieve" swift test --package-path macos-app/Packages/SigSieveKit` from the repo root, after `cargo build --release --locked`. Expected: all pass, only the fish test skipped.

- [ ] **Step 5: Commit** with the message `macos-app: ForwardedKeys helper for missing-key rows and sheet saves`.

### Task 2: AppModel additions

**Files:**
- Modify: `macos-app/App/AppModel.swift`. The edit section is near `toggleKey` (around line 398); the check state is around lines 308–383; `init` is around line 54.
- Test: `macos-app/Packages/SigSieveKit/Tests/SigSieveKitTests/SourceRulesTests.swift`, which gets a new test.

**Interfaces:**
- Consumes: `ForwardedKeys.rows`, `ForwardedKeys.applying` (Task 1).
- Produces:
  - `var forwardedRows: [ForwardedKeyRow]` is `ForwardedKeys.rows(forwarded: selectedProfile?.forwardedKeys ?? [], agentKeys: agentKeys)`.
  - `func setForwardedKeys(selection: Set<Fingerprint>)` is `edit { $0.forwardedKeys = ForwardedKeys.applying(selection: selection, to: $0.forwardedKeys, agentKeys: agentKeys) }`.
  - `@Published private(set) var checkFinishedAt: Date?` is set to `Date()` everywhere `checkState = .finished(...)` is assigned. It is set to `nil` in `resetCheck()` and wherever `checkState` becomes `.idle`.
  - Selection memory uses UserDefaults key `"selectedServer"` (`static let selectedServerKey`):
    - `selectedServer.didSet` writes `selectedServer?.value`, or removes the key when nil.
    - At the end of the first `refresh()`, if `selectedServer == nil`, the model restores `HostInput(stored)` only when it is non-nil and contained in `servers`.
  - Keep `toggleKey` until Task 5 removes its last caller, then delete it in Task 5.

- [ ] **Step 1: Write the failing source-rule test** `@Test func keyEditsAndCheckTimeFollowTheGate()` in `SourceRulesTests.swift`. It reads `AppModel.swift` and expects these exact strings:
  - `func setForwardedKeys(selection: Set<Fingerprint>) {\n        edit { $0.forwardedKeys = ForwardedKeys.applying(selection: selection, to: $0.forwardedKeys, agentKeys: agentKeys) }`
  - Inside the `resetCheck()` body: `checkFinishedAt = nil`
  - The count of `checkState = .finished(` equals the count of `checkFinishedAt = Date()`.
  - `if let stored = defaults.string(forKey: Self.selectedServerKey), let host = HostInput(stored), servers.contains(host)`

- [ ] **Step 2: Run** `swift test --package-path macos-app/Packages/SigSieveKit --filter SourceRulesTests`. Expected: the new test FAILS.

- [ ] **Step 3: Implement** the four additions. `save()` already calls `inputsChanged()`, so a Save that changes the list resets a passed check (AC1). A Save that does not change it keeps the check, because the inputs are equal.

- [ ] **Step 3a:** In the same test file, add `@Test func forwardedKeysHelperGrantsNothing()`: none of `ConnectionCheck.swift`, `CommandBuilder.swift` or `AppModel.swift`'s `currentInputs` body mention `ForwardedKeys`.

- [ ] **Step 4: Run** the full Kit suite and then `xcodebuild -project macos-app/SigSieve.xcodeproj -scheme SigSieve -configuration Debug -derivedDataPath macos-app/build build`. Expected: tests pass and the build reports `** BUILD SUCCEEDED **`.

- [ ] **Step 5: Commit** with the message `macos-app: model support for sheet saves, check time and remembered server`.

### Task 3: Main window views

**Files:**
- Create in `macos-app/App/Views/`:
  - `MainWindow.swift`: the `NavigationSplitView`, sidebar and detail container, and the bottom bar.
  - `ServerHeader.swift`: blocking errors, name, address, agent `Menu` and agent state.
  - `ProtectionLine.swift`
  - `ForwardedKeysGroup.swift`
  - `BindingSection.swift`
  - `CheckResultView.swift`
- Modify: `macos-app/App/Views/StatusRow.swift`. Add `enum StatusText` holding `static func blockingErrors(_ model: AppModel) -> [String]`, `static func agentSummary(_ model: AppModel) -> String`, and the two existing `describe` functions, moved unchanged. Keep the file name, since `emptyCLISearchListHasItsOwnMessage` reads it. The `StatusRow` view stays and calls `StatusText`, because the old panel uses it until Task 5 deletes it. Update `StatusRow.describe` callers to `StatusText.describe`.
- Test: `SourceRulesTests.swift`, which gets new tests and moved paths.

**Interfaces:**
- Consumes: `model.forwardedRows`, `model.checkFinishedAt`, `model.setAgent`, `model.removeHostKey`, `model.canConnect`, `model.inputsProblem`, `model.copyableCommand`, `model.connectError`.
- Produces: `struct MainWindow: View`, the scene content for Task 5. Sheets are opened through `@State` booleans in `MainWindow`:
  - `showEditKeys`
  - `showProtection`
  - `showAddHostKey`
  - `showAddServer`

  Task 4 supplies the sheet views. Until then, each sheet shows `Text("…")`.

Layout, texts, order and states are exactly the spec's sections "Sidebar", "Detail pane" and "Bottom bar". Points the spec leaves open are decided here:

- Key rows. Remove calls `model.setForwardedKeys(selection: Set(current).subtracting([fp]))`, an immediate and explicit single action. A `.notInAgent` row shows `fp.short`, then "Not in the agent" in `.secondary`, then copy and Remove. It shows no comment and no type.
- The agent `Menu` options use the existing `agentOptions` logic, copied from `AdvancedSection` into `ServerHeader` (Task 5 deletes the original).
- Header truncation: the agent name uses `.lineLimit(1).truncationMode(.middle)` with `.help(fullName)`, and the key count is a separate `Text` with `.layoutPriority(1)`. This covers Review Focus 4.
- The check time is formatted as `checkFinishedAt.formatted(date: .omitted, time: .shortened)`.
- The detail `ScrollView` holds sections 1–6. The bottom bar sits outside it in a `VStack`, with `Divider()` above it.

- [ ] **Step 1: Write the failing source-rule tests:**
  - `@Test func warningsAreOutsideDetails()`. In `CheckResultView.swift`, the index of `"SigSieve checks again when it connects"` and of `"If the server's host key is not in known_hosts, OpenSSH refuses the connection.` are both less than the index of `DisclosureGroup("Details"`. `ProtectionLine.swift` contains `Text("Forwarded key can sign for any server while connected")` and `"Identity filtering only"` and `"Destination binding"`. (AC3)
  - `@Test func noVisibilityWording()`. For every file under `App/`, the file text contains none of the substrings ` sees `, `cannot see`, `hidden from`, `stay hidden`.
  - `@Test func missingKeysAreLabelled()`. `ForwardedKeysGroup.swift` contains `case .notInAgent(` and `"Not in the agent"`. (AC2)
  - Move the `untracked` pin in `connectRechecksWhenIncludesAreUntracked` from `Views/CheckSection.swift` to `Views/CheckResultView.swift`, adjusting only indentation.
  - Move the binding caption pins that stay on the main screen to `Views/BindingSection.swift`: `"SigSieve does not verify that these host keys belong to the server."`, plus the destination-binding caption and the three limit lines, each as an exact `Text("…")`. The known_hosts list pins move in Task 4.

- [ ] **Step 2: Run** `swift test --package-path macos-app/Packages/SigSieveKit --filter SourceRulesTests`. Expected: the new and moved tests FAIL, because the files are missing.

- [ ] **Step 3: Implement** the six views and the `StatusText` change.

- [ ] **Step 4: Run** the Kit suite and the Debug `xcodebuild` from Task 2. Expected: all pass and the build succeeds. `MainWindow` is not shown yet; Task 5 wires it.

- [ ] **Step 5: Commit** with the message `macos-app: main window views (sidebar, detail, check result, bottom bar)`.

### Task 4: Sheets

**Files:**
- Create in `macos-app/App/Views/`:
  - `EditKeysSheet.swift`
  - `ProtectionSheet.swift`
  - `AddHostKeySheet.swift`
  - `AddServerSheet.swift`
- Modify: `MainWindow.swift`, to replace the placeholder sheet bodies.
- Test: `SourceRulesTests.swift`.

**Interfaces:**
- Consumes:
  - `model.agentKeys`, `model.keyQuery` / `KeyFilter`, `model.forwardedRows`, `model.setForwardedKeys(selection:)`
  - `model.setMode`, `model.knownHosts`, `model.knownHostsError`, `model.addKnownHost`, `model.addDestination`, `model.addServer`

Behaviour, per the spec's "Sheets":

- **EditKeysSheet**
  - Holds `@State var draft: Set<Fingerprint>`, initialised once in `.onAppear` from the profile's `forwardedKeys`.
  - Rows are checkboxes bound to `draft`. The "Not in the agent" section comes first and lists `.notInAgent` fingerprints. Then comes the searchable `List` of `agentKeys` (search uses its own `@State` query, not `model.keyQuery`).
  - Cancel calls `dismiss()` only. Save calls `model.setForwardedKeys(selection: draft)` and then `dismiss()`. Nothing touches the model before Save (AC1).
- **ProtectionSheet**
  - `@State var draft: ProtectionMode`, shown as two radio rows with full texts. Save calls `model.setMode(draft)`. Cancel dismisses.
- **AddHostKeySheet**
  - Contains the existing `knownHostsPicker`, `KnownHostRow` and `manualEntry` content, copied from `AdvancedSection.swift` with their texts and the `await model.addKnownHost(entry)` call unchanged. Copied, not moved: the old panel must still compile until Task 5 deletes the originals; rename private types if they clash. Each Add saves at once, as today.
  - "Done" closes it.
- **AddServerSheet**
  - The existing field, validation text and `addServer` call, copied from `ServerPicker.swift` (Task 5 deletes the original).

- [ ] **Step 1: Update the source-rule tests:**
  - `knownHostsPickerWiringAndWording` now reads `Views/AddHostKeySheet.swift` instead of `Views/AdvancedSection.swift`. It keeps every assertion except the "SigSieve does not verify…" pin, which Task 3 moved to `BindingSection.swift`. If the sheet also shows that sentence, keep the pin there too.
  - Add `@Test func sheetsSaveOnlyOnSave()`. `EditKeysSheet.swift` contains exactly one `model.setForwardedKeys(`, and it comes after `Button("Save")`. `ProtectionSheet.swift` contains exactly one `model.setMode(`, and it comes after `Button("Save")`. Neither file contains `.onDisappear` or `.onChange` calling the model, so closing the sheet with Esc or the window's close button saves nothing, exactly like Cancel.
  - In the same test, `EditKeysSheet.swift` initialises `draft` from `forwardedKeys` (all saved fingerprints, including missing ones), not from `agentKeys`.

- [ ] **Step 2: Run** the `SourceRulesTests` filter. Expected: FAIL.

- [ ] **Step 3: Implement** the four sheets and wire them in `MainWindow`.

- [ ] **Step 4: Run** the Kit suite and the Debug build. Expected: all pass and `** BUILD SUCCEEDED **`.

- [ ] **Step 5: Commit** with the message `macos-app: Edit Keys, Protection, Add Host Key and Add Server sheets`.

### Task 5: Scenes, Settings, menu bar, lifecycle; remove the old panel

**Files:**
- Modify: `macos-app/App/SigSieveApp.swift`
- Modify: `macos-app/App/Views/SettingsView.swift`. Remove `FooterView` and turn the view into a `Form`, per the spec's "Settings window", with the caption "Existing servers keep their own agent.".
- Create: `macos-app/App/Views/MenuStatusView.swift`
- Delete: `KeyList.swift`, `ServerPicker.swift`, `AdvancedSection.swift`, `CheckSection.swift`, the `MenuWindow` struct and the `StatusRow` view struct (keep `enum StatusText` in `StatusRow.swift`). Delete `toggleKey` from `AppModel.swift`.

**Interfaces:**
- Consumes: `MainWindow` (Task 3).

Decisions:

- **Scenes:**
  - `Window("SigSieve", id: "main") { MainWindow() }` with `.defaultSize(width: 820, height: 600)`; `MainWindow` sets `.frame(minWidth: 640, minHeight: 460)`.
  - `Window("Settings", id: "settings") { SettingsView() }` with `.windowResizability(.contentSize)`.
  - `.commands { CommandGroup(replacing: .appSettings) { Button("Settings…") { openWindow(id: "settings") }.keyboardShortcut(",") } }`.
  - `MenuBarExtra` keeps its label and `MenuBarIcon` unchanged, with `MenuStatusView` as content.
- **Activation:**
  - `MainWindow.onAppear` calls `NSApp.setActivationPolicy(.regular)` and `NSApp.activate(ignoringOtherApps: true)`. Use `ignoringOtherApps`; macOS 13 lacks the parameterless form.
  - `.onDisappear` calls `NSApp.setActivationPolicy(.accessory)`. Settings never changes the policy.
- **Refresh:**
  - `MainWindow` runs `refresh()` in `.onAppear`, and on `NSWindow.didBecomeKeyNotification` only when `($0.object as? NSWindow)?.identifier?.rawValue` equals the main window's identifier.
  - Capture the identifier in a small `NSViewRepresentable` that reads `view.window`. SwiftUI sets it to `"main"`-prefixed values, so compare with `hasPrefix("main")`.
  - The "Open SigSieve" menu item calls `openWindow(id: "main")`, then `NSApp.activate(ignoringOtherApps: true)`, then `Task { await model.refresh() }`. This covers Review Focus 5.
- **MenuStatusView:**
  - The text follows the spec's "Menu bar". It shows "Check passed HH:mm" only when `model.canConnect`, "Checking…" for `.running`, "Check failed" for a finished failure, and "Not checked" otherwise.
  - Below that come `StatusText.blockingErrors(model).first`, if there is one, then "Open SigSieve", "Settings…" and "Quit SigSieve".
- **Launch:** the main window opens at launch, which is the default for the first `Window` scene.

- [ ] **Step 1: Update the source-rule tests:**
  - Add `@Test func menuBarNeverClaimsReadyWithoutGate()`. In `MenuStatusView.swift`, the substring `"Check passed` appears exactly once, inside a branch that begins `if model.canConnect`. The file contains no `runCheck(` and no `connect(`.
  - Add `@Test func refreshOnOpen()`. `MenuStatusView.swift` contains `openWindow(id: "main")` and `await model.refresh()`.

- [ ] **Step 2: Run** the `SourceRulesTests` filter. Expected: FAIL.

- [ ] **Step 3: Implement** the changes and delete the old views.

- [ ] **Step 4: Run** the full Kit suite, then the Release build from CI:
  ```
  xcodebuild -project macos-app/SigSieve.xcodeproj -scheme SigSieve -configuration Release -derivedDataPath macos-app/build build
  ```
  Then `plutil -lint macos-app/build/Build/Products/Release/SigSieve.app/Contents/Info.plist`. Expected: all pass, `** BUILD SUCCEEDED **`, `OK`. Also run `git grep -n "toggleKey\|MenuWindow\|FooterView" macos-app/App`; expected output: nothing.

- [ ] **Step 5: Commit** with the message `macos-app: main window, Settings window and menu bar status; remove the old panel`.

### Task 6: Manual checklist and owner run

**Files:**
- Modify: `macos-app/README.md`, section "Manual checklist".

- [ ] **Step 1:** Append these manual checks to the checklist, after item 7, with the status "not run":
  - **M1 (AC1).** After a passed check, open Edit Keys, untick a key and press Cancel. The result and Connect are unchanged. Open the sheet again, untick and press Save. The result clears and Connect is disabled. Open the sheet again, change nothing and press Save. The result stays.
  - **M2 (AC2).** Use a throwaway OpenSSH agent (as in item 1) holding one synthetic key; forward it and run a check. `ssh-add -d` that key and reopen the window: the result is cleared, the row reads "Not in the agent" with no comment, and Edit Keys lists it ticked. `ssh-add` the same key file again and reopen: the row shows the key normally. Then add a second synthetic key with the same comment: it does not match the forwarded row, because the match is by fingerprint, not by name.
  - **M3 (AC3).** In filtering mode, "Forwarded key can sign for any server while connected" is visible before any check. After a pass, every warning is visible while Details is closed.
  - **M4a.** With the window open, SigSieve is in the Dock and in ⌘Tab. After closing the window it is in neither, and the menu bar icon stays.
  - **M4b.** "Open SigSieve" works with the window closed, behind other windows, and when it is already in front.
  - **M4c.** ⌘, and the menu's "Settings…" open one Settings window. Closing Settings leaves the main window and the Dock state unchanged.
  - **M4d.** Quit and relaunch: the last selected server is selected again, and its check is "Not checked".
  - **M4e.** Quit, run `defaults write dev.sigsieve.macos selectedServer no-such-server.invalid`, and relaunch. Nothing is selected and there is no error. Repeat with the value `-bad`.
- [ ] **Step 2:** Mark items 1, 2 and 7 for re-run on the new UI. Extend M1 with two more cases: close the sheet with Esc without Save (nothing changes), and open Edit Keys while a key is "Not in the agent", press Save without changes, and confirm the row is still there. Extend M3: read every warning in the real window with Details closed, in light and dark mode.
- [ ] **Step 2a: Full verification on the final commit.** From the repo root: `cargo build --release --locked`, then `SIGSIEVE_TEST_CLI="$PWD/target/release/sigsieve" swift test --package-path macos-app/Packages/SigSieveKit` (expected: all pass, only the fish test skipped, integration tests ran), then the Release `xcodebuild` and `plutil -lint` from Task 5. Record the counts in the task report. Earlier CI runs do not count for these commits; a new CI run needs a push, which needs fresh owner approval.
- [ ] **Step 3: Commit** with the message `macos-app: manual checks for the redesigned window`.
- [ ] **Step 4: Stop.** The owner runs the manual checks on their Mac, in the same way and under the same limits as on 2026-11-18: a test key, `.invalid` servers, and `touch` only. Do not push. A push to PR #74 needs fresh owner approval.
