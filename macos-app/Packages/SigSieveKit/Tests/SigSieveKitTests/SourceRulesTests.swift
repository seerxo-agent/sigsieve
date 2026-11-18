import Foundation
import Testing

// A second check, not the boundary (the boundary is ProcessRunner). Scans the
// Kit's Sources/ and macos-app/App/, which must exist.

private let kitRoot = URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
private let appRoot = kitRoot.deletingLastPathComponent().deletingLastPathComponent()
/// The one file allowed to start a process, relative to macos-app/.
private let processRunnerPath = "Packages/SigSieveKit/Sources/SigSieveKit/ProcessExecution/ProcessRunner.swift"

/// Each Swift file with its path relative to macos-app/.
private func sourceFiles() throws -> [(name: String, text: String)] {
    let app = appRoot.appending(path: "App")
    try #require(FileManager.default.fileExists(atPath: app.path), "macos-app/App/ is missing")
    let root = appRoot.standardizedFileURL.path(percentEncoded: false)
    let prefix = root.hasSuffix("/") ? root : root + "/"
    var files: [(String, String)] = []
    for root in [kitRoot.appending(path: "Sources"), app] {
        let e = try #require(FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil))
        for case let url as URL in e where url.pathExtension == "swift" {
            let path = url.standardizedFileURL.path(percentEncoded: false)
            #expect(path.hasPrefix(prefix), "\(path) is outside macos-app/")
            files.append((String(path.dropFirst(prefix.count)), try String(contentsOf: url, encoding: .utf8)))
        }
    }
    #expect(files.contains { $0.0 == processRunnerPath })
    #expect(files.contains { $0.0.hasPrefix("App/") })
    return files
}

@Test func onlyProcessRunnerUsesProcess() throws {
    for (name, text) in try sourceFiles() {
        for token in ["Process()", "NSTask", "Process.run(", "launchedProcess"] where name != processRunnerPath {
            #expect(!text.contains(token), "\(name) mentions \(token)")
        }
        for token in ["posix_spawn", "execv", "NSAppleScript"] {
            #expect(!text.contains(token), "\(name) mentions \(token)")
        }
        // libc system(); the Kit's own TempDir.system() is a different function.
        let withoutOwnSystem = text.replacingOccurrences(of: "func system(", with: "").replacingOccurrences(of: "TempDir.system(", with: "")
        #expect(!withoutOwnSystem.contains("system("), "\(name) calls system(")
    }
}

@Test func noSourceNamesTheSshBinary() throws {
    for (name, text) in try sourceFiles() {
        for token in ["/usr/bin/ssh\"", "\"ssh\"", "\"-G\""] {
            #expect(!text.contains(token), "\(name) mentions \(token)")
        }
    }
}

/// The picker's App wiring, which the Kit tests cannot reach: every file it reads, those files
/// in the check's stamps, and the two sentences that set expectations next to it.
@Test func knownHostsPickerWiringAndWording() throws {
    let app = appRoot.appending(path: "App")
    let model = try String(contentsOf: app.appending(path: "AppModel.swift"), encoding: .utf8)
    for path in ["\".ssh/known_hosts\"", "\"/etc/ssh/ssh_known_hosts\"", "\"/etc/ssh/ssh_known_hosts2\"", "\"/.ssh/known_hosts2\""] {
        #expect(model.contains(path), "AppModel.swift lacks \(path)")
    }
    #expect(model.contains("SSHConfigAliases.stamps(for: [knownHostsFile.path] + revocationFiles)"))
    #expect(model.contains("configStamps: discovery.stamps + knownHostsStamps"))
    #expect(model.contains("revocationFiles: revocationFiles.map"))
    let binding = try String(contentsOf: app.appending(path: "Views/BindingSection.swift"), encoding: .utf8)
    #expect(binding.contains("Text(\"SigSieve does not verify that these host keys belong to the server.\")"))
    let view = try String(contentsOf: app.appending(path: "Views/AddHostKeySheet.swift"), encoding: .utf8)
    #expect(view.contains("Text(\"SigSieve does not verify that these host keys belong to the server.\")"))
    #expect(view.contains("Text(\"Listed keys were found in your local known_hosts files. Custom UserKnownHostsFile, GlobalKnownHostsFile, KnownHostsCommand and RevokedHostKeys settings are not read.\")"))
    // A picker Add goes through the stale-list guard, never straight to addDestination.
    #expect(view.contains("await model.addKnownHost(entry)"))
    #expect(!view.contains("Destination(name: entry.name"))
    // A changed picker file resets the check and reloads, on Add and on refresh.
    #expect(model.contains("guard knownHostsStamps != knownHostsLoadedStamps else { return false }\n        resetCheck()\n        await loadKnownHosts()"))
    #expect(model.contains("let changed = await reloadKnownHostsIfChanged()\n        guard !changed, knownHosts.contains(entry) else {"))
    #expect(model.contains("if !(await reloadKnownHostsIfChanged()) { await loadKnownHosts() }"))
}

/// Return in the Edit Keys search must never Save: Save is not the default action and the field has no onSubmit.
@Test func editKeysReturnNeverSaves() throws {
    let src = try String(contentsOf: appRoot.appending(path: "App/Views/EditKeysSheet.swift"), encoding: .utf8)
    #expect(!src.contains(".keyboardShortcut(.defaultAction)"), "Save must not be the default action")
    #expect(!src.contains(".onSubmit"), "the search field must not submit to the model")
    // Brace-matched body of a button's action closure.
    func action(_ title: String) throws -> String {
        let r = try #require(src.range(of: "Button(\"\(title)\")"), "lacks \(title)")
        var depth = 0, body = "", started = false
        for c in src[r.upperBound...] {
            if c == "{" { depth += 1; started = true; if depth == 1 { continue } }
            if c == "}" { depth -= 1; if started && depth == 0 { break } }
            if started { body.append(c) }
        }
        return body.trimmingCharacters(in: .whitespacesAndNewlines)
    }
    // An explicit Save press still saves, and dismisses only when the save succeeded.
    #expect(try action("Save") == "if model.setForwardedKeys(selection: draft, for: server) { dismiss() }", "Save closure")
    // Esc still cancels, and Cancel only dismisses.
    #expect(try action("Cancel") == "dismiss()", "Cancel only dismisses")
    let cancel = try #require(src.range(of: "Button(\"Cancel\")"))
    #expect(src[cancel.upperBound...].prefix(120).contains(".keyboardShortcut(.cancelAction)"), "Cancel keeps Esc")
}

/// Settings saves the socket and CLI path only on the Use / Save buttons; Return saves nothing.
@Test func settingsSavesOnlyOnButtons() throws {
    let src = try String(contentsOf: appRoot.appending(path: "App/Views/SettingsView.swift"), encoding: .utf8)
    #expect(!src.contains(".onSubmit"), "no field may submit")
    #expect(!src.contains(".keyboardShortcut(.defaultAction)"), "no default action")
    // Hand-built cards sized by their content: no Form, no scrolling, height from content.
    #expect(!src.contains("Form {"))
    #expect(!src.contains("ScrollView"))
    #expect(src.contains(".fixedSize(horizontal: false, vertical: true)"))
    #expect(src.contains(".pickerStyle(.menu)"))
    // Brace-matched body of a button's action closure.
    func action(_ title: String) throws -> String {
        let r = try #require(src.range(of: "Button(\"\(title)\")"), "lacks \(title)")
        var depth = 0, body = "", started = false
        for c in src[r.upperBound...] {
            if c == "{" { depth += 1; started = true; if depth == 1 { continue } }
            if c == "}" { depth -= 1; if started && depth == 0 { break } }
            if started { body.append(c) }
        }
        return body.trimmingCharacters(in: .whitespacesAndNewlines)
    }
    #expect(try action("Use") == "useAgent(.openssh(socket: socket))")
    #expect(try action("Save") == "Task { await model.setCLIPath(cliPath) }")
    #expect(src.contains("\"Not saved yet. The default agent is still \\(model.agentName(for: model.defaultAgent)).\""), "caption names the active agent")
    #expect(!src.contains("Not saved yet. The default agent is unchanged."), "old caption removed")
    for text in ["Enter the agent socket path to use the OpenSSH agent. The default agent is unchanged.",
                 "The agent socket must be an absolute path (starting with /) without control characters. The default agent is unchanged.",
                 "Existing servers keep their own agent.",
                 "Path is optional and must be absolute."] {
        #expect(src.contains(text), "lost: \(text)")
    }
}

/// Settings is a sidebar of three panes with one-line rows, sized by the window, not a fixed 500 pt.
@Test func settingsSidebarLayout() throws {
    let src = try String(contentsOf: appRoot.appending(path: "App/Views/SettingsView.swift"), encoding: .utf8)
    for (title, symbol) in [("Agent", "key.fill"), ("Command Line", "terminal.fill"), ("Files", "doc.fill")] {
        #expect(src.contains("\"\(title)\"") && src.contains("\"\(symbol)\""), "lacks \(title) / \(symbol)")
    }
    #expect(src.contains("\"Socket\""))
    #expect(!src.contains(".frame(width: 500)"))
    #expect(src.contains("abbreviatingWithTildeInPath"))
    #expect(!src.contains("Path (optional, absolute)"))
}

/// The Settings window has no title-bar strip and is exactly as tall as its content.
@Test func settingsSceneFitsContent() throws {
    let src = try String(contentsOf: appRoot.appending(path: "App/SigSieveApp.swift"), encoding: .utf8)
    let start = try #require(src.range(of: "Window(\"Settings\", id: \"settings\")"))
    let end = try #require(src.range(of: "MenuBarExtra", range: start.upperBound..<src.endIndex))
    let scene = src[start.upperBound..<end.lowerBound]
    #expect(scene.contains(".windowStyle(.hiddenTitleBar)"))
    #expect(scene.contains(".windowResizability(.contentSize)"))
    #expect(!scene.contains(".defaultSize("))
}

/// Sheets keep a draft and write only on Save; Cancel, Esc and window close discard it.
@Test func sheetsSaveOnlyOnSave() throws {
    let views = appRoot.appending(path: "App/Views")
    for (file, call) in [("EditKeysSheet.swift", "model.setForwardedKeys("), ("ProtectionSheet.swift", "model.setMode(")] {
        let src = try String(contentsOf: views.appending(path: file), encoding: .utf8)
        #expect(src.components(separatedBy: call).count == 2, "\(file): exactly one \(call)")
        let save = try #require(src.range(of: "Button(\"Save\")"), "\(file) lacks Save")
        let at = try #require(src.range(of: call))
        #expect(save.lowerBound < at.lowerBound, "\(file): \(call) only after Save")
        #expect(src[at.upperBound...].prefix(while: { $0 != "\n" }).contains("for: server"), "\(file) passes for: server")
        #expect(src.contains("if \(call)") && src.contains(", for: server) { dismiss() }"), "\(file): dismiss only when the save succeeded")
        #expect(!src.contains(".onDisappear"))
        // The whole closure body, brace-matched, so a multi-line closure is checked too.
        for r in src.ranges(of: ".onChange(of: model.selectedServer)") {
            var depth = 0, body = "", started = false
            for c in src[r.upperBound...] {
                if c == "{" { depth += 1; started = true; continue }
                if c == "}" { depth -= 1; if started && depth == 0 { break } }
                if started { body.append(c) }
            }
            #expect(!body.contains("model."), "\(file): onChange must only dismiss")
        }
        #expect(src.contains(".onChange(of: model.selectedServer) { _ in dismiss() }"), "\(file): onChange is exactly a dismiss")
    }
    let appModel = try String(contentsOf: appRoot.appending(path: "App/AppModel.swift"), encoding: .utf8)
    #expect(appModel.contains("return edit { $0.forwardedKeys = ForwardedKeys.applying("))
    #expect(appModel.contains("return edit { $0.mode = mode }"))
    #expect(appModel.contains("private func edit(_ change: (inout Profile) -> Void) -> Bool {"))
    #expect(appModel.contains("return save(next)"))
    let edit = try String(contentsOf: views.appending(path: "EditKeysSheet.swift"), encoding: .utf8)
    #expect(edit.contains("ForwardedKeys.rows(forwarded: profile.forwardedKeys, agentKeys: model.agentKeys)"))
    #expect(!edit.contains("model.forwardedRows"))
    #expect(edit.contains("_draft = State(initialValue: Set(profile.forwardedKeys))"))
    #expect(!edit.contains("draft = Set(model.agentKeys"))
    let prot = try String(contentsOf: views.appending(path: "ProtectionSheet.swift"), encoding: .utf8)
    #expect(prot.contains("_draft = State(initialValue: profile.mode)"))
    let main = try String(contentsOf: views.appending(path: "MainWindow.swift"), encoding: .utf8)
    #expect(main.contains("EditKeysSheet(server: $0.server, profile: $0.profile)"))
    #expect(main.contains("ProtectionSheet(server: $0.server, profile: $0.profile)"))
    #expect(!main.contains("EditKeysSheet(server: model.") && !main.contains("ProtectionSheet(server: model."))
    #expect(main.contains("SheetTarget(server: $0, profile: model.profile(for: $0))"))
}

/// F2: when some Include files are untracked, connect() re-runs the whole check through the Kit
/// right before writing the launcher, and launches only if that re-check passed for the same
/// inputs. The decision itself is unit-tested in ConnectionCheckTests (recheckBeforeConnect).
@Test func connectRechecksWhenIncludesAreUntracked() throws {
    let app = appRoot.appending(path: "App")
    let model = try String(contentsOf: app.appending(path: "AppModel.swift"), encoding: .utf8)
    let start = try #require(model.range(of: "func connect() async {"))
    let end = try #require(model.range(of: "// MARK: Profile edits", range: start.upperBound..<model.endIndex))
    let body = String(model[start.upperBound..<end.lowerBound])
    func at(_ s: String) throws -> String.Index { try #require(body.range(of: s), "connect() lacks \(s)").lowerBound }
    let branch = try at("if discovery.untracked {")
    let recheck = try at("await ConnectionCheck.recheckBeforeConnect(inputs, runner: runner, gate: &recheckGate)")
    let same = try at("guard let now = currentInputs, now == inputs, !sshConfigChanged(), let nowTmp = verifiedTmp else {")
    let keep = try at("gate = recheckGate")
    let refuse = try at("guard passed else { return }")
    let write = try at("Launcher.write(inputs, under: tmp.path)")
    #expect(branch < recheck && recheck < same && same < keep && keep < refuse && refuse < write)
    #expect(body.components(separatedBy: "Launcher.write(").count == 2, "one launcher write in connect()")
    let view = try String(contentsOf: app.appending(path: "Views/CheckResultView.swift"), encoding: .utf8)
    #expect(view.contains("if model.discovery.untracked {\n                Text(\"Some Include files cannot be tracked; SigSieve checks again when you connect.\")"))
}

/// F3: a change to the CLI must run the app's integration tests, on push and on pull request.
@Test func ciRunsOnCLIChanges() throws {
    let workflow = appRoot.deletingLastPathComponent().appending(path: ".github/workflows/macos-app.yml")
    let text = try String(contentsOf: workflow, encoding: .utf8)
    let paths = "paths: ['macos-app/**', '.github/workflows/macos-app.yml', 'src/**', 'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml']"
    #expect(text.contains("  pull_request:\n    \(paths)\n  push:\n    \(paths)\n"))
}

/// F5: the Release app has hardened runtime and no injected get-task-allow; still ad hoc signed.
@Test func releaseSigningHygiene() throws {
    let project = try String(contentsOf: appRoot.appending(path: "SigSieve.xcodeproj/project.pbxproj"), encoding: .utf8)
    let start = try #require(project.range(of: "5C1A00000000000000000A04 /* Release */ = {"))
    let end = try #require(project.range(of: "name = Release;", range: start.upperBound..<project.endIndex))
    let release = project[start.upperBound..<end.lowerBound]
    for line in ["ENABLE_HARDENED_RUNTIME = YES;", "CODE_SIGN_INJECT_BASE_ENTITLEMENTS = NO;",
                 "CODE_SIGN_IDENTITY = \"-\";", "DEVELOPMENT_TEAM = \"\";"] {
        #expect(release.contains(line), "Release lacks \(line)")
    }
    #expect(!project.contains("CODE_SIGN_ENTITLEMENTS"))
}

/// F7: an empty search list gets its own message, never "Searched: " followed by nothing.
@Test func emptyCLISearchListHasItsOwnMessage() throws {
    let row = try String(contentsOf: appRoot.appending(path: "App/Views/StatusRow.swift"), encoding: .utf8)
    let empty = try #require(row.range(of: "case .notFound(let searched) where searched.isEmpty:\n            \"SigSieve CLI lookup was interrupted before it finished.\""))
    let general = try #require(row.range(of: "case .notFound(let searched):\n            \"SigSieve CLI not found. Searched:"))
    #expect(empty.lowerBound < general.lowerBound)
}

/// Sheet saves are server-guarded, a passed check dies when a forwarded key leaves the agent,
/// the finish time follows every finished state, and the selected server is remembered.
@Test func keyEditsAndCheckTimeFollowTheGate() throws {
    let model = try String(contentsOf: appRoot.appending(path: "App/AppModel.swift"), encoding: .utf8)
    func body(_ head: String, to next: String) throws -> String {
        let s = try #require(model.range(of: head), "AppModel lacks \(head)")
        let e = try #require(model.range(of: next, range: s.upperBound..<model.endIndex), "no \(next) after \(head)")
        return String(model[s.upperBound..<e.lowerBound])
    }
    #expect(model.contains("func setForwardedKeys(selection: Set<Fingerprint>, for server: HostInput) -> Bool {\n        guard selectedServer == server else { return false }\n        return edit { $0.forwardedKeys = ForwardedKeys.applying(selection: selection, to: $0.forwardedKeys, agentKeys: agentKeys) }"))
    #expect(model.contains("func setMode(_ mode: ProtectionMode, for server: HostInput) -> Bool {\n        guard selectedServer == server else { return false }"))
    #expect(try body("private func resetCheck() {", to: "// MARK: Check and connect").contains("checkedKeyPresence = nil"))
    #expect(try body("private func resetCheck() {", to: "// MARK: Check and connect").contains("checkFinishedAt = nil"))
    #expect(try body("private func refreshAgent() async {", to: "private func loadKnownHosts").contains("ForwardedKeys.present(forwarded: selectedProfile?.forwardedKeys ?? [], agentKeys: agentKeys) != p { resetCheck() }"))
    let connect = try body("func connect() async {", to: "// MARK: Profile edits")
    let refresh = try #require(connect.range(of: "verifyTmpdir()\n        await refreshAgent()"))
    let gate = try #require(connect.range(of: "guard canConnect"))
    #expect(refresh.lowerBound < gate.lowerBound)
    #expect(model.components(separatedBy: "checkState = .finished(").count == model.components(separatedBy: "checkFinishedAt = Date()").count)
    #expect(model.contains("if let stored = defaults.string(forKey: Self.selectedServerKey), let host = HostInput(stored), servers.contains(host)"))
}

/// The key-list helper only shapes the UI's selection; the check and the command never see it.
@Test func forwardedKeysHelperGrantsNothing() throws {
    let kit = kitRoot.appending(path: "Sources/SigSieveKit")
    for name in ["Check/ConnectionCheck.swift", "Command/CommandBuilder.swift"] {
        let found = try FileManager.default.enumerator(at: kit, includingPropertiesForKeys: nil)!.compactMap { $0 as? URL }
            .filter { $0.lastPathComponent == (name as NSString).lastPathComponent }
        #expect(!found.isEmpty, "\(name) not found")
        for url in found { #expect(!(try String(contentsOf: url, encoding: .utf8)).contains("ForwardedKeys"), "\(url.lastPathComponent) mentions ForwardedKeys") }
    }
    let model = try String(contentsOf: appRoot.appending(path: "App/AppModel.swift"), encoding: .utf8)
    let s = try #require(model.range(of: "var currentInputs: CheckInputs? {"))
    let e = try #require(model.range(of: "var canConnect: Bool {", range: s.upperBound..<model.endIndex))
    #expect(!model[s.upperBound..<e.lowerBound].contains("ForwardedKeys"))
}

/// Fix round 1: the agent-presence reset also holds on the connect re-check path, the check
/// snapshot is taken from a fresh agent answer, and every refreshAgent path compares presence.
@Test func agentPresenceResetHoldsOnEveryPath() throws {
    let model = try String(contentsOf: appRoot.appending(path: "App/AppModel.swift"), encoding: .utf8)
    func body(_ head: String, to next: String) throws -> String {
        let s = try #require(model.range(of: head), "AppModel lacks \(head)")
        let e = try #require(model.range(of: next, range: s.upperBound..<model.endIndex))
        return String(model[s.upperBound..<e.lowerBound])
    }
    // 1. connect(): a reset during the re-check stops before the result is shown or launched.
    let connect = try body("func connect() async {", to: "// MARK: Profile edits")
    func at(_ s: String) throws -> String.Index { try #require(connect.range(of: s), "connect() lacks \(s)").lowerBound }
    let snap = try at("let presenceBefore = checkedKeyPresence")
    let recheck = try at("await ConnectionCheck.recheckBeforeConnect(")
    let guardPresence = try at("guard presenceBefore != nil, checkedKeyPresence == presenceBefore else {")
    let keep = try at("gate = recheckGate")
    let reset = try at("checkedKeyPresence = ForwardedKeys.present(forwarded: now.profile.forwardedKeys, agentKeys: agentKeys)")
    let show = try at("checkState = .finished(result); checkFinishedAt = Date()")
    #expect(snap < recheck && recheck < guardPresence && guardPresence < keep && keep < reset && reset < show)
    // 2. runCheck(): fresh agent answer before the inputs and the snapshot.
    let run = try body("func runCheck() async {", to: "/// Ruling 7")
    let fresh = try #require(run.range(of: "await refreshAgent()"))
    let read = try #require(run.range(of: "guard let inputs = currentInputs"))
    #expect(fresh.lowerBound < read.lowerBound)
    // 3. refreshAgent(): the comparison runs after the unreachable and catch paths too.
    let agent = try body("private func refreshAgent() async {", to: "private func loadKnownHosts")
    let tmpFail = try #require(agent.range(of: "agentState = .unreachable(\"the temporary directory failed verification\")"))
    let catchPath = try #require(agent.range(of: "cannot be used\")"))
    let compare = try #require(agent.range(of: "ForwardedKeys.present(forwarded: selectedProfile?.forwardedKeys ?? [], agentKeys: agentKeys) != p { resetCheck() }"))
    #expect(tmpFail.lowerBound < compare.lowerBound && catchPath.lowerBound < compare.lowerBound)
    #expect(try #require(agent.range(of: "guard agent == (selectedProfile?.agent ?? defaultAgent) else { return }")).lowerBound < compare.lowerBound)
}

/// AC3: no security warning hides inside the collapsed Details, and filtering is never shown as binding.
@Test func warningsAreOutsideDetails() throws {
    let views = appRoot.appending(path: "App/Views")
    let result = try String(contentsOf: views.appending(path: "CheckResultView.swift"), encoding: .utf8)
    let details = try #require(result.range(of: "DisclosureGroup(\"Details\""))
    let recheck = try #require(result.range(of: "\"SigSieve checks again when it connects\""))
    let knownHosts = try #require(result.range(of: "\"If the server's host key is not in known_hosts, OpenSSH refuses the connection."))
    #expect(recheck.lowerBound < details.lowerBound && knownHosts.lowerBound < details.lowerBound)
    // The filtering warning is shown once, in ProtectionLine; a pass does not repeat it (owner 2026-11-19).
    let warning = "Forwarded key can sign for any server while connected"
    #expect(!result.contains(warning), "CheckResultView.swift repeats the filtering warning")
    // CLI warnings (`sigsieve: warning: …`) are shown above Details in both results, word for word.
    let cliWarning = try #require(result.range(of: "$0.label == \"sigsieve\" && $0.value.hasPrefix(\"warning:\")"))
    #expect(cliWarning.lowerBound < details.lowerBound)
    for result in ["PassedResult", "FailedResult"] {
        let s = try #require(view(result, in: try String(contentsOf: views.appending(path: "CheckResultView.swift"), encoding: .utf8)))
        let warn = try #require(s.range(of: "CLIWarnings(lines: lines)"), "\(result) lacks CLIWarnings")
        let det = try #require(s.range(of: "Details(result: result"), "\(result) lacks Details")
        #expect(warn.lowerBound < det.lowerBound)
    }
    let protection = try String(contentsOf: views.appending(path: "ProtectionLine.swift"), encoding: .utf8)
    for text in ["Text(\"Forwarded key can sign for any server while connected\")", "\"Identity filtering only\"", "\"Destination binding\""] {
        #expect(protection.contains(text), "ProtectionLine.swift lacks \(text)")
    }
    // Always visible in filtering mode: inside the `if !binding` body, never inside a DisclosureGroup.
    let notBinding = try #require(braceBody(after: "if !binding {", in: protection), "ProtectionLine lacks if !binding")
    #expect(notBinding.contains("Text(\"\(warning)\")"), "the filtering warning is not inside if !binding")
    #expect(!protection.contains("DisclosureGroup"))
    // The detail shows ProtectionLine for every selected server: not in a DisclosureGroup and not
    // in a branch on the check (before and after Check).
    let main = try String(contentsOf: views.appending(path: "MainWindow.swift"), encoding: .utf8)
    #expect(main.components(separatedBy: "ProtectionLine {").count == 2, "MainWindow shows ProtectionLine exactly once")
    let line = try #require(main.range(of: "ProtectionLine {"))
    for header in enclosingHeaders(of: line.lowerBound, in: main) {
        for word in ["DisclosureGroup", "checkState", "canConnect", "result", "checkFinishedAt"] {
            #expect(!header.contains(word), "ProtectionLine sits inside \"\(header)\"")
        }
    }
}

/// The source line that opens each block enclosing `index`, innermost first. For a `} else {`
/// block the line of the matching `if` is included too, so an else branch counts as conditioned.
private func enclosingHeaders(of index: String.Index, in src: String) -> [String] {
    func line(at i: String.Index) -> String {
        let start = src[..<i].lastIndex(of: "\n").map(src.index(after:)) ?? src.startIndex
        let end = src[i...].firstIndex(of: "\n") ?? src.endIndex
        return String(src[start..<end])
    }
    /// The `{` matching the `}` at `close`.
    func opener(ofClose close: String.Index) -> String.Index? {
        var depth = 0, i = close
        while i > src.startIndex {
            i = src.index(before: i)
            if src[i] == "}" { depth += 1 }
            if src[i] == "{" { if depth == 0 { return i }; depth -= 1 }
        }
        return nil
    }
    var headers: [String] = [], depth = 0, i = index
    while i > src.startIndex {
        i = src.index(before: i)
        if src[i] == "}" { depth += 1; continue }
        guard src[i] == "{" else { continue }
        if depth > 0 { depth -= 1; continue }
        var h = line(at: i)
        headers.append(h)
        // Follow `} else if … {` / `} else {` back to the `if` that the branch belongs to.
        var at = i
        while h.trimmingCharacters(in: .whitespaces).hasPrefix("}"),
              let close = src[..<at].lastIndex(of: "}"), let open = opener(ofClose: close) {
            h = line(at: open); headers.append(h); at = open
        }
    }
    return headers
}

/// The body of `private struct <name>: View` up to the next top-level declaration.
private func view(_ name: String, in text: String) -> String? {
    guard let s = text.range(of: "private struct \(name): View {") else { return nil }
    let e = text.range(of: "\n}\n", range: s.upperBound..<text.endIndex)?.lowerBound ?? text.endIndex
    return String(text[s.upperBound..<e])
}

/// The app never claims a server sees, cannot see or has keys hidden from it.
@Test func noVisibilityWording() throws {
    for (name, text) in try sourceFiles() where name.hasPrefix("App/") {
        for phrase in [" sees ", "cannot see", "hidden from", "stay hidden"] {
            #expect(!text.contains(phrase), "\(name) contains \"\(phrase)\"")
        }
    }
}

/// AC1, AC2: a forwarded key missing from the agent gets its own row, and rows never edit the policy.
@Test func missingKeysAreLabelled() throws {
    let group = try String(contentsOf: appRoot.appending(path: "App/Views/ForwardedKeysGroup.swift"), encoding: .utf8)
    #expect(group.contains("case .notInAgent("))
    #expect(group.contains("\"Not in the agent\""))
    #expect(!group.contains("setForwardedKeys("))
    #expect(!group.contains("Button(\"Remove\")"))
}

/// The binding texts that stay on the main screen, word for word.
@Test func bindingCaptionsStayOnTheMainScreen() throws {
    let binding = try String(contentsOf: appRoot.appending(path: "App/Views/BindingSection.swift"), encoding: .utf8)
    for text in [
        "Text(\"Destination binding names the servers the forwarded key may log in to onward from this server, for example github.com. It does not protect the login to this server itself.\")",
        "Text(\"SigSieve does not verify that these host keys belong to the server.\")",
        "Text(\"Binding needs OpenSSH hostbound authentication on the onward server.\")",
        "Text(\"RSA host keys cannot bind.\")",
        "Text(\"With Secretive, a cancelled Touch ID prompt means reconnecting.\")",
    ] {
        #expect(binding.contains(text), "BindingSection.swift lacks \(text)")
    }
}

/// The text after `head` up to its matching closing brace.
private func braceBody(after head: String, in src: String) -> String? {
    guard let r = src.range(of: head) else { return nil }
    var depth = 1, body = ""
    for c in src[r.upperBound...] {
        if c == "{" { depth += 1 }
        if c == "}" { depth -= 1; if depth == 0 { return body } }
        body.append(c)
    }
    return nil
}

/// The menu bar says "Check passed" only when the gate is open, and never starts a check or a connection.
@Test func menuBarNeverClaimsReadyWithoutGate() throws {
    let src = try String(contentsOf: appRoot.appending(path: "App/Views/MenuStatusView.swift"), encoding: .utf8)
    #expect(src.components(separatedBy: "\"Check passed").count == 2, "exactly one \"Check passed")
    let branch = try #require(braceBody(after: "if model.canConnect {", in: src), "no if model.canConnect branch")
    #expect(branch.contains("\"Check passed"), "\"Check passed is outside the canConnect branch")
    #expect(!src.contains("runCheck("))
    #expect(!src.contains("connect("))
}

/// "Open SigSieve" brings the main window forward and refreshes, even when it is already key.
@Test func refreshOnOpen() throws {
    let src = try String(contentsOf: appRoot.appending(path: "App/Views/MenuStatusView.swift"), encoding: .utf8)
    let open = try #require(src.range(of: "openWindow(id: \"main\")"))
    let refresh = try #require(src.range(of: "await model.refresh()"))
    #expect(open.lowerBound < refresh.lowerBound)
    // A minimised main window comes back too: the captured NSWindow, never an identifier string.
    let restore = try #require(src.range(of: "if window.isMiniaturized { window.deminiaturize(nil) }"))
    let front = try #require(src.range(of: "window.makeKeyAndOrderFront(nil)"))
    #expect(open.lowerBound < restore.lowerBound && restore.lowerBound < front.lowerBound)
    #expect(src.contains("if let window = MainWindowRef.window {"))
    let main = try String(contentsOf: appRoot.appending(path: "App/Views/MainWindow.swift"), encoding: .utf8)
    #expect(main.contains("MainWindowRef.window = window"))
    #expect(main.contains("MainWindowRef.window = nil"))
}

/// The menu panel shows a blocking error in full and offers its actions as menu rows with shortcut hints.
@Test func menuPanelRows() throws {
    let src = try String(contentsOf: appRoot.appending(path: "App/Views/MenuStatusView.swift"), encoding: .utf8)
    let error = try #require(braceBody(after: "if let error = StatusText.blockingErrors(model).first {", in: src))
    #expect(!error.contains(".lineLimit("), "a warning is never shortened")
    #expect(!error.contains(".truncationMode("), "a warning is never shortened")
    for hint in ["\"↩\"", "\"⌘,\"", "\"⌘Q\""] {
        #expect(src.contains(hint), "lacks hint \(hint)")
    }
    #expect(src.contains(".keyboardShortcut(.defaultAction)"))
    #expect(src.contains(".keyboardShortcut(\",\", modifiers: .command)"))
    #expect(src.contains(".keyboardShortcut(\"q\", modifiers: .command)"))
}
