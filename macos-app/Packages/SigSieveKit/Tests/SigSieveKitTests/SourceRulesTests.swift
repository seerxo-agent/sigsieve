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
    let view = try String(contentsOf: app.appending(path: "Views/AdvancedSection.swift"), encoding: .utf8)
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
    let view = try String(contentsOf: app.appending(path: "Views/CheckSection.swift"), encoding: .utf8)
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
    #expect(model.contains("func setForwardedKeys(selection: Set<Fingerprint>, for server: HostInput) -> Bool {\n        guard selectedServer == server else { return false }\n        edit { $0.forwardedKeys = ForwardedKeys.applying(selection: selection, to: $0.forwardedKeys, agentKeys: agentKeys) }"))
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
