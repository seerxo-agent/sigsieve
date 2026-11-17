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
