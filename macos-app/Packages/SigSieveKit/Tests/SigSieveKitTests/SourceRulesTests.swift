import Foundation
import Testing

// A second check, not the boundary (the boundary is ProcessRunner). Scans the
// Kit's Sources/, and macos-app/App/ only when that directory exists.

private let kitRoot = URL(filePath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()

private func sourceFiles() throws -> [(name: String, text: String)] {
    var roots = [kitRoot.appending(path: "Sources")]
    let app = kitRoot.deletingLastPathComponent().deletingLastPathComponent().appending(path: "App")
    if FileManager.default.fileExists(atPath: app.path) { roots.append(app) }
    var files: [(String, String)] = []
    for root in roots {
        let e = try #require(FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil))
        for case let url as URL in e where url.pathExtension == "swift" {
            files.append((url.lastPathComponent, try String(contentsOf: url, encoding: .utf8)))
        }
    }
    #expect(files.contains { $0.0 == "ProcessRunner.swift" })
    return files
}

@Test func onlyProcessRunnerUsesProcess() throws {
    for (name, text) in try sourceFiles() {
        for token in ["Process()", "NSTask"] where name != "ProcessRunner.swift" {
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
