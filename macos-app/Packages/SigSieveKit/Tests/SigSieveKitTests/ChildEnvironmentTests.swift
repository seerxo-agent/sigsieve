import Foundation
import Testing
@testable import SigSieveKit

private func tmp(_ name: String = "d") -> String {
    let parent = TestDirectory.make()
    let dir = parent.appending(path: name).path
    try! FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: false)
    chmod(dir, 0o700)
    return dir
}

private func resolved(_ p: String) -> String {
    let r = realpath(p, nil)!
    defer { free(r) }
    return String(cString: r)
}

private func verified() throws -> VerifiedTempDir { try TempDir.verified(TempDir.system()) }

// MARK: - Child environment

@Test func environmentHasExactlyTheDocumentedVariables() throws {
    let t = try verified()
    let env = try ChildEnvironment.make(home: "/Users/t", cliDirectory: "/opt/homebrew/bin",
                                        tmpdir: t, agent: .openssh(socket: "/s"))
    #expect(env.variables.map(\.name) == ["HOME", "PATH", "LANG", "TMPDIR", "SSH_AUTH_SOCK"])
    #expect(env.dictionary == [
        "HOME": "/Users/t",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin",
        "LANG": "en_US.UTF-8",
        "TMPDIR": t.path,
        "SSH_AUTH_SOCK": "/s",
    ])
}

@Test func secretiveSocketIsUnderHome() throws {
    let env = try ChildEnvironment.make(home: "/Users/t", cliDirectory: "/usr/local/bin",
                                        tmpdir: try verified(), agent: .secretive)
    #expect(env.dictionary["SSH_AUTH_SOCK"]
            == "/Users/t/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh")
    #expect(AgentChoice.openssh(socket: "/a b").socketPath(home: "/h") == "/a b")
}

@Test func onlyTheAllowlistedNamesExist() throws {
    // make() builds from its arguments only (pinned by the source scan below);
    // setenv is not used here because it races getenv in parallel tests.
    let env = try ChildEnvironment.make(home: "/h", cliDirectory: "/c", tmpdir: try verified(), agent: .secretive)
    #expect(Set(env.dictionary.keys) == ["HOME", "PATH", "LANG", "TMPDIR", "SSH_AUTH_SOCK"])
    #expect(env.variables.count == 5)
}

@Test(arguments: ["", "relative", "/a\nb", "/a\u{202E}b"])
func unsafeHomeIsRefused(_ home: String) throws {
    #expect(throws: ChildEnvironmentError.unsafeHome(home)) {
        try ChildEnvironment.make(home: home, cliDirectory: "/c", tmpdir: try verified(), agent: .secretive)
    }
}

@Test(arguments: ["", "relative.sock", "/", "/a\u{0}b", "/a\u{200B}b"])
func unsafeSocketIsRefused(_ socket: String) throws {
    #expect(throws: ChildEnvironmentError.unsafeSocket(socket)) {
        try ChildEnvironment.make(home: "/h", cliDirectory: "/c", tmpdir: try verified(), agent: .openssh(socket: socket))
    }
}

@Test func pathLongerThanTheSocketLimitIsRefused() throws {
    // 70 bytes is the most the CLI's "<dir>/sigsieve-<12 hex>/agent.sock" fits in sun_path.
    var d = tmp()
    while resolved(d).utf8.count <= TempDir.maxPathBytes {
        d += "/x"
        try FileManager.default.createDirectory(atPath: d, withIntermediateDirectories: false)
        chmod(d, 0o700)
    }
    #expect(throws: TempDirError.tooLong(resolved(d))) { try TempDir.verified(d) }
    #expect(resolved(d).utf8.count + 33 > 103)
}

@Test(arguments: ["relative/bin", "", "/a:/b", "/a\nb", "/a\u{0}b", "/a=b/bin"])
func unsafeCLIDirectoryIsRefused(_ dir: String) throws {
    // A ":" would add a second PATH entry; a relative one depends on the cwd;
    // "=" makes env(1) in the launcher read the CLI path as an assignment.
    #expect(throws: ChildEnvironmentError.unsafeCLIDirectory(dir)) {
        try ChildEnvironment.make(home: "/h", cliDirectory: dir, tmpdir: try verified(), agent: .secretive)
    }
}

// MARK: - TMPDIR source

@Test func systemTempDirComesFromConfstrNotTheEnvironment() throws {
    // getconf asks the same confstr name; TMPDIR in this process is not read.
    let p = Process()
    p.executableURL = URL(filePath: "/usr/bin/getconf")
    p.arguments = ["DARWIN_USER_TEMP_DIR"]
    p.environment = ["TMPDIR": "/tmp/"]
    let out = Pipe()
    p.standardOutput = out
    try p.run()
    p.waitUntilExit()
    let fromGetconf = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        .trimmingCharacters(in: .newlines)
    #expect(try TempDir.system() == fromGetconf)
    #expect(try TempDir.system() != "/tmp/")
}

@Test func systemTempDirPassesVerificationOnThisMachine() throws {
    let t = try TempDir.verified(TempDir.system())
    #expect(t.path.hasPrefix("/private/var/folders/"))
    #expect(!t.path.hasSuffix("/"))
}

// MARK: - TMPDIR refusals (no fallback to /tmp)

@Test func relativePathIsRefused() {
    #expect(throws: TempDirError.notAbsolute("var/folders/x")) { try TempDir.verified("var/folders/x") }
    #expect(throws: TempDirError.notAbsolute("")) { try TempDir.verified("") }
}

@Test func missingDirectoryIsRefused() {
    let p = tmp() + "/gone"
    #expect(throws: TempDirError.missing(p)) { try TempDir.verified(p) }
}

@Test func fileIsRefused() throws {
    let f = tmp() + "/file"
    FileManager.default.createFile(atPath: f, contents: Data())
    #expect(throws: TempDirError.notADirectory(resolved(f))) { try TempDir.verified(f) }
}

@Test(arguments: [0o755, 0o770, 0o701, 0o710, 0o705])
func groupOrOtherAccessIsRefused(_ m: Int) {
    let d = tmp()
    chmod(d, mode_t(m))
    #expect(throws: TempDirError.notPrivate(resolved(d))) { try TempDir.verified(d) }
}

@Test func otherOwnerIsRefused() {
    let d = tmp()
    #expect(throws: TempDirError.wrongOwner(resolved(d))) { try TempDir.verified(d, uid: getuid() + 1) }
}

@Test func unsupportedCharactersAreRefused() {
    for name in ["a b", "it's", "a$b", "a%b", "é"] {
        let d = tmp(name)
        #expect(throws: TempDirError.unsupportedCharacters(resolved(d))) { try TempDir.verified(d) }
    }
}

@Test func symlinkIsCheckedAfterResolving() throws {
    let target = tmp()
    chmod(target, 0o755)
    let link = tmp() + "/link"
    try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: target)
    #expect(throws: TempDirError.notPrivate(resolved(target))) { try TempDir.verified(link) }
}

@Test func writableAncestorIsRefusedUnlessSticky() throws {
    // Another user able to write the parent could replace the directory
    // between verification and use; the CLI applies the same rule.
    let d = tmp()
    let parent = (d as NSString).deletingLastPathComponent
    chmod(parent, 0o777)
    defer { chmod(parent, 0o700) }
    #expect(throws: TempDirError.unsafeAncestor(resolved(parent))) { try TempDir.verified(d) }
    chmod(parent, 0o1777)
    #expect(try TempDir.verified(d).path == resolved(d))
}

@Test func sharedTmpIsRefused() {
    // /tmp is root-owned and world-writable: never accepted, never a fallback.
    #expect(throws: TempDirError.wrongOwner("/private/tmp")) { try TempDir.verified("/tmp") }
}

@Test func acceptsAPrivateDirectoryAndReturnsTheResolvedPath() throws {
    let d = tmp()
    let link = tmp() + "/link"
    try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: d)
    #expect(try TempDir.verified(d + "/").path == resolved(d))
    #expect(try TempDir.verified(link).path == resolved(d))
}

@Test func errorsNameThePathAndTheRule() {
    let d = tmp()
    chmod(d, 0o755)
    do {
        _ = try TempDir.verified(d)
        Issue.record("expected a refusal")
    } catch {
        let text = "\(error)"
        #expect(text.contains(resolved(d)))
        #expect(text.contains("group or others"))
    }
}

@Test func environmentSourceNeverReadsTheProcessEnvironment() throws {
    // The getconf test cannot tell confstr from $TMPDIR when both agree (as
    // they do in a normal test run); this pins the source instead.
    let source = URL(filePath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .appending(path: "Sources/SigSieveKit/ProcessExecution/ChildEnvironment.swift")
    let text = try String(contentsOf: source, encoding: .utf8)
    for forbidden in ["ProcessInfo", "getenv", "_NSGetEnviron", "NSTemporaryDirectory", "temporaryDirectory", "\"/tmp"] {
        #expect(!text.contains(forbidden), "ChildEnvironment.swift mentions \(forbidden)")
    }
    #expect(!text.contains(/\benviron\b/), "ChildEnvironment.swift mentions environ")
    #expect(text.contains("confstr(_CS_DARWIN_USER_TEMP_DIR"))
}
