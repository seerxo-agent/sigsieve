import Foundation
import Testing
@testable import SigSieveKit

private func fp(_ c: Character) -> Fingerprint { Fingerprint("SHA256:" + String(repeating: c, count: 42) + "A")! }

private func makeInputs(tmpdir: URL) throws -> CheckInputs {
    let profile = Profile(server: HostInput("web")!, agent: .secretive, forwardedKeys: [fp("a")],
                          mode: .filtering, destinations: [])
    let cli = CLIInfo(path: URL(filePath: "/opt/x/sigsieve"), version: "sigsieve 1.0.0")
    let env = try ChildEnvironment.make(
        home: "/Users/test", cliDirectory: "/opt/x",
        tmpdir: TempDir.verified(tmpdir.path(percentEncoded: false)), agent: profile.agent)
    return CheckInputs(profile: profile, cli: cli, environment: env, configStamps: [])
}

private func mode(_ path: String) -> mode_t {
    var st = stat()
    precondition(lstat(path, &st) == 0)
    return st.st_mode & 0o7777
}

private func age(_ path: String, hours: Double) {
    let t = Date(timeIntervalSinceNow: -hours * 3600).timeIntervalSince1970
    var times = [timeval(tv_sec: Int(t), tv_usec: 0), timeval(tv_sec: Int(t), tv_usec: 0)]
    precondition(lutimes(path, &times) == 0)
}

private func exists(_ path: String) -> Bool {
    var st = stat()
    return lstat(path, &st) == 0
}

@Test func writesAPrivateDirectoryAndExecutableScript() throws {
    let tmp = TestDirectory.make()
    let script = try Launcher.write(makeInputs(tmpdir: tmp), under: tmp.path(percentEncoded: false))
    let dir = script.deletingLastPathComponent()
    #expect(dir.lastPathComponent.hasPrefix("sigsieve-launch-"))
    #expect(script.lastPathComponent == "connect.command")
    #expect(mode(dir.path(percentEncoded: false)) == 0o700)
    #expect(mode(script.path(percentEncoded: false)) == 0o700)
    #expect(dir.deletingLastPathComponent().path(percentEncoded: false) == tmp.path(percentEncoded: false)
            || dir.deletingLastPathComponent().resolvingSymlinksInPath() == tmp.resolvingSymlinksInPath())
}

@Test func scriptContentIsTheBuilderOutputForThatDirectory() throws {
    let tmp = TestDirectory.make()
    let inputs = try makeInputs(tmpdir: tmp)
    let script = try Launcher.write(inputs, under: tmp.path(percentEncoded: false))
    let dir = script.deletingLastPathComponent().path(percentEncoded: false).replacingOccurrences(of: "/$", with: "", options: .regularExpression)
    let expected = CommandBuilder.launcherScript(inputs.profile, cli: inputs.cli, environment: inputs.environment,
                                                 selfDirectory: dir)
    #expect(try String(contentsOf: script, encoding: .utf8) == expected)
}

@Test func twoWritesUseDifferentDirectories() throws {
    let tmp = TestDirectory.make()
    let inputs = try makeInputs(tmpdir: tmp)
    let a = try Launcher.write(inputs, under: tmp.path(percentEncoded: false))
    let b = try Launcher.write(inputs, under: tmp.path(percentEncoded: false))
    #expect(a.deletingLastPathComponent() != b.deletingLastPathComponent())
}

@Test func writeIntoAMissingDirectoryThrows() throws {
    let tmp = TestDirectory.make()
    let missing = tmp.appending(path: "nope").path(percentEncoded: false)
    #expect(throws: LauncherError.self) { try Launcher.write(makeInputs(tmpdir: tmp), under: missing) }
}

@Test func removeStaleDeletesOnlyOldLauncherDirectories() throws {
    let tmp = TestDirectory.make()
    let t = tmp.path(percentEncoded: false)
    let old = t + "/sigsieve-launch-a", new = t + "/sigsieve-launch-b"
    let sock = t + "/sigsieve-0123456789ab", other = t + "/other"
    for d in [old, new, sock, other] { #expect(mkdir(d, 0o700) == 0) }
    #expect(FileManager.default.createFile(atPath: old + "/connect.command", contents: Data("x".utf8)))
    for d in [old, sock, other] { age(d, hours: 2) }
    Launcher.removeStale(under: t)
    #expect(!exists(old))
    #expect(exists(new))
    #expect(exists(sock))
    #expect(exists(other))
}

@Test func removeStaleLeavesADirectoryWithUnexpectedContent() throws {
    let tmp = TestDirectory.make()
    let t = tmp.path(percentEncoded: false)
    let d = t + "/sigsieve-launch-a"
    #expect(mkdir(d, 0o700) == 0)
    #expect(FileManager.default.createFile(atPath: d + "/other.txt", contents: Data()))
    age(d, hours: 2)
    Launcher.removeStale(under: t)
    #expect(exists(d + "/other.txt"))
}

@Test func removeStaleIgnoresASymlinkNamedLikeALauncher() throws {
    let tmp = TestDirectory.make()
    let t = tmp.path(percentEncoded: false)
    let target = t + "/target"
    #expect(mkdir(target, 0o700) == 0)
    #expect(FileManager.default.createFile(atPath: target + "/connect.command", contents: Data()))
    let link = t + "/sigsieve-launch-link"
    #expect(symlink(target, link) == 0)
    age(link, hours: 2)
    Launcher.removeStale(under: t)
    #expect(exists(target + "/connect.command"))
    #expect(exists(link))
}
