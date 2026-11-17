import Foundation
import Testing
@testable import SigSieveKit

private final class FakeRunner: Running, @unchecked Sendable {
    private let lock = NSLock()
    private(set) var calls: [(tool: Tool, arguments: [String], stdin: String?, timeout: Duration)] = []
    let result: Result<RunResult, RunError>
    init(exit: Int32 = 0, stdout: String = "") { result = .success(RunResult(exitCode: exit, stdout: stdout, stderr: "")) }
    init(error: RunError) { result = .failure(error) }

    func run(_ tool: Tool, _ arguments: [String], environment: ChildEnvironment,
             stdin: Data?, timeout: Duration) async throws -> RunResult {
        lock.withLock { calls.append((tool, arguments, stdin.map { String(decoding: $0, as: UTF8.self) }, timeout)) }
        return try result.get()
    }
}

private func env() -> ChildEnvironment {
    try! ChildEnvironment.make(home: TestDirectory.make().path, cliDirectory: TestDirectory.make().path,
                               tmpdir: try! TempDir.verified(TempDir.system()), agent: .openssh(socket: "/s"))
}

private let a43 = String(repeating: "A", count: 43)
private let b43 = String(repeating: "B", count: 42) + "A"
private func out(_ fp: String, _ comment: String, _ type: String, bits: Int = 256) -> String {
    "\(bits) SHA256:\(fp) \(comment) (\(type))"
}
private func file(_ text: String) throws -> URL {
    let u = TestDirectory.make().appending(path: "known_hosts")
    try text.write(to: u, atomically: true, encoding: .utf8)
    return u
}

@Test func markedLinesAreRemovedBeforeFingerprinting() {
    let text = """
    # comment
    host-a ssh-ed25519 AAAAC3Nza...A
    @revoked host-b ssh-ed25519 AAAAC3Nza...B
    @cert-authority *.example ssh-ed25519 AAAAC3Nza...C
      @REVOKED host-d ssh-ed25519 AAAAC3Nza...D
    |1|c2FsdA==|aGFzaA== ssh-ed25519 AAAAC3Nza...E
    """
    let kept = KnownHosts.selectableLines(text)
    #expect(kept.contains("...A")); #expect(kept.contains("...E"))
    #expect(!kept.contains("...B")); #expect(!kept.contains("...C")); #expect(!kept.contains("...D"))
    #expect(!kept.contains("#"))
}

@Test func aKeyRevokedAnywhereIsNotOfferedFromAnUnmarkedLine() {
    let text = "host-a ssh-ed25519 KEYX\n@revoked * ssh-ed25519 KEYX\nhost-c ssh-ed25519 KEYY\n@Weird host-d ssh-ed25519 KEYZ"
    let kept = KnownHosts.selectableLines(text)
    #expect(!kept.contains("KEYX")); #expect(!kept.contains("KEYZ")); #expect(kept.contains("KEYY"))
}

@Test func entriesAreFingerprintedFromStdinNotFromTheFile() async throws {
    let f = try file("host-a,alias ssh-ed25519 KEYA\n@revoked h ssh-ed25519 KEYB\n")
    let runner = FakeRunner(stdout: out(a43, "host-a,alias", "ED25519") + "\n")
    let entries = await KnownHosts.entries(file: f, runner: runner, environment: env())
    #expect(entries == [KnownHostEntry(name: "host-a", fingerprint: Fingerprint("SHA256:" + a43)!, type: "ED25519")])
    let call = try #require(runner.calls.first)
    #expect(call.arguments == ["-l", "-E", "sha256", "-f", "-"])
    #expect(call.stdin == "host-a,alias ssh-ed25519 KEYA")
    #expect(call.timeout == .seconds(10))
    if case .sshKeygen = call.tool {} else { Issue.record("wrong tool") }
}

@Test func hashedHostNamesBecomeNamelessEntries() async throws {
    let f = try file("|1|c2FsdA==|aGFzaA== ssh-ed25519 KEYA\nhost-b ssh-ed25519 KEYB\n")
    let runner = FakeRunner(stdout: out(a43, "|1|c2FsdA==|aGFzaA==", "ED25519") + "\n" + out(b43, "host-b", "ED25519") + "\n")
    let entries = await KnownHosts.entries(file: f, runner: runner, environment: env())
    #expect(entries.map(\.name) == [nil, "host-b"])
}

@Test func rsaEntriesAreMarkedByType() async throws {
    let f = try file("host-a ssh-rsa KEYA\n")
    let runner = FakeRunner(stdout: out(a43, "host-a", "RSA", bits: 3072) + "\n")
    let entries = await KnownHosts.entries(file: f, runner: runner, environment: env())
    #expect(entries.map(\.type) == ["RSA"])
}

@Test func duplicateFingerprintsKeepTheFirst() async throws {
    let f = try file("host-a ssh-ed25519 KEYA\nhost-b ssh-ed25519 KEYA\n")
    let runner = FakeRunner(stdout: out(a43, "host-a", "ED25519") + "\n" + out(a43, "host-b", "ED25519") + "\n")
    let entries = await KnownHosts.entries(file: f, runner: runner, environment: env())
    #expect(entries.map(\.name) == ["host-a"])
}

@Test func malformedOutputLinesAreDroppedButKeepAlignment() async throws {
    let f = try file("host-a ssh-ed25519 KEYA\nhost-b ssh-ed25519 KEYB\n")
    let runner = FakeRunner(stdout: "garbage\n" + out(b43, "host-b", "ED25519") + "\n")
    let entries = await KnownHosts.entries(file: f, runner: runner, environment: env())
    #expect(entries.map(\.name) == ["host-b"])
}

@Test func outputCountMismatchFailsClosed() async throws {
    let f = try file("host-a ssh-ed25519 KEYA\nhost-b ssh-ed25519 KEYB\n")
    let runner = FakeRunner(stdout: out(b43, "host-b", "ED25519") + "\n")
    #expect(await KnownHosts.entries(file: f, runner: runner, environment: env()).isEmpty)
}

@Test func missingFileGivesNoEntries() async {
    let runner = FakeRunner()
    let missing = TestDirectory.make().appending(path: "nope")
    #expect(await KnownHosts.entries(file: missing, runner: runner, environment: env()).isEmpty)
    #expect(await KnownHosts.entries(file: TestDirectory.make(), runner: runner, environment: env()).isEmpty)
    #expect(runner.calls.isEmpty)
}

@Test func oversizedFileIsNotRead() async throws {
    let u = TestDirectory.make().appending(path: "big")
    try Data(repeating: 0x61, count: 4 * 1024 * 1024 + 1).write(to: u)
    let runner = FakeRunner()
    #expect(await KnownHosts.entries(file: u, runner: runner, environment: env()).isEmpty)
    #expect(runner.calls.isEmpty)
}

@Test func runFailuresGiveNoEntries() async throws {
    let f = try file("host-a ssh-ed25519 KEYA\n")
    for runner in [FakeRunner(error: .timedOut), FakeRunner(error: .cannotStart("x")), FakeRunner(exit: 1, stdout: out(a43, "host-a", "ED25519"))] {
        #expect(await KnownHosts.entries(file: f, runner: runner, environment: env()).isEmpty)
    }
}

@Test func realSshKeygenNeverReturnsAMarkedKey() async throws {
    let dir = TestDirectory.make()
    var pubs: [String] = []
    for i in 1...3 {
        let p = Process()
        p.executableURL = URL(filePath: "/usr/bin/ssh-keygen")
        p.arguments = ["-t", "ed25519", "-N", "", "-f", dir.appending(path: "k\(i)").path, "-q"]
        try p.run(); p.waitUntilExit()
        let pub = try String(contentsOf: dir.appending(path: "k\(i).pub"), encoding: .utf8)
        let f = pub.split(separator: " ")
        pubs.append("\(f[0]) \(f[1])")
    }
    let f = try file("plain.example \(pubs[0])\n@revoked bad.example \(pubs[1])\n@cert-authority *.ca \(pubs[2])\n")
    let entries = await KnownHosts.entries(file: f, runner: ProcessRunner(), environment: env())
    #expect(entries.count == 1)
    #expect(entries.first?.name == "plain.example")
    #expect(entries.first?.type == "ED25519")
    let want = try await ProcessRunner().run(.sshKeygen, ["-l", "-E", "sha256", "-f", dir.appending(path: "k1.pub").path],
                                             environment: env(), stdin: nil, timeout: .seconds(10))
    #expect(want.stdout.contains(entries.first?.fingerprint.value ?? "?"))
}

@Test func aBareKeyLineCannotCarryARevokedKey() {
    let kept = KnownHosts.selectableLines("ssh-ed25519 KEYX c\n@revoked * ssh-ed25519 KEYX\nhost-a ssh-ed25519 KEYY")
    #expect(!kept.contains("KEYX")); #expect(kept.contains("KEYY"))
}

@Test func tabSeparatedLinesAreHandled() {
    let kept = KnownHosts.selectableLines("host-a\tssh-ed25519\tKEYA\n@revoked\t*\tssh-ed25519\tKEYB\nhost-b\tssh-ed25519\tKEYB")
    #expect(kept.contains("KEYA")); #expect(!kept.contains("KEYB"))
}

@Test func fifoAtThePathGivesNoEntriesWithoutHanging() async {
    let p = TestDirectory.make().appending(path: "fifo").path
    #expect(mkfifo(p, 0o600) == 0)
    // O_NONBLOCK on open and the regular-file check mean a FIFO neither blocks nor is read.
    #expect(await KnownHosts.entries(file: URL(filePath: p), runner: FakeRunner(), environment: env()).isEmpty)
}

@Test func symlinkedFileIsRead() async throws {
    let f = try file("host-a ssh-ed25519 KEYA\n")
    let link = TestDirectory.make().appending(path: "link")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: f)
    let runner = FakeRunner(stdout: out(a43, "host-a", "ED25519") + "\n")
    #expect(await KnownHosts.entries(file: link, runner: runner, environment: env()).count == 1)
}

@Test func realSshKeygenRevokedKeyIsNotOfferedFromABareKeyLine() async throws {
    let dir = TestDirectory.make()
    let p = Process()
    p.executableURL = URL(filePath: "/usr/bin/ssh-keygen")
    p.arguments = ["-t", "ed25519", "-N", "", "-f", dir.appending(path: "k").path, "-q"]
    try p.run(); p.waitUntilExit()
    let parts = try String(contentsOf: dir.appending(path: "k.pub"), encoding: .utf8).split(separator: " ")
    let key = "\(parts[0]) \(parts[1])"
    let f = try file("\(key) junk\n@revoked * \(key)\n")
    #expect(!KnownHosts.selectableLines(try String(contentsOf: f, encoding: .utf8)).contains(String(parts[1])))
    #expect(await KnownHosts.entries(file: f, runner: ProcessRunner(), environment: env()).isEmpty)
}

@Test func aLineSshKeygenRejectsFailsClosed() async throws {
    let dir = TestDirectory.make()
    let p = Process()
    p.executableURL = URL(filePath: "/usr/bin/ssh-keygen")
    p.arguments = ["-t", "ed25519", "-N", "", "-f", dir.appending(path: "k").path, "-q"]
    try p.run(); p.waitUntilExit()
    let parts = try String(contentsOf: dir.appending(path: "k.pub"), encoding: .utf8).split(separator: " ")
    let f = try file("good.example \(parts[0]) \(parts[1])\nbad.example ssh-ed25519 !!!notbase64!!!\n")
    #expect(await KnownHosts.entries(file: f, runner: ProcessRunner(), environment: env()).isEmpty)
}
