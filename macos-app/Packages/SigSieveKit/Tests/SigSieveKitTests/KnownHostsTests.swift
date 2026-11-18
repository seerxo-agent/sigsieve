import Foundation
import Testing
@testable import SigSieveKit

private final class FakeRunner: Running, @unchecked Sendable {
    private let lock = NSLock()
    private(set) var calls: [(tool: Tool, arguments: [String], stdin: String?, timeout: Duration)] = []
    let result: Result<RunResult, RunError>
    /// Consumed one per call before `result` is used.
    private var queue: [String] = []
    init(first: [String], then stdout: String) { result = .success(RunResult(exitCode: 0, stdout: stdout, stderr: "")); queue = first }
    init(exit: Int32 = 0, stdout: String = "") { result = .success(RunResult(exitCode: exit, stdout: stdout, stderr: "")) }
    init(error: RunError) { result = .failure(error) }

    func run(_ tool: Tool, _ arguments: [String], environment: ChildEnvironment,
             stdin: Data?, timeout: Duration) async throws -> RunResult {
        lock.withLock { calls.append((tool, arguments, stdin.map { String(decoding: $0, as: UTF8.self) }, timeout)) }
        if let next = lock.withLock({ queue.isEmpty ? nil : queue.removeFirst() }) {
            return RunResult(exitCode: 0, stdout: next, stderr: "")
        }
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
      @revoked host-d ssh-ed25519 AAAAC3Nza...D
    |1|c2FsdA==|aGFzaA== ssh-ed25519 AAAAC3Nza...E
    """
    let kept = KnownHosts.selectableLines(text)
    #expect(kept.contains("...A")); #expect(kept.contains("...E"))
    #expect(!kept.contains("...B")); #expect(!kept.contains("...C")); #expect(!kept.contains("...D"))
    #expect(!kept.contains("#"))
}

@Test func aKeyRevokedAnywhereIsNotOfferedFromAnUnmarkedLine() {
    let text = "host-a ssh-ed25519 KEYX\n@revoked * ssh-ed25519 KEYX\nhost-c ssh-ed25519 KEYY"
    let kept = KnownHosts.selectableLines(text)
    #expect(!kept.contains("KEYX")); #expect(kept.contains("KEYY"))
}

@Test func entriesAreFingerprintedFromStdinNotFromTheFile() async throws {
    let f = try file("host-a,alias ssh-ed25519 KEYA\n@revoked h ssh-ed25519 KEYB\n")
    let runner = FakeRunner(first: [out(b43, "h", "ED25519") + "\n"], then: out(a43, "host-a,alias", "ED25519") + "\n")
    let entries = await KnownHosts.entries(file: f, runner: runner, environment: env())
    #expect(entries == [KnownHostEntry(name: "host-a", fingerprint: Fingerprint("SHA256:" + a43)!, type: "ED25519")])
    #expect(runner.calls.first?.stdin == "h ssh-ed25519 KEYB")
    let call = try #require(runner.calls.last)
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

@Test func unparseableOutputLineFailsClosed() async throws {
    let f = try file("host-a ssh-ed25519 KEYA\nhost-b ssh-ed25519 KEYB\n")
    let runner = FakeRunner(stdout: "garbage\n" + out(b43, "host-b", "ED25519") + "\n")
    #expect(await KnownHosts.entries(file: f, runner: runner, environment: env()).isEmpty)
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

@Test func revokedFingerprintRunReturningTooFewLinesGivesNoEntries() async throws {
    let f = try file("host-a ssh-ed25519 KEYA\n@revoked h ssh-ed25519 KEYB\n@revoked h2 ssh-ed25519 KEYC\n")
    let runner = FakeRunner(first: [out(b43, "h", "ED25519") + "\n"], then: out(a43, "host-a", "ED25519") + "\n")
    #expect(await KnownHosts.entries(file: f, runner: runner, environment: env()).isEmpty)
}

@Test func revokedFingerprintIsDroppedFromTheResult() async throws {
    let f = try file("host-a ssh-ed25519 KEYA\nhost-b ssh-ed25519 KEYB\n@revoked h ssh-ed25519 KEYC\n")
    let runner = FakeRunner(first: [out(a43, "h", "ED25519") + "\n"],
                            then: out(a43, "host-a", "ED25519") + "\n" + out(b43, "host-b", "ED25519") + "\n")
    #expect(await KnownHosts.entries(file: f, runner: runner, environment: env()).map(\.name) == ["host-b"])
}

private func throwawayBlob(type: String = "ed25519") throws -> (blob: String, fingerprint: String) {
    let dir = TestDirectory.make()
    let p = Process()
    p.executableURL = URL(filePath: "/usr/bin/ssh-keygen")
    p.arguments = ["-t", type, "-N", "", "-f", dir.appending(path: "k").path, "-q"]
    try p.run(); p.waitUntilExit()
    let parts = try String(contentsOf: dir.appending(path: "k.pub"), encoding: .utf8).split(separator: " ")
    let q = Process(), pipe = Pipe()
    q.executableURL = URL(filePath: "/usr/bin/ssh-keygen")
    q.arguments = ["-l", "-E", "sha256", "-f", dir.appending(path: "k.pub").path]
    q.standardOutput = pipe
    try q.run(); q.waitUntilExit()
    let fp = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self).split(separator: " ")[1]
    return (String(parts[1]), String(fp))
}

/// Raw bytes of a known_hosts file; entries() must never offer the revoked key.
private func realEntries(_ bytes: [UInt8]) async throws -> [KnownHostEntry] {
    let u = TestDirectory.make().appending(path: "known_hosts")
    try Data(bytes).write(to: u)
    return await KnownHosts.entries(file: u, runner: ProcessRunner(), environment: env())
}

@Test func realSshKeygenNeverOffersARevokedKeyHiddenByOddBytes() async throws {
    let (b, fp) = try throwawayBlob()
    let rev = "@revoked * ssh-ed25519 \(b)\n"
    let mid = b.index(b.startIndex, offsetBy: 20)
    let shapes = [
        "host ssh-ed25519 \(b)\r junk\n", "host ssh-ed25519 \(b)\0junk\n",
        "host ssh-ed25519 \(b) \u{301}junk\n",
        "host ssh-ed25519 \(b[..<mid])\u{0C}\(b[mid...])\n",
    ]
    for shape in shapes {
        let entries = try await realEntries(Array((shape + rev).utf8))
        #expect(!entries.contains { $0.fingerprint.value == fp }, "leaked: \(shape.debugDescription)")
    }
    // The revocation itself hidden behind a form feed: the whole file is refused.
    let hidden = "@revoked * ssh-ed25519 \(b[..<mid])\u{0C}\(b[mid...])\nhost ssh-ed25519 \(b)\n"
    #expect(try await realEntries(Array(hidden.utf8)).isEmpty)
}

@Test func uncleanRevokedLineRefusesTheFileWithFakeRunner() async throws {
    let f = try file("host-a ssh-ed25519 KEYA\n@revoked * ssh-ed25519 KEYB\u{0C}KEYC\n")
    let runner = FakeRunner(stdout: out(a43, "host-a", "ED25519") + "\n")
    #expect(await KnownHosts.entries(file: f, runner: runner, environment: env()).isEmpty)
    #expect(runner.calls.isEmpty)
}

@Test func deviceNodeIsNotOpened() async {
    #expect(await KnownHosts.entries(file: URL(filePath: "/dev/null"), runner: FakeRunner(), environment: env()).isEmpty)
}

@Test func outputHostFieldNotMatchingTheInputFailsClosed() async throws {
    // Right count, parseable, but the line at position 1 echoes a different host: unexpected.
    let f = try file("host-a ssh-ed25519 KEYA\nhost-b ssh-ed25519 KEYB\n")
    let runner = FakeRunner(stdout: out(a43, "host-a", "ED25519") + "\n" + out(b43, "other", "ED25519") + "\n")
    #expect(await KnownHosts.entries(file: f, runner: runner, environment: env()).isEmpty)
}

@Test func revokedRunOutputProblemsFailClosed() async throws {
    let f = try file("host-a ssh-ed25519 KEYA\n@revoked h ssh-ed25519 KEYB\n")
    let good = out(a43, "host-a", "ED25519") + "\n"
    for bad in ["", "garbage\n", out(b43, "wrong", "ED25519") + "\n", out(b43, "h", "ED25519") + "\n" + out(a43, "h", "ED25519") + "\n"] {
        let runner = FakeRunner(first: [bad], then: good)
        #expect(await KnownHosts.entries(file: f, runner: runner, environment: env()).isEmpty, "\(bad.debugDescription)")
    }
    #expect(await KnownHosts.entries(file: f, runner: FakeRunner(exit: 1), environment: env()).isEmpty)
}

@Test func realSshKeygenRevokedKeyUnderAnotherHostIsNotOfferedBeforeOrAfter() async throws {
    let (b, fp) = try throwawayBlob()
    let text = "before.example ssh-ed25519 \(b)\n@revoked * ssh-ed25519 \(b)\nafter.example ssh-ed25519 \(b) c\nalias,other ssh-ed25519 \(b)\n"
    #expect(!(try await realEntries(Array(text.utf8))).contains { $0.fingerprint.value == fp })
}

@Test func aRejectedLineAmongThreeRealKeysFailsClosedNeverShiftingNames() async throws {
    let a = try throwawayBlob(), b = try throwawayBlob(), c = try throwawayBlob()
    let text = "one ssh-ed25519 \(a.blob)\ntwo ssh-ed25519 !!!bad!!!\nthree ssh-ed25519 \(c.blob)\n"
    #expect(try await realEntries(Array(text.utf8)).isEmpty)
    // Without the rejected line every name sits on its own key.
    let ok = try await realEntries(Array("one ssh-ed25519 \(a.blob)\ntwo ssh-ed25519 \(b.blob)\nthree ssh-ed25519 \(c.blob)\n".utf8))
    #expect(ok.map(\.name) == ["one", "two", "three"])
    #expect(ok.map(\.fingerprint.value) == [a.fingerprint, b.fingerprint, c.fingerprint])
}

@Test func nonAsciiLinesAreDroppedAndNonAsciiRevokedLineEmptiesTheList() async throws {
    let (b, _) = try throwawayBlob()
    let (g, gfp) = try throwawayBlob()
    let dropped = try await realEntries(Array("h\u{e9}st ssh-ed25519 \(b)\ngood ssh-ed25519 \(g)\nc ssh-ed25519 \(b) caf\u{e9}\n".utf8))
    #expect(dropped.map(\.fingerprint.value) == [gfp])
    #expect(try await realEntries(Array("@revoked h\u{e9} ssh-ed25519 \(b)\ngood ssh-ed25519 \(g)\n".utf8)).isEmpty)
}

/// An RSA key and the same key with a non-minimal exponent mpint (a leading zero byte).
private func rsaPair() throws -> (blob: String, alt: String, fingerprint: String) {
    let dir = TestDirectory.make()
    let p = Process()
    p.executableURL = URL(filePath: "/usr/bin/ssh-keygen")
    p.arguments = ["-t", "rsa", "-b", "2048", "-N", "", "-f", dir.appending(path: "r").path, "-q"]
    try p.run(); p.waitUntilExit()
    let blob = String(try String(contentsOf: dir.appending(path: "r.pub"), encoding: .utf8).split(separator: " ")[1])
    let raw = [UInt8](Data(base64Encoded: blob)!)
    func field(_ at: Int) -> ArraySlice<UInt8> {
        let n = Int(raw[at]) << 24 | Int(raw[at + 1]) << 16 | Int(raw[at + 2]) << 8 | Int(raw[at + 3])
        return raw[(at + 4)..<(at + 4 + n)]
    }
    let t = field(0), e = field(4 + t.count), n = field(8 + t.count + e.count)
    func enc(_ f: [UInt8]) -> [UInt8] { withUnsafeBytes(of: UInt32(f.count).bigEndian) { Array($0) } + f }
    let alt = enc(Array(t)) + enc([0] + Array(e)) + enc(Array(n))
    let q = Process(), pipe = Pipe()
    q.executableURL = URL(filePath: "/usr/bin/ssh-keygen")
    q.arguments = ["-l", "-E", "sha256", "-f", dir.appending(path: "r.pub").path]
    q.standardOutput = pipe
    try q.run(); q.waitUntilExit()
    let fp = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self).split(separator: " ")[1]
    return (blob, Data(alt).base64EncodedString(), String(fp))
}

@Test func quotedHostFieldCannotHideARevokedRsaKey() async throws {
    let r = try rsaPair(), k2 = try throwawayBlob()
    let text = "@revoked *,\"x ssh-rsa \(r.blob) \" ssh-ed25519 \(k2.blob) *,\"x\nhost ssh-rsa \(r.alt)\n"
    #expect(try await realEntries(Array(text.utf8)).isEmpty)
    // Plain RSA alt-exponent against an honest revocation of the canonical form: layer 2 never sees the blob match.
    let honest = "@revoked * ssh-rsa \(r.blob)\nhost ssh-rsa \(r.alt)\n"
    #expect(!(try await realEntries(Array(honest.utf8))).contains { $0.fingerprint.value == r.fingerprint })
}

@Test func quotedHostFieldCannotMisattributeAName() async throws {
    let k1 = try throwawayBlob(), k2 = try throwawayBlob()
    let text = "real.example.com,\"x ssh-ed25519 \(k1.blob) \" ssh-ed25519 \(k2.blob) real.example.com,\"x\n"
    #expect(try await realEntries(Array(text.utf8)).isEmpty)
}

@Test func commentedLineIsListedAndSendsOnlyHostTypeBlob() async throws {
    let k = try throwawayBlob()
    let entries = try await realEntries(Array("b ssh-ed25519 \(k.blob) mycomment\n".utf8))
    #expect(entries.map(\.name) == ["b"]); #expect(entries.map(\.fingerprint.value) == [k.fingerprint])
    #expect(KnownHosts.selectableLines("b ssh-ed25519 \(k.blob) mycomment") == "b ssh-ed25519 \(k.blob)")
}

@Test func certLinesAreNotOfferedButStillRevoke() async throws {
    let k = try throwawayBlob()
    let cert = "h ssh-ed25519-cert-v01@openssh.com AAAA"
    #expect(KnownHosts.selectableLines(cert) == "")
    // A revoked cert line is still sent to the revocation run.
    let f = try file("good ssh-ed25519 KEYA\n@revoked h ssh-ed25519-cert-v01@openssh.com AAAA\n")
    let runner = FakeRunner(first: [out(b43, "h", "ED25519-CERT") + "\n"], then: out(a43, "good", "ED25519") + "\n")
    #expect(await KnownHosts.entries(file: f, runner: runner, environment: env()).count == 1)
    #expect(runner.calls.first?.stdin == "h ssh-ed25519-cert-v01@openssh.com AAAA")
    _ = k
}

@Test func malformedRevokedMarkersFailClosed() {
    #expect(KnownHosts.selectableLines("host ssh-ed25519 KEYA\n@revoked* h ssh-ed25519 KEYB") == "")
    #expect(KnownHosts.selectableLines("host ssh-ed25519 KEYA\n@revoked h ssh-ed25519") == "")
    #expect(KnownHosts.selectableLines("host ssh-ed25519 KEYA\n@revoked *,\"x ssh-ed25519 KEYB\"") == "")
}

@Test func textLayerAloneDropsTheOddByteShapes() {
    let rev = "@revoked * ssh-ed25519 BLOBX\n"
    for shape in ["host ssh-ed25519 BLOBX\r junk", "host ssh-ed25519 BLOBX\0junk",
                  "host ssh-ed25519 BLOBX \u{301}junk", "host ssh-ed25519 BLOB\u{0C}X"] {
        #expect(!KnownHosts.selectableLines(shape + "\n" + rev).contains("BLOB"), "\(shape.debugDescription)")
    }
}

@Test func unknownMarkersAndDoubleMarkersFailClosed() {
    #expect(KnownHosts.selectableLines("host ssh-ed25519 KEYA\n@Weird h ssh-ed25519 KEYZ") == "")
    // ssh compares markers case-sensitively: "@REVOKED" is not a marker it knows.
    #expect(KnownHosts.selectableLines("host ssh-ed25519 KEYA\n@REVOKED h ssh-ed25519 KEYZ") == "")
    #expect(KnownHosts.selectableLines("host ssh-ed25519 KEYA\n@cert-authority @revoked h ssh-ed25519 KEYZ") == "")
    #expect(KnownHosts.selectableLines("host ssh-ed25519 KEYA\n@revoked h @x ssh-ed25519 KEYZ") == "")
    #expect(KnownHosts.selectableLines("host ssh-ed25519 KEYA\n@cert-authority *.x ssh-ed25519 KEYZ") == "host ssh-ed25519 KEYA")
}

@Test func onlyAllowlistedTypesAreOffered() {
    let ok = ["ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa"]
    for t in ok { #expect(KnownHosts.selectableLines("h \(t) KEYA") == "h \(t) KEYA", "\(t)") }
    for t in ["webauthn-sk-ecdsa-sha2-nistp256@openssh.com", "sk-ssh-ed25519@openssh.com", "ssh-dss",
              "ssh-ed25519-cert-v01@openssh.com", "KEYA", "SSH-ED25519", "rsa-sha2-256"] {
        #expect(KnownHosts.selectableLines("h \(t) KEYA") == "", "\(t)")
    }
    #expect(KnownHosts.selectableLines("ssh-ed25519 KEYA ssh-ed25519") == "")
}

@Test func aLineWhoseHostIsItsBlobIsNotOffered() {
    #expect(KnownHosts.selectableLines("KEYA ssh-ed25519 KEYA\nh ssh-ed25519 KEYB") == "h ssh-ed25519 KEYB")
}

@Test func nameLabelSkipsNegationsAndCanBeNil() async throws {
    let f = try file("!bad,good ssh-ed25519 KEYA\n!only ssh-ed25519 KEYB\n")
    let runner = FakeRunner(stdout: out(a43, "!bad,good", "ED25519") + "\n" + out(b43, "!only", "ED25519") + "\n")
    #expect(await KnownHosts.entries(file: f, runner: runner, environment: env()).map(\.name) == ["good", nil])
}

@Test func allDigitHostsAreNotSentToSshKeygen() {
    #expect(KnownHosts.selectableLines("123 ssh-ed25519 KEYA\n-7 ssh-ed25519 KEYA\n+1 ssh-ed25519 KEYA\nh1 ssh-ed25519 KEYB\n1a ssh-ed25519 KEYC")
            == "h1 ssh-ed25519 KEYB\n1a ssh-ed25519 KEYC")
}

@Test func revokedLineWithDigitHostFailsClosed() async throws {
    for host in ["123", "-7", "+1"] {
        #expect(KnownHosts.selectableLines("host-a ssh-ed25519 KEYA\n@revoked \(host) ssh-ed25519 KEYB") == "", "\(host)")
        let f = try file("host-a ssh-ed25519 KEYA\n@revoked \(host) ssh-ed25519 KEYB\n")
        // Even a runner that answers every line in full does not get a say: the file is refused first.
        let runner = FakeRunner(first: [out(b43, host, "ED25519") + "\n"], then: out(a43, "host-a", "ED25519") + "\n")
        #expect(await KnownHosts.entries(file: f, runner: runner, environment: env()).isEmpty)
        #expect(runner.calls.isEmpty)
    }
}

@Test func certOutputTypeIsNotOffered() async throws {
    let f = try file("host-a ssh-ed25519 KEYA\nhost-b ssh-ed25519 KEYB\n")
    let runner = FakeRunner(stdout: out(a43, "host-a", "ED25519-CERT") + "\n" + out(b43, "host-b", "ED25519") + "\n")
    #expect(await KnownHosts.entries(file: f, runner: runner, environment: env()).map(\.name) == ["host-b"])
}

/// An `sk-ecdsa-sha2-nistp256@openssh.com` public blob built from a throwaway P-256 key
/// (type, curve, point, application "ssh:"), as a webauthn key in known_hosts carries.
private func throwawaySKBlob() throws -> String {
    var raw = Data(base64Encoded: try throwawayBlob(type: "ecdsa").blob)!
    var fields: [Data] = []
    while raw.count >= 4 {
        let n = raw.prefix(4).reduce(0) { $0 << 8 | Int($1) }
        fields.append(raw.dropFirst(4).prefix(n)); raw = raw.dropFirst(4 + n)
    }
    let out = [Data("sk-ecdsa-sha2-nistp256@openssh.com".utf8), fields[1], fields[2], Data("ssh:".utf8)]
        .reduce(into: Data()) { d, f in d += withUnsafeBytes(of: UInt32(f.count).bigEndian) { Data($0) } + f }
    return out.base64EncodedString()
}

@Test func realSshKeygenBareKeyAndWebauthnShapesAreNotOffered() async throws {
    let k = try throwawayBlob()
    #expect(try await realEntries(Array("ssh-ed25519 \(k.blob) ssh-ed25519\n".utf8)).isEmpty)
    let wa = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
    let sk = "\(wa) \(try throwawaySKBlob()) \(wa)\n"
    // Real ssh-keygen does fingerprint this line, so only the type allowlist keeps it out.
    let probe = TestDirectory.make().appending(path: "probe"); try Data(sk.utf8).write(to: probe)
    let q = Process(), pipe = Pipe()
    q.executableURL = URL(filePath: "/usr/bin/ssh-keygen")
    q.arguments = ["-l", "-E", "sha256", "-f", probe.path]; q.standardOutput = pipe
    try q.run(); q.waitUntilExit()
    #expect(q.terminationStatus == 0)
    #expect(String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self).contains("SHA256:"))
    #expect(try await realEntries(Array(sk.utf8)).isEmpty)
    #expect(try await realEntries(Array(("good ssh-ed25519 \(k.blob)\n" + sk).utf8)).map(\.name) == ["good"])
}

@Test func revocationFilesRevokeButAreNotOffered() async throws {
    let k1 = try throwawayBlob(), k2 = try throwawayBlob()
    let main = TestDirectory.make().appending(path: "known_hosts")
    try Data("a ssh-ed25519 \(k1.blob)\nb ssh-ed25519 \(k2.blob)\n".utf8).write(to: main)
    let second = TestDirectory.make().appending(path: "kh2")
    try Data("@revoked * ssh-ed25519 \(k1.blob)\nplain ssh-ed25519 \(try throwawayBlob().blob)\n".utf8).write(to: second)
    let missing = TestDirectory.make().appending(path: "nope")
    let entries = await KnownHosts.entries(file: main, revocationFiles: [missing, second], runner: ProcessRunner(), environment: env())
    #expect(entries.map(\.name) == ["b"])
    #expect(entries.map(\.fingerprint.value) == [k2.fingerprint])
}

@Test func unusableRevocationFileGivesNoEntries() async throws {
    let k = try throwawayBlob()
    let main = TestDirectory.make().appending(path: "known_hosts")
    try Data("a ssh-ed25519 \(k.blob)\n".utf8).write(to: main)
    let dir = TestDirectory.make()
    let unreadable = dir.appending(path: "unreadable")
    try Data("x".utf8).write(to: unreadable)
    chmod(unreadable.path, 0)
    let fifo = dir.appending(path: "fifo"); mkfifo(fifo.path, 0o600)
    let unclean = dir.appending(path: "unclean")
    try Data("@revoked * ssh-ed25519 AA\u{0C}AA\n".utf8).write(to: unclean)
    let oversized = dir.appending(path: "oversized")
    try Data(repeating: 0x23, count: KnownHosts.maxFileBytes + 1).write(to: oversized)
    for bad in [unreadable, fifo, dir, unclean, oversized] {
        let runner = FakeRunner(stdout: out(a43, "a", "ED25519") + "\n")
        #expect(await KnownHosts.entries(file: main, revocationFiles: [bad], runner: runner, environment: env()).isEmpty, "\(bad.lastPathComponent)")
    }
}

@Test func aSecondaryRevocationAlsoAppliesByText() async throws {
    let main = try file("a ssh-ed25519 KEYA\n")
    let second = TestDirectory.make().appending(path: "kh2")
    try Data("@revoked * ssh-ed25519 KEYA\n".utf8).write(to: second)
    // The fake fingerprints the two runs differently, so only the text layer can catch it.
    let runner = FakeRunner(first: [out(b43, "*", "ED25519") + "\n"], then: out(a43, "a", "ED25519") + "\n")
    #expect(await KnownHosts.entries(file: main, revocationFiles: [second], runner: runner, environment: env()).isEmpty)
}

@Test func aSecondaryRevocationAppliesByFingerprintToAnotherSpelling() async throws {
    let r = try rsaPair(), k = try throwawayBlob()
    let main = TestDirectory.make().appending(path: "known_hosts")
    try Data("a ssh-rsa \(r.blob)\nb ssh-ed25519 \(k.blob)\n".utf8).write(to: main)
    let second = TestDirectory.make().appending(path: "kh2")
    try Data("@revoked * ssh-rsa \(r.alt)\n".utf8).write(to: second)
    let entries = await KnownHosts.entries(file: main, revocationFiles: [second], runner: ProcessRunner(), environment: env())
    #expect(entries.map(\.name) == ["b"])
    #expect(!entries.contains { $0.fingerprint.value == r.fingerprint })
}

@Test func aRevocationPathUnderAnUnsearchableDirectoryGivesNoEntries() async throws {
    let main = try file("a ssh-ed25519 KEYA\n")
    let locked = TestDirectory.make().appending(path: "locked")
    try FileManager.default.createDirectory(at: locked, withIntermediateDirectories: false)
    chmod(locked.path, 0)
    defer { chmod(locked.path, 0o700) }
    let runner = FakeRunner(stdout: out(a43, "a", "ED25519") + "\n")
    #expect(await KnownHosts.entries(file: main, revocationFiles: [locked.appending(path: "known_hosts2")],
                                     runner: runner, environment: env()).isEmpty)
}

// MARK: - F4: a @cert-authority key is never offered, like a revoked one

@Test func realSshKeygenCertAuthorityKeyIsNotOfferedFromAnotherHostsLine() async throws {
    let ca = try throwawayBlob(), plain = try throwawayBlob()
    let text = "before.example ssh-ed25519 \(ca.blob)\n@cert-authority *.example ssh-ed25519 \(ca.blob)\n"
        + "plain.example ssh-ed25519 \(plain.blob)\nafter.example ssh-ed25519 \(ca.blob) c\n"
    let entries = try await realEntries(Array(text.utf8))
    #expect(entries.map(\.fingerprint.value) == [plain.fingerprint])
    // The text layer drops it too.
    #expect(KnownHosts.selectableLines(text) == "plain.example ssh-ed25519 \(plain.blob)")
}

@Test func realSshKeygenCertAuthorityInARevocationFileIsNotOffered() async throws {
    let ca = try throwawayBlob(), plain = try throwawayBlob()
    let f = try file("ca-host ssh-ed25519 \(ca.blob)\nplain ssh-ed25519 \(plain.blob)\n")
    let extra = try file("@cert-authority * ssh-ed25519 \(ca.blob)\n")
    let entries = await KnownHosts.entries(file: f, revocationFiles: [extra], runner: ProcessRunner(), environment: env())
    #expect(entries.map(\.fingerprint.value) == [plain.fingerprint])
}

@Test func uncleanOrMalformedCertAuthorityLineFailsClosed() async throws {
    let ca = try throwawayBlob(), plain = try throwawayBlob()
    let mid = ca.blob.index(ca.blob.startIndex, offsetBy: 20)
    for marked in ["@cert-authority * ssh-ed25519 \(ca.blob[..<mid])\u{0C}\(ca.blob[mid...])",
                   "@cert-authority h\u{e9} ssh-ed25519 \(ca.blob)",
                   "@cert-authority * ssh-ed25519",
                   "@cert-authority 123 ssh-ed25519 \(ca.blob)"] {
        let text = "\(marked)\nhost ssh-ed25519 \(ca.blob)\nplain ssh-ed25519 \(plain.blob)\n"
        #expect(try await realEntries(Array(text.utf8)).isEmpty, "\(marked.debugDescription)")
        #expect(KnownHosts.selectableLines(text) == "", "\(marked.debugDescription)")
    }
}
