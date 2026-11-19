import Foundation
import Testing
@testable import SigSieveKit

private final class FakeRunner: Running, @unchecked Sendable {
    private let lock = NSLock()
    private(set) var calls: [(tool: Tool, arguments: [String], timeout: Duration)] = []
    let result: Result<RunResult, RunError>
    init(exit: Int32, stdout: String = "", stderr: String = "") {
        result = .success(RunResult(exitCode: exit, stdout: stdout, stderr: stderr))
    }
    init(error: RunError) { result = .failure(error) }

    func run(_ tool: Tool, _ arguments: [String], environment: ChildEnvironment,
             stdin: Data?, timeout: Duration) async throws -> RunResult {
        lock.withLock { calls.append((tool, arguments, timeout)) }
        return try result.get()
    }
}

private func env() -> ChildEnvironment {
    try! ChildEnvironment.make(home: TestDirectory.make().path, cliDirectory: TestDirectory.make().path,
                               tmpdir: try! TempDir.verified(TempDir.system()), agent: .openssh(socket: "/s"))
}

// 43 valid base64 characters; the last one is in the allowed set.
private let a43 = String(repeating: "A", count: 43)
private let b43 = String(repeating: "B", count: 42) + "A"
private func fp(_ s: String) -> Fingerprint { Fingerprint("SHA256:" + s)! }

private func synthetic(_ n: Int) -> [AgentKey] {
    (0..<n).map { i in
        let body = String(format: "%042d", i) + "A"
        return AgentKey(fingerprint: fp(body), bits: 256, type: "ED25519", comment: "key-\(i)")
    }
}

@Suite struct AgentKeysTests {
    @Test func parsesOrdinaryLine() {
        let k = AgentKeys.parse("256 SHA256:\(a43) work laptop (ED25519)\n")[0]
        #expect(k.bits == 256); #expect(k.type == "ED25519"); #expect(k.comment == "work laptop")
        #expect(k.fingerprint == fp(a43)); #expect(k.id == k.fingerprint)
    }

    @Test func commentMayBeEmptyOrContainParentheses() {
        #expect(AgentKeys.parse("256 SHA256:\(a43)  (ECDSA)\n")[0].comment == "")
        #expect(AgentKeys.parse("256 SHA256:\(a43) key (old) (ECDSA)\n")[0].comment == "key (old)")
    }

    @Test func acceptsCRLF() {
        let keys = AgentKeys.parse("256 SHA256:\(a43) a (ED25519)\r\n3072 SHA256:\(b43) b (RSA)\r\n")
        #expect(keys.map(\.comment) == ["a", "b"])
    }

    @Test func identicalCommentsStaySeparateKeys() {
        let keys = AgentKeys.parse("256 SHA256:\(a43) same (ED25519)\n256 SHA256:\(b43) same (ED25519)\n")
        #expect(keys.count == 2)
        #expect(Set(keys.map(\.id)).count == 2)
    }

    @Test func duplicateFingerprintIsListedOnce() {
        let keys = AgentKeys.parse("256 SHA256:\(a43) first (ED25519)\n256 SHA256:\(a43) second (ED25519)\n")
        #expect(keys.map(\.comment) == ["first"])
    }

    @Test func malformedLinesAreSkipped() {
        #expect(AgentKeys.parse("garbage\n256 MD5:aa x (RSA)\n\n256 SHA256:\(a43) no type\n") == [])
        #expect(AgentKeys.parse("garbage\n256 SHA256:\(a43) ok (ED25519)\n").count == 1)
    }

    @Test func typeMustBeUppercaseAsciiAndBitsNumeric() {
        #expect(AgentKeys.parse("256 SHA256:\(a43) key (old)\n") == [])
        #expect(AgentKeys.parse("256 SHA256:\(a43) key (\u{E9}D)\n") == [])
        #expect(AgentKeys.parse("x56 SHA256:\(a43) key (ED25519)\n") == [])
        #expect(AgentKeys.parse("256 SHA256:\(a43) key (SK-ED25519)\n").count == 1)
    }

    @Test func unicodeLineSeparatorsStayInTheComment() {
        let k = AgentKeys.parse("256 SHA256:\(a43) a\u{2028}b\u{2029}c\u{85}d (ED25519)\r\n")
        #expect(k.count == 1); #expect(k[0].comment == "a\u{2028}b\u{2029}c\u{85}d")
    }

    @Test func runErrorsGetReadableSentences() async {
        #expect(await AgentKeys.list(runner: FakeRunner(error: .timedOut), environment: env())
                == .unreachable("ssh-add did not answer within 10 seconds"))
        #expect(await AgentKeys.list(runner: FakeRunner(error: .cannotStart("boom")), environment: env())
                == .unreachable("ssh-add could not start: boom"))
        #expect(await AgentKeys.list(runner: FakeRunner(error: .notAllowed("/x")), environment: env())
                == .unreachable("ssh-add was not allowed to run"))
    }

    @Test func exit0ListsKeysAndUsesSshAddWithTimeout() async {
        let r = FakeRunner(exit: 0, stdout: "256 SHA256:\(a43) k (ED25519)\n")
        let state = await AgentKeys.list(runner: r, environment: env())
        #expect(state == .keys(AgentKeys.parse("256 SHA256:\(a43) k (ED25519)\n")))
        #expect(r.calls.count == 1)
        #expect(r.calls[0].arguments == ["-l", "-E", "sha256"])
        #expect(r.calls[0].timeout == .seconds(10))
        if case .sshAdd = r.calls[0].tool {} else { Issue.record("not ssh-add") }
    }

    @Test func exit0WithNoKeysIsEmpty() async {
        #expect(await AgentKeys.list(runner: FakeRunner(exit: 0, stdout: "\n"), environment: env()) == .empty)
    }

    @Test func exit1IsEmptyNotAnError() async {
        let r = FakeRunner(exit: 1, stdout: "The agent has no identities.\n")
        #expect(await AgentKeys.list(runner: r, environment: env()) == .empty)
    }

    @Test func exit2IsUnreachableWithStderr() async {
        let r = FakeRunner(exit: 2, stderr: "Could not open a connection to your authentication agent.\n")
        #expect(await AgentKeys.list(runner: r, environment: env())
                == .unreachable("Could not open a connection to your authentication agent."))
    }

    @Test func otherExitCodeIsUnreachableNamingTheCode() async {
        guard case .unreachable(let m) = await AgentKeys.list(runner: FakeRunner(exit: 7), environment: env()) else {
            Issue.record("expected unreachable"); return
        }
        #expect(m.contains("7"))
    }

    @Test func timeoutIsUnreachable() async {
        guard case .unreachable = await AgentKeys.list(runner: FakeRunner(error: .timedOut), environment: env()) else {
            Issue.record("expected unreachable"); return
        }
    }

    @Test func filterMatchesCommentTypeAndFingerprint() {
        let keys = [
            AgentKey(fingerprint: fp(a43), bits: 256, type: "ED25519", comment: "Work Laptop"),
            AgentKey(fingerprint: fp(b43), bits: 3072, type: "RSA", comment: "home"),
        ]
        #expect(KeyFilter.filter(keys, query: "").count == 2)
        #expect(KeyFilter.filter(keys, query: "work").map(\.comment) == ["Work Laptop"])
        #expect(KeyFilter.filter(keys, query: "rsa").map(\.comment) == ["home"])
        #expect(KeyFilter.filter(keys, query: "sha256:bbb").map(\.comment) == ["home"])
        #expect(KeyFilter.filter(keys, query: "zzz").isEmpty)
    }

    @Test func filterDoesNotFoldDiacritics() {
        let keys = [AgentKey(fingerprint: fp(a43), bits: 256, type: "RSA", comment: "\u{E9}")]
        #expect(KeyFilter.filter(keys, query: "e").isEmpty)
        #expect(KeyFilter.filter(keys, query: "\u{C9}").count == 1)
        // Canonical equivalence holds: NFD "e" + U+0301 is the same character as U+00E9.
        let nfd = [AgentKey(fingerprint: fp(a43), bits: 256, type: "RSA", comment: "cafe\u{0301}")]
        #expect(KeyFilter.filter(nfd, query: "cafe").isEmpty)
        #expect(KeyFilter.filter(nfd, query: "caf\u{C9}").count == 1)
        #expect(KeyFilter.filter(nfd, query: "caf\u{E9}").count == 1)
    }

    @Test func filtering500KeysIsFast() {
        let keys = synthetic(500)
        // Best of 5 runs, so pauses on a busy CI runner do not fail it (one run took 2 s there);
        // a real slowdown still slows every run. One filter must fit in a 60 Hz frame while typing.
        let clock = ContinuousClock()
        let best = (0..<5).map { _ in
            clock.measure { for _ in 0..<20 { _ = KeyFilter.filter(keys, query: "key-49") } }
        }.min()!
        #expect(best / 20 < .milliseconds(16))
    }
}
