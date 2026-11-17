import Foundation
import Testing
@testable import SigSieveKit

private func fp(_ c: Character) -> Fingerprint { Fingerprint("SHA256:" + String(repeating: c, count: 42) + "A")! }

private let baseProfile = Profile(server: HostInput("web")!, agent: .secretive, forwardedKeys: [fp("a")],
                                  mode: .filtering, destinations: [])
private let baseTmp = TestDirectory.make()
private let baseStamp = FileStamp(path: "/cfg/config", size: 10, modified: Date(timeIntervalSince1970: 1000))

private func makeInputs(profile: Profile = baseProfile, home: String = "/Users/test", cliPath: String = "/opt/x/sigsieve",
                        version: String = "sigsieve 1.0.0", tmpdir: URL = baseTmp,
                        stamps: [FileStamp] = [baseStamp]) throws -> CheckInputs {
    let cli = CLIInfo(path: URL(filePath: cliPath), version: version)
    let env = try ChildEnvironment.make(
        home: home, cliDirectory: URL(filePath: cliPath).deletingLastPathComponent().path(percentEncoded: false),
        tmpdir: TempDir.verified(tmpdir.path(percentEncoded: false)), agent: profile.agent)
    return CheckInputs(profile: profile, cli: cli, environment: env, configStamps: stamps)
}

private struct Call: Equatable {
    let tool: URL
    let arguments: [String]
    let timeout: Duration
    let stdin: Data?
    let environment: ChildEnvironment
}

private final class FakeRunner: Running, @unchecked Sendable {
    private let lock = NSLock()
    private var queue: [Result<RunResult, RunError>]
    private var recorded: [Call] = []
    var calls: [Call] { lock.withLock { recorded } }

    init(_ results: [Result<RunResult, RunError>]) { queue = results }

    func run(_ tool: Tool, _ arguments: [String], environment: ChildEnvironment,
             stdin: Data?, timeout: Duration) async throws -> RunResult {
        let next: Result<RunResult, RunError> = lock.withLock {
            recorded.append(Call(tool: tool.url, arguments: arguments, timeout: timeout, stdin: stdin, environment: environment))
            return queue.removeFirst()
        }
        return try next.get()
    }
}

private func ok(_ code: Int32, _ out: String = "", _ err: String = "") -> Result<RunResult, RunError> {
    .success(RunResult(exitCode: code, stdout: out, stderr: err))
}

private let passing = CheckResult(doctor: StepResult(outcome: .passed, lines: [], hint: nil, raw: ""),
                                  dryRun: StepResult(outcome: .passed, lines: [], hint: nil, raw: ""))

@Test func bothStepsPassing() async throws {
    let inputs = try makeInputs()
    let runner = FakeRunner([ok(0), ok(0)])
    let r = await ConnectionCheck.run(inputs, runner: runner)
    #expect(r.passed)
    #expect(r.doctor.outcome == .passed)
    #expect(r.dryRun?.outcome == .passed)
    let key = fp("a").value
    #expect(runner.calls.map(\.arguments) == [
        ["doctor", "--secretive", "--allow-fingerprint", key],
        ["connect", "web", "--secretive", "--allow-fingerprint", key, "--dry-run", "--", "-o", "StrictHostKeyChecking=yes"],
    ])
    #expect(runner.calls.allSatisfy { $0.environment == inputs.environment })
    #expect(runner.calls.allSatisfy { $0.tool == inputs.cli.path && $0.stdin == nil })
}

@Test func doctorFailureSkipsDryRun() async throws {
    let runner = FakeRunner([ok(1)])
    let r = await ConnectionCheck.run(try makeInputs(), runner: runner)
    #expect(r.dryRun == nil)
    #expect(!r.passed)
    #expect(r.doctor.outcome == .failed)
    #expect(runner.calls.count == 1)
}

@Test func dryRunFailureIsNotPassed() async throws {
    let r = await ConnectionCheck.run(try makeInputs(), runner: FakeRunner([ok(0), ok(1)]))
    #expect(r.doctor.outcome == .passed)
    #expect(r.dryRun?.outcome == .failed)
    #expect(!r.passed)
}

@Test func exit2IsInvalidConfiguration() async throws {
    let r = await ConnectionCheck.run(try makeInputs(), runner: FakeRunner([ok(2)]))
    #expect(r.doctor.outcome == .invalidConfiguration)
    #expect(!r.passed)
}

@Test func unknownExitCodeIsAFailure() async throws {
    let r = await ConnectionCheck.run(try makeInputs(), runner: FakeRunner([ok(137)]))
    #expect(r.doctor.outcome == .failed)
}

@Test func textSayingPassedWithExit1IsStillAFailure() async throws {
    let r = await ConnectionCheck.run(try makeInputs(),
                                      runner: FakeRunner([ok(1, "Result: all checks passed\n")]))
    #expect(r.doctor.outcome == .failed)
    #expect(!r.passed)
}

@Test func silentExit0IsAPass() async throws {
    let r = await ConnectionCheck.run(try makeInputs(), runner: FakeRunner([ok(0, "Result: FAILED\n"), ok(0)]))
    #expect(r.passed)
}

@Test func hintLineIsExtracted() async throws {
    let r = await ConnectionCheck.run(try makeInputs(),
                                      runner: FakeRunner([ok(1, "Agent: down\n  hint: start Secretive \nmore\n")]))
    #expect(r.doctor.hint == "start Secretive")
    let none = await ConnectionCheck.run(try makeInputs(), runner: FakeRunner([ok(1, "Agent: down\n")]))
    #expect(none.doctor.hint == nil)
}

@Test func timeoutIsReportedAndUses150Seconds() async throws {
    let runner = FakeRunner([.failure(.timedOut)])
    let r = await ConnectionCheck.run(try makeInputs(), runner: runner)
    #expect(r.doctor.outcome == .timedOut)
    #expect(!r.passed)
    #expect(runner.calls.map(\.timeout) == [.seconds(150)])

    let both = FakeRunner([ok(0), ok(0)])
    _ = await ConnectionCheck.run(try makeInputs(), runner: both)
    #expect(both.calls.map(\.timeout) == [.seconds(150), .seconds(150)])
}

@Test func otherRunErrorsAreFailures() async throws {
    for e in [RunError.cannotStart("nope"), .notAllowed("/x")] {
        let r = await ConnectionCheck.run(try makeInputs(), runner: FakeRunner([.failure(e)]))
        #expect(r.doctor.outcome == .failed)
        #expect(!r.doctor.raw.isEmpty)
        #expect(!r.passed)
    }
}

@Test func rawOutputKeepsStdoutAndStderr() async throws {
    let both = await ConnectionCheck.run(try makeInputs(), runner: FakeRunner([ok(1, "out", "err")]))
    #expect(both.doctor.raw == "out\nerr")
    let onlyErr = await ConnectionCheck.run(try makeInputs(), runner: FakeRunner([ok(1, "", "err")]))
    #expect(onlyErr.doctor.raw == "err")
    let onlyOut = await ConnectionCheck.run(try makeInputs(), runner: FakeRunner([ok(1, "out", "")]))
    #expect(onlyOut.doctor.raw == "out")
}

@Test func linesAreSplitOnTheFirstColon() {
    #expect(ConnectionCheck.lines(from: "Login agent:         your SSH_AUTH_SOCK agent, passed as IdentityAgent\n")
            == [ResultLine(label: "Login agent", value: "your SSH_AUTH_SOCK agent, passed as IdentityAgent")])
    #expect(ConnectionCheck.lines(from: "A: b: c\nno colon\n: orphan\n  K :  v  \n")
            == [ResultLine(label: "A", value: "b: c"), ResultLine(label: "K", value: "v")])
}

@Test func gateOpensOnlyForTheCheckedInputs() throws {
    let inputs = try makeInputs()
    var g = CheckGate()
    #expect(!g.canConnect(inputs))
    g.record(passing, for: inputs)
    #expect(g.canConnect(inputs))
    #expect(g.result == passing)
}

private enum Change: CaseIterable {
    case home, forwardedKeys, mode, destinations, server, agent, cliPath, cliVersion, tmpdir, configStampSize, configStampDate

    func apply(to i: CheckInputs) throws -> CheckInputs {
        var p = i.profile
        var path = i.cli.path.path(percentEncoded: false), version = i.cli.version
        var tmp = baseTmp, stamps = i.configStamps, home = "/Users/test"
        switch self {
        case .home: home = "/Users/other"
        case .forwardedKeys: p.forwardedKeys.append(fp("b"))
        case .mode: p.mode = .binding
        case .destinations: p.destinations = [Destination(name: "d", hostKeys: [fp("c")])]
        case .server: p.server = HostInput("other")!
        case .agent: p.agent = .openssh(socket: "/s")
        case .cliPath: path = "/opt/y/sigsieve"
        case .cliVersion: version = "sigsieve 1.0.1"
        case .tmpdir: tmp = TestDirectory.make()
        case .configStampSize: stamps = [FileStamp(path: baseStamp.path, size: 11, modified: baseStamp.modified)]
        case .configStampDate:
            stamps = [FileStamp(path: baseStamp.path, size: baseStamp.size, modified: Date(timeIntervalSince1970: 2000))]
        }
        return try makeInputs(profile: p, home: home, cliPath: path, version: version, tmpdir: tmp, stamps: stamps)
    }
}

@Test(arguments: Change.allCases)
private func anyChangeClosesTheGate(_ c: Change) throws {
    let inputs = try makeInputs()
    var g = CheckGate()
    g.record(passing, for: inputs)
    #expect(!g.canConnect(try c.apply(to: inputs)))
}

@Test func aFailedCheckNeverOpensTheGate() throws {
    let inputs = try makeInputs()
    var g = CheckGate()
    let failed = CheckResult(doctor: StepResult(outcome: .failed, lines: [], hint: nil, raw: ""), dryRun: nil)
    g.record(failed, for: inputs)
    #expect(!g.canConnect(inputs))
    g.record(passing, for: inputs)
    #expect(g.canConnect(inputs))
    g.record(failed, for: inputs)
    #expect(!g.canConnect(inputs))
}

@Test func bindingWithoutAHostKeyIsInvalidAndRunsNothing() async throws {
    var p = baseProfile
    p.mode = .binding
    p.destinations = [Destination(name: "github.com", hostKeys: [])]
    let inputs = try makeInputs(profile: p)
    let runner = FakeRunner([])
    let r = await ConnectionCheck.run(inputs, runner: runner)
    let reason = "Destination binding needs at least one host key. Add one, or switch to Identity filtering."
    #expect(r.doctor == StepResult(outcome: .invalidConfiguration, lines: [], hint: reason, raw: reason))
    #expect(r.dryRun == nil)
    #expect(!r.passed)
    #expect(runner.calls.isEmpty)
    var g = CheckGate()
    g.record(r, for: inputs)
    #expect(!g.canConnect(inputs))
}

@Test func bindingWithAHostKeyPassesTheDestinationToBothSteps() async throws {
    var p = baseProfile
    p.mode = .binding
    p.destinations = [Destination(name: "github.com", hostKeys: [fp("c")])]
    let runner = FakeRunner([ok(0), ok(0)])
    let r = await ConnectionCheck.run(try makeInputs(profile: p), runner: runner)
    #expect(r.passed)
    #expect(runner.calls.map(\.arguments) == [
        ["doctor", "--secretive", "--allow-fingerprint", fp("a").value, "--allow-destination", fp("c").value],
        ["connect", "web", "--secretive", "--allow-fingerprint", fp("a").value, "--allow-destination", fp("c").value,
         "--dry-run", "--", "-o", "StrictHostKeyChecking=yes"],
    ])
}

@Test func filteringWithStoredDestinationsPassesNoDestination() async throws {
    var p = baseProfile
    p.destinations = [Destination(name: "github.com", hostKeys: [fp("c")])]
    let runner = FakeRunner([ok(0), ok(0)])
    _ = await ConnectionCheck.run(try makeInputs(profile: p), runner: runner)
    #expect(runner.calls.map(\.arguments) == [
        ["doctor", "--secretive", "--allow-fingerprint", fp("a").value],
        ["connect", "web", "--secretive", "--allow-fingerprint", fp("a").value,
         "--dry-run", "--", "-o", "StrictHostKeyChecking=yes"],
    ])
}
