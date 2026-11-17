import Foundation
import Testing
@testable import SigSieveKit

// Integration tests against the real `sigsieve` binary, a throwaway ssh-agent
// and synthetic keys. The CLI path comes from SIGSIEVE_TEST_CLI; without it
// the CLI tests are skipped, except in CI, where `ciAlwaysProvidesTheBuiltCLI`
// fails instead. Raw CLI output is printed with an "EVIDENCE" header.

private let testCLI: URL? = {
    guard let p = ProcessInfo.processInfo.environment["SIGSIEVE_TEST_CLI"], !p.isEmpty else { return nil }
    var st = stat()
    guard stat(p, &st) == 0, st.st_mode & S_IFMT == S_IFREG, access(p, X_OK) == 0 else { return nil }
    return URL(filePath: p)
}()

/// The passwd home, which the CLI and ssh use for `~/.ssh/config` whatever HOME says.
private let passwdSSHConfig: String = {
    guard let pw = getpwuid(getuid()), let dir = pw.pointee.pw_dir else { return "~/.ssh/config" }
    return String(cString: dir) + "/.ssh/config"
}()

private func environment(_ agent: ThrowawayAgent, cliDirectory: String = "/usr/bin") throws -> ChildEnvironment {
    try ChildEnvironment.make(home: TestDirectory.make().path, cliDirectory: cliDirectory,
                              tmpdir: TempDir.verified(TempDir.system()), agent: .openssh(socket: agent.socket))
}

private func count(_ s: AgentState) -> Int {
    if case .keys(let k) = s { return k.count }
    return 0
}

private func evidence(_ name: String, _ text: String) {
    print("=== EVIDENCE \(name) ===\n\(text)\n=== END \(name) ===")
}

/// Wraps a real `ProcessRunner`. Records every call the Kit makes (argv as
/// the Kit built it, exit code, output). With `config`, a `connect` call gets
/// `-F <config>` inserted right after `--`, so `ssh -G` inside the CLI reads
/// the temporary file instead of the passwd home's `~/.ssh/config`.
private final class RecordingRunner: Running, @unchecked Sendable {
    struct Call {
        /// As the Kit built it.
        let arguments: [String]
        /// As the CLI received it (with the -F insertion, if any).
        let sent: [String]
        let result: RunResult?
    }

    private let inner: Running
    private let config: String?
    private let lock = NSLock()
    private var recorded: [Call] = []
    var calls: [Call] { lock.withLock { recorded } }

    init(_ inner: Running = ProcessRunner(), config: String? = nil) {
        self.inner = inner
        self.config = config
    }

    func run(_ tool: Tool, _ arguments: [String], environment: ChildEnvironment,
             stdin: Data?, timeout: Duration) async throws -> RunResult {
        var argv = arguments
        if let config, argv.first == "connect", let dd = argv.firstIndex(of: "--") {
            argv.insert(contentsOf: ["-F", config], at: dd + 1)
        }
        do {
            let r = try await inner.run(tool, argv, environment: environment, stdin: stdin, timeout: timeout)
            lock.withLock { recorded.append(Call(arguments: arguments, sent: argv, result: r)) }
            return r
        } catch {
            lock.withLock { recorded.append(Call(arguments: arguments, sent: argv, result: nil)) }
            throw error
        }
    }

    func report() -> String {
        calls.enumerated().map { i, c in
            let r = c.result
            return "call \(i + 1): sigsieve \(c.arguments.joined(separator: " "))\n"
                + (c.sent == c.arguments ? "" : "sent to the CLI: sigsieve \(c.sent.joined(separator: " "))\n")
                + "exit: \(r.map { String($0.exitCode) } ?? "threw")\n"
                + "--- stdout ---\n\(r?.stdout ?? "")--- stderr ---\n\(r?.stderr ?? "")"
        }.joined(separator: "\n") + "\nrunner calls: \(calls.count)"
    }
}

/// Locates the real CLI through the Kit (runs `--version`) and builds inputs for a profile.
private func inputs(_ profile: Profile, _ agent: ThrowawayAgent, stamps: [FileStamp]) async throws -> CheckInputs {
    let env = try environment(agent, cliDirectory: testCLI!.deletingLastPathComponent().path)
    let cli = try await CLILocator(runner: ProcessRunner(), userPath: testCLI!.path, appPATH: nil, fixed: [])
        .locate { _ in env }
    return CheckInputs(profile: profile, cli: cli, environment: env, configStamps: stamps)
}

private func filtering(_ agent: ThrowawayAgent, _ keys: [Fingerprint], server: String = "t") -> Profile {
    Profile(server: HostInput(server)!, agent: .openssh(socket: agent.socket), forwardedKeys: keys,
            mode: .filtering, destinations: [])
}

/// A config the dry run can read: host `t` and an Include that does not exist yet.
private func goodConfig() throws -> (config: URL, include: URL) {
    let dir = TestDirectory.make()
    let config = dir.appending(path: "good"), include = dir.appending(path: "inc")
    try "Host t\n  HostName 127.0.0.1\nInclude \(include.path)\n".write(to: config, atomically: false, encoding: .utf8)
    return (config, include)
}

private let unknownKey = Fingerprint("SHA256:" + String(repeating: "a", count: 42) + "A")!
private let hostKey = Fingerprint("SHA256:" + String(repeating: "h", count: 42) + "A")!

// MARK: - CI guard (never skipped)

@Test func ciAlwaysProvidesTheBuiltCLI() {
    let env = ProcessInfo.processInfo.environment
    guard env["CI"] != nil else { return }
    let path = env["SIGSIEVE_TEST_CLI"]
    #expect(path != nil && !path!.isEmpty, "CI must set SIGSIEVE_TEST_CLI to the built CLI")
    #expect(testCLI != nil, "SIGSIEVE_TEST_CLI=\(path ?? "") is not an executable regular file")
    #expect(testCLI?.lastPathComponent == "sigsieve")
}

// MARK: - Throwaway agent (no CLI needed)

@Suite struct ThrowawayAgentTests {
    @Test func listsTheThrowawayAgentsKeys() async throws {
        let agent = try ThrowawayAgent(keys: 3)
        defer { withExtendedLifetime(agent) {} } // alive until the test ends, also in optimized builds
        let state = await AgentKeys.list(runner: ProcessRunner(), environment: try environment(agent))
        guard case .keys(let keys) = state else { Issue.record("expected keys, got \(state)"); return }
        #expect(keys.count == 3)
        #expect(Set(keys.map(\.fingerprint)) == Set(agent.fingerprints))
        #expect(keys.allSatisfy { $0.type == "ED25519" && $0.bits == 256 })
    }

    @Test func emptyAgentIsTheEmptyState() async throws {
        let agent = try ThrowawayAgent(keys: 0)
        defer { withExtendedLifetime(agent) {} } // alive until the test ends, also in optimized builds
        #expect(await AgentKeys.list(runner: ProcessRunner(), environment: try environment(agent)) == .empty)
    }

    @Test func stoppedAgentIsUnreachable() async throws {
        let agent = try ThrowawayAgent(keys: 1)
        defer { withExtendedLifetime(agent) {} } // alive until the test ends, also in optimized builds
        agent.stop()
        let state = await AgentKeys.list(runner: ProcessRunner(), environment: try environment(agent))
        guard case .unreachable = state else { Issue.record("expected unreachable, got \(state)"); return }
    }

    @Test func fiveHundredKeysListAndFilterWithinBudget() async throws {
        let agent = try ThrowawayAgent(keys: 500)
        defer { withExtendedLifetime(agent) {} } // alive until the test ends, also in optimized builds
        let env = try environment(agent)
        var state = AgentState.empty
        var filtered: [AgentKey] = []
        let t = await ContinuousClock().measure {
            state = await AgentKeys.list(runner: ProcessRunner(), environment: env)
            if case .keys(let k) = state { filtered = KeyFilter.filter(k, query: "k427") }
        }
        print("=== EVIDENCE 500 keys: list + filter took \(t) ===")
        #expect(count(state) == 500)
        #expect(filtered.map(\.fingerprint) == [agent.fingerprints[427]])
        #expect(t < .seconds(2))
    }

    @Test func wrongVersionBinaryBlocks() async throws {
        let dir = TestDirectory.make()
        let fake = dir.appending(path: "sigsieve")
        try "#!/bin/sh\necho 'sigsieve 2.0.0'\n".write(to: fake, atomically: false, encoding: .utf8)
        chmod(fake.path, 0o755)
        let resolved = String(cString: realpath(fake.path, nil)!)
        let runner = RecordingRunner()
        await #expect(throws: CLIError.unsupportedVersion(path: resolved, output: "sigsieve 2.0.0\n")) {
            _ = try await CLILocator(runner: runner, userPath: fake.path, appPATH: nil, fixed: [])
                .locate { _ in try! ChildEnvironment.make(home: dir.path, cliDirectory: dir.path,
                                                          tmpdir: TempDir.verified(TempDir.system()),
                                                          agent: .openssh(socket: "/s")) }
        }
        #expect(runner.calls.map(\.arguments) == [["--version"]])
    }
}

// MARK: - Real CLI

@Suite(.enabled(if: testCLI != nil, "set SIGSIEVE_TEST_CLI to the built sigsieve"))
struct RealCLITests {
    @Test func doctorPassesForAnAllowedKey() async throws {
        let agent = try ThrowawayAgent(keys: 1)
        defer { withExtendedLifetime(agent) {} } // alive until the test ends, also in optimized builds
        let (config, _) = try goodConfig()
        let i = try await inputs(filtering(agent, agent.fingerprints), agent, stamps: [])
        let runner = RecordingRunner(config: config.path)
        let r = await ConnectionCheck.run(i, runner: runner)
        evidence("doctor + dry run pass", runner.report())
        #expect(r.doctor.outcome == .passed)
        #expect(r.doctor.lines.contains { $0.label == "Filtering" && $0.value.hasPrefix("verified") })
        #expect(r.doctor.raw.contains("Result: all checks passed"))
        #expect(r.dryRun?.outcome == .passed)
        #expect(r.dryRun?.raw.contains("ssh not started") == true)
        #expect(r.dryRun?.raw.contains("-F \(config.path)") == true)
        #expect(r.dryRun?.raw.contains(passwdSSHConfig) == false)
        #expect(r.passed)
        #expect(runner.calls.map { $0.result?.exitCode } == [0, 0])
    }

    /// Owner case (c): the fingerprint is not in the agent.
    @Test func doctorFailsForAMissingKey() async throws {
        let agent = try ThrowawayAgent(keys: 1)
        defer { withExtendedLifetime(agent) {} } // alive until the test ends, also in optimized builds
        let i = try await inputs(filtering(agent, [unknownKey]), agent, stamps: [])
        let runner = RecordingRunner()
        let r = await ConnectionCheck.run(i, runner: runner)
        evidence("doctor missing key", runner.report())
        #expect(r.doctor.outcome == .failed)
        #expect(r.doctor.raw.contains("Approved identities: 0/1 available"))
        #expect(r.dryRun == nil)
        #expect(!r.passed)
        #expect(runner.calls.count == 1)
        #expect(runner.calls[0].result?.exitCode == 1)
        var gate = CheckGate()
        gate.record(r, for: i)
        #expect(!gate.canConnect(i))
    }

    @Test func dryRunPassesAgainstAnIsolatedConfig() async throws {
        let agent = try ThrowawayAgent(keys: 1)
        defer { withExtendedLifetime(agent) {} } // alive until the test ends, also in optimized builds
        let dir = TestDirectory.make()
        let good = dir.appending(path: "good")
        try "Host t\n  HostName 127.0.0.1\n".write(to: good, atomically: false, encoding: .utf8)
        let env = try environment(agent, cliDirectory: testCLI!.deletingLastPathComponent().path)
        let argv = ["connect", "t", "--upstream", agent.socket,
                    "--allow-fingerprint", agent.fingerprints[0].value, "--dry-run", "--",
                    "-F", good.path, "-o", "StrictHostKeyChecking=yes"]
        let r = try await ProcessRunner().run(.cli(testCLI!), argv, environment: env, stdin: nil, timeout: .seconds(60))
        let raw = r.stdout + r.stderr
        evidence("dry run good config (exit \(r.exitCode))", "argv: \(argv.joined(separator: " "))\n--- stdout ---\n\(r.stdout)--- stderr ---\n\(r.stderr)")
        #expect(r.exitCode == 0)
        #expect(raw.contains("ssh not started"))
        #expect(raw.contains("Would run:"))
        #expect(raw.contains("-F \(good.path)"))
        #expect(!raw.contains(passwdSSHConfig))
    }

    /// Owner case (d), and proof that the CLI reads the -F file: same argv, other outcome.
    @Test func matchExecConfigIsRefusedByTheCLIAndNothingRuns() async throws {
        let agent = try ThrowawayAgent(keys: 1)
        defer { withExtendedLifetime(agent) {} } // alive until the test ends, also in optimized builds
        let dir = TestDirectory.make()
        let exec = dir.appending(path: "exec"), marker = dir.appending(path: "marker")
        try "Match exec \"touch \(marker.path)\"\nHost t\n".write(to: exec, atomically: false, encoding: .utf8)
        let env = try environment(agent, cliDirectory: testCLI!.deletingLastPathComponent().path)
        let argv = ["connect", "t", "--upstream", agent.socket, "--allow-fingerprint", agent.fingerprints[0].value,
                    "--dry-run", "--", "-F", exec.path, "-o", "StrictHostKeyChecking=yes"]
        let r = try await ProcessRunner().run(.cli(testCLI!), argv, environment: env, stdin: nil, timeout: .seconds(60))
        let raw = r.stdout + r.stderr
        evidence("dry run Match exec config (exit \(r.exitCode))", "argv: \(argv.joined(separator: " "))\n--- stdout ---\n\(r.stdout)--- stderr ---\n\(r.stderr)")
        #expect(r.exitCode == 1)
        #expect(raw.contains(exec.path))
        #expect(raw.contains("Match exec"))
        #expect(!raw.contains(passwdSSHConfig))
        #expect(access(marker.path, F_OK) != 0)

        _ = SSHConfigAliases.discover(config: exec, home: dir)
        #expect(access(marker.path, F_OK) != 0)
        #expect(!CommandBuilder.connectArguments(filtering(agent, agent.fingerprints), dryRun: true).contains("-F"))

        // Through the Kit: doctor passes, the dry run fails, Connect stays closed.
        let i = try await inputs(filtering(agent, agent.fingerprints), agent, stamps: [])
        let runner = RecordingRunner(config: exec.path)
        let check = await ConnectionCheck.run(i, runner: runner)
        evidence("check with Match exec config", runner.report())
        #expect(check.doctor.outcome == .passed)
        #expect(check.dryRun?.outcome == .failed)
        #expect(!check.passed)
        #expect(runner.calls.map { $0.result?.exitCode } == [0, 1])
        var gate = CheckGate()
        gate.record(check, for: i)
        #expect(!gate.canConnect(i))
        #expect(access(marker.path, F_OK) != 0)
    }

    @Test func sigsieveVariablesInTheTestEnvironmentAreIgnored() async throws {
        let agent = try ThrowawayAgent(keys: 1)
        defer { withExtendedLifetime(agent) {} } // alive until the test ends, also in optimized builds
        setenv("SIGSIEVE_ALLOW", unknownKey.value, 1)
        setenv("SIGSIEVE_DESTINATIONS", hostKey.value, 1)
        defer { unsetenv("SIGSIEVE_ALLOW"); unsetenv("SIGSIEVE_DESTINATIONS") }
        let i = try await inputs(filtering(agent, agent.fingerprints), agent, stamps: [])
        let runner = RecordingRunner()
        let r = try await runner.run(.cli(i.cli.path), ["doctor"] + CommandBuilder.doctorArguments(i.profile),
                                     environment: i.environment, stdin: nil, timeout: .seconds(60))
        evidence("doctor with SIGSIEVE_* set in the test process", runner.report())
        #expect(r.exitCode == 0)
        #expect(r.stdout.contains("Allowlist:          1 valid fingerprint(s)"))
        #expect(r.stdout.contains("available  ED25519 \(agent.fingerprints[0].value)"))
        #expect(!(r.stdout + r.stderr).contains(unknownKey.value))
        #expect(r.stdout.contains("Destination binding: not enforced"))
        #expect(!i.environment.variables.contains { $0.name.hasPrefix("SIGSIEVE") })
    }

    /// Owner case (a): a user path that does not exist is reported, never replaced.
    @Test func wrongCLIPathRunsNothing() async throws {
        let missing = TestDirectory.make().appending(path: "nope/sigsieve").path
        let runner = RecordingRunner()
        await #expect(throws: CLIError.notFound(searched: [missing])) {
            _ = try await CLILocator(runner: runner, userPath: missing, appPATH: testCLI!.deletingLastPathComponent().path,
                                     fixed: [testCLI!.path]).locate { _ in fatalError("no environment is needed") }
        }
        print("=== EVIDENCE wrong CLI path: runner calls \(runner.calls.count) ===")
        #expect(runner.calls.isEmpty)
    }

    /// Owner case (b): the SSH config changes after a passing check.
    @Test(arguments: ["rewritten", "includeCreated"])
    func configChangeAfterAPassingCheckClosesTheGate(_ change: String) async throws {
        let agent = try ThrowawayAgent(keys: 1)
        defer { withExtendedLifetime(agent) {} } // alive until the test ends, also in optimized builds
        let (config, include) = try goodConfig()
        let home = TestDirectory.make()
        let discovered = SSHConfigAliases.discover(config: config, home: home)
        #expect(discovered.stamps.map(\.path) == [config.path, include.path])
        #expect(discovered.stamps[1].size == -1)

        let i = try await inputs(filtering(agent, agent.fingerprints), agent, stamps: discovered.stamps)
        let runner = RecordingRunner(config: config.path)
        let r = await ConnectionCheck.run(i, runner: runner)
        #expect(r.passed)
        var gate = CheckGate()
        gate.record(r, for: i)
        let same = CheckInputs(profile: i.profile, cli: i.cli, environment: i.environment,
                               configStamps: SSHConfigAliases.currentStamps(for: i.configStamps))
        #expect(gate.canConnect(same))

        if change == "rewritten" {
            // Same bytes: only the identity (inode/ctime) can tell.
            let text = try String(contentsOf: config, encoding: .utf8)
            try text.write(to: config, atomically: true, encoding: .utf8)
        } else {
            try "# added\n".write(to: include, atomically: false, encoding: .utf8)
        }
        let now = CheckInputs(profile: i.profile, cli: i.cli, environment: i.environment,
                              configStamps: SSHConfigAliases.currentStamps(for: i.configStamps))
        print("=== EVIDENCE config \(change): runner calls \(runner.calls.count), exits \(runner.calls.map { $0.result?.exitCode ?? -1 }), gate before \(gate.canConnect(same)), after \(gate.canConnect(now)) ===")
        #expect(now.configStamps != i.configStamps)
        #expect(!gate.canConnect(now))
    }

    /// Owner criterion 3: binding is never downgraded.
    @Test func bindingWithoutAHostKeyRunsNothing() async throws {
        let agent = try ThrowawayAgent(keys: 1)
        defer { withExtendedLifetime(agent) {} } // alive until the test ends, also in optimized builds
        let p = Profile(server: HostInput("t")!, agent: .openssh(socket: agent.socket), forwardedKeys: agent.fingerprints,
                        mode: .binding, destinations: [Destination(name: "t", hostKeys: [])])
        let i = try await inputs(p, agent, stamps: [])
        let runner = RecordingRunner()
        let r = await ConnectionCheck.run(i, runner: runner)
        print("=== EVIDENCE binding without host key: runner calls \(runner.calls.count), outcome \(r.doctor.outcome), raw: \(r.doctor.raw) ===")
        #expect(r.doctor.outcome == .invalidConfiguration)
        #expect(r.doctor.hint == Profile.bindingWithoutHostKey)
        #expect(r.dryRun == nil)
        #expect(runner.calls.count == 0)
        var gate = CheckGate()
        gate.record(r, for: i)
        #expect(!gate.canConnect(i))
    }

    @Test func bindingWithAHostKeyReachesTheCLIAsAllowDestination() async throws {
        let agent = try ThrowawayAgent(keys: 1)
        defer { withExtendedLifetime(agent) {} } // alive until the test ends, also in optimized builds
        let (config, _) = try goodConfig()
        let p = Profile(server: HostInput("t")!, agent: .openssh(socket: agent.socket), forwardedKeys: agent.fingerprints,
                        mode: .binding, destinations: [Destination(name: "t", hostKeys: [hostKey])])
        let i = try await inputs(p, agent, stamps: [])
        let runner = RecordingRunner(config: config.path)
        let r = await ConnectionCheck.run(i, runner: runner)
        evidence("binding with host key", runner.report())
        #expect(runner.calls.count == 2)
        #expect(runner.calls.allSatisfy { c in
            c.arguments.firstIndex(of: "--allow-destination").map { c.arguments[$0 + 1] == hostKey.value } ?? false
        })
        #expect(r.doctor.outcome == .passed)
        #expect(r.doctor.raw.contains("Destination binding: enforced"))
        #expect(r.doctor.raw.contains("destination binding verified"))
        #expect(r.dryRun?.raw.contains("Destination binding: enforced") == true)
        #expect(r.passed)
    }
}
