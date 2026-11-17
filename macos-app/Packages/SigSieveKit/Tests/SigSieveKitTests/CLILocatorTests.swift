import Foundation
import Testing
@testable import SigSieveKit

private final class FakeRunner: Running, @unchecked Sendable {
    private let lock = NSLock()
    private(set) var calls: [(tool: Tool, arguments: [String], stdin: Data?, timeout: Duration)] = []
    let result: Result<RunResult, RunError>
    init(stdout: String = "sigsieve 1.0.0\n", exit: Int32 = 0) {
        result = .success(RunResult(exitCode: exit, stdout: stdout, stderr: ""))
    }
    init(error: RunError) { result = .failure(error) }

    func run(_ tool: Tool, _ arguments: [String], environment: ChildEnvironment,
             stdin: Data?, timeout: Duration) async throws -> RunResult {
        lock.withLock { calls.append((tool, arguments, stdin, timeout)) }
        return try result.get()
    }
    var paths: [String] { calls.compactMap { if case .cli(let u) = $0.tool { u.path } else { nil } } }
}

private func resolved(_ p: String) -> String {
    let r = realpath(p, nil)!
    defer { free(r) }
    return String(cString: r)
}

@discardableResult
private func file(mode: Int = 0o755, name: String = "sigsieve") throws -> URL {
    let url = TestDirectory.make().appending(path: name)
    try "#!/bin/sh\n".write(to: url, atomically: false, encoding: .utf8)
    chmod(url.path, mode_t(mode))
    return url
}

private func env(_ cli: URL) -> ChildEnvironment {
    try! ChildEnvironment.make(home: TestDirectory.make().path, cliDirectory: cli.deletingLastPathComponent().path,
                               tmpdir: try! TempDir.verified(TempDir.system()), agent: .openssh(socket: "/s"))
}

private func locator(_ r: Running, user: String? = nil, app: String? = nil, fixed: [String] = []) -> CLILocator {
    CLILocator(runner: r, userPath: user, appPATH: app, fixed: fixed)
}

@Suite struct CLILocatorTests {
    @Test func userPathWinsOverFixedLocations() async throws {
        let user = try file(), fixed = try file()
        let r = FakeRunner()
        let info = try await locator(r, user: user.path, fixed: [fixed.path]).locate(environment: env)
        #expect(info.path.path == resolved(user.path))
        #expect(info.version == "sigsieve 1.0.0")
        #expect(r.paths == [resolved(user.path)])
    }

    @Test func searchOrderIsUserThenFixedThenAppPATH() async throws {
        let fixed = try file(), app = try file()
        let missing = TestDirectory.make().appending(path: "sigsieve").path
        let r = FakeRunner()
        // no user path -> fixed beats appPATH
        let info = try await locator(r, user: nil, app: app.deletingLastPathComponent().path, fixed: [missing, fixed.path])
            .locate(environment: env)
        #expect(info.path.path == resolved(fixed.path))
        // empty user path counts as unset; only appPATH left
        let info2 = try await locator(FakeRunner(), user: "", app: "relative:" + app.deletingLastPathComponent().path,
                                      fixed: [missing])
            .locate(environment: env)
        #expect(info2.path.path == resolved(app.path))
    }

    @Test func missingUserPathDoesNotFallThrough() async throws {
        let fixed = try file()
        let missing = TestDirectory.make().appending(path: "sigsieve").path
        let r = FakeRunner()
        await #expect(throws: CLIError.notFound(searched: [missing])) {
            try await locator(r, user: missing, fixed: [fixed.path]).locate(environment: env)
        }
        #expect(r.calls.isEmpty)
    }

    @Test func realRunnerRefusalOfRenamedTargetIsUnsupportedVersion() async throws {
        let other = try file(name: "other")
        let link = TestDirectory.make().appending(path: "sigsieve")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: other)
        let error = await #expect(throws: CLIError.self) {
            try await CLILocator(runner: ProcessRunner(), userPath: link.path, appPATH: nil, fixed: [])
                .locate(environment: env)
        }
        guard case .unsupportedVersion(let p, let out) = error else { Issue.record("got \(String(describing: error))"); return }
        #expect(p == resolved(other.path))
        #expect(out.contains("notAllowed"))
    }

    @Test func symlinkIsResolvedInTheReportedPath() async throws {
        let target = try file()
        let link = TestDirectory.make().appending(path: "sigsieve")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        let r = FakeRunner()
        let info = try await locator(r, user: link.path).locate(environment: env)
        #expect(info.path.path == resolved(target.path))
        #expect(r.paths == [resolved(target.path)])
    }

    @Test func versionIsRunWithFixedArgumentsTimeoutAndNoStdin() async throws {
        let r = FakeRunner()
        _ = try await locator(r, user: try file().path).locate(environment: env)
        #expect(r.calls.count == 1)
        #expect(r.calls[0].arguments == ["--version"])
        #expect(r.calls[0].stdin == nil)
        #expect(r.calls[0].timeout == .seconds(5))
    }

    @Test func nonExecutableFileIsReported() async throws {
        let f = try file(mode: 0o644)
        let r = FakeRunner()
        await #expect(throws: CLIError.notExecutable(resolved(f.path))) {
            try await locator(r, user: f.path).locate(environment: env)
        }
        #expect(r.calls.isEmpty)
    }

    @Test(arguments: ["sigsieve 1.0.0\n", "sigsieve 1.12.3\n"])
    func acceptsVersion1(_ out: String) async throws {
        let info = try await locator(FakeRunner(stdout: out), user: try file().path).locate(environment: env)
        #expect(info.version == String(out.dropLast()))
    }

    @Test(arguments: ["sigsieve 2.0.0\n", "sigsieve 0.9.0\n", "sigsieve 1.0.0-alpha.2\n", "other 1.0.0\n", "",
                      "sigsieve 1.0.0", "sigsieve 1.0.0\n\n", "sigsieve 1.0\n", "sigsieve 1.٣.0\n"])
    func refusesOtherVersions(_ out: String) async throws {
        let f = try file()
        await #expect(throws: CLIError.unsupportedVersion(path: resolved(f.path), output: out)) {
            try await locator(FakeRunner(stdout: out), user: f.path).locate(environment: env)
        }
    }

    @Test func nonZeroExitFromVersionIsUnsupported() async throws {
        let f = try file()
        await #expect(throws: CLIError.unsupportedVersion(path: resolved(f.path), output: "sigsieve 1.0.0\n")) {
            try await locator(FakeRunner(exit: 1), user: f.path).locate(environment: env)
        }
    }

    @Test func runnerErrorIsUnsupportedAndDoesNotFallThrough() async throws {
        let first = try file(), second = try file()
        let r = FakeRunner(error: .timedOut)
        let error = await #expect(throws: CLIError.self) {
            try await locator(r, user: first.path, fixed: [second.path]).locate(environment: env)
        }
        guard case .unsupportedVersion(let p, _) = error else { Issue.record("got \(String(describing: error))"); return }
        #expect(p == resolved(first.path))
        #expect(r.calls.count == 1)
    }

    @Test func nothingFoundListsWhatWasSearched() async throws {
        let b = TestDirectory.make().appending(path: "sigsieve").path
        let c = TestDirectory.make().path
        let app = "\(c):relative/bin::\(c)"
        await #expect(throws: CLIError.notFound(searched: [b, c + "/sigsieve"])) {
            try await locator(FakeRunner(), user: nil, app: app, fixed: [b]).locate(environment: env)
        }
    }

    @Test func environmentGetsTheResolvedCLI() async throws {
        let target = try file()
        let link = TestDirectory.make().appending(path: "sigsieve")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        nonisolated(unsafe) var seen: URL?
        _ = try await locator(FakeRunner(), user: link.path).locate { seen = $0; return env($0) }
        #expect(seen?.path == resolved(target.path))
    }
}
