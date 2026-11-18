import Foundation
import Testing
@testable import SigSieveKit

private func dir() -> URL { TestDirectory.make() }

private func resolved(_ p: String) -> String {
    let r = realpath(p, nil)!
    defer { free(r) }
    return String(cString: r)
}

private func env() throws -> ChildEnvironment {
    try ChildEnvironment.make(home: dir().path, cliDirectory: "/usr/local/bin",
                              tmpdir: try TempDir.verified(TempDir.system()), agent: .openssh(socket: "/s"))
}

/// Writes an executable file with the given name in a fresh directory.
@discardableResult
private func script(_ body: String, name: String = "sigsieve", mode: Int = 0o755) throws -> URL {
    let url = dir().appending(path: name)
    try body.write(to: url, atomically: false, encoding: .utf8)
    chmod(url.path, mode_t(mode))
    return url
}

private func run(_ cli: URL, _ args: [String] = [], stdin: Data? = nil,
                 timeout: Duration = .seconds(5)) async throws -> RunResult {
    try await ProcessRunner().run(.cli(cli), args, environment: try env(), stdin: stdin, timeout: timeout)
}

private func isAlive(_ pid: pid_t) -> Bool { kill(pid, 0) == 0 }

/// Polls until the process is gone (an orphan is reaped by launchd shortly after it dies).
private func goneSoon(_ pid: pid_t) async -> Bool {
    for _ in 0..<750 {   // up to 15 s: a loaded machine can starve the reaper
        if !isAlive(pid) { return true }
        try? await Task.sleep(for: .milliseconds(20))
    }
    return false
}

private func readPid(_ file: URL) async throws -> pid_t {
    for _ in 0..<1000 {   // up to 20 s
        if let s = try? String(contentsOf: file, encoding: .utf8), s.hasSuffix("\n"), let p = pid_t(s.dropLast()) { return p }
        try await Task.sleep(for: .milliseconds(20))
    }
    throw RunError.timedOut
}

// MARK: - Refusals

@Test(arguments: ["/usr/bin/ssh", "/bin/sh", "/usr/bin/env", "/usr/bin/osascript"])
func refusesAnyOtherExecutable(_ path: String) async throws {
    let expected = resolved(path)
    await #expect(throws: RunError.notAllowed(expected)) {
        try await run(URL(filePath: path), ["-V"])
    }
}

@Test func refusesASymlinkNamedSigsieveThatPointsAtSsh() async throws {
    let link = dir().appending(path: "sigsieve")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: URL(filePath: "/usr/bin/ssh"))
    await #expect(throws: RunError.notAllowed(resolved("/usr/bin/ssh"))) {
        try await run(link, ["-V"])
    }
}

@Test func refusalStartsNothing() async throws {
    let marker = dir().appending(path: "marker")
    let other = try script("#!/bin/sh\ntouch '\(marker.path)'\n", name: "other")
    await #expect(throws: RunError.notAllowed(resolved(other.path))) { try await run(other) }
    #expect(!FileManager.default.fileExists(atPath: marker.path))
}

@Test func refusesADirectoryNamedSigsieve() async throws {
    let d = dir().appending(path: "sigsieve")
    try FileManager.default.createDirectory(at: d, withIntermediateDirectories: false)
    await #expect(throws: RunError.notAllowed(resolved(d.path))) { try await run(d) }
}

@Test func refusesANonExecutableFileNamedSigsieve() async throws {
    let f = try script("#!/bin/sh\necho hi\n", mode: 0o644)
    await #expect(throws: RunError.notAllowed(resolved(f.path))) { try await run(f) }
}

@Test func refusesAMissingFile() async throws {
    let p = dir().appending(path: "sigsieve").path
    await #expect(throws: RunError.notAllowed(p)) { try await run(URL(filePath: p)) }
}

@Test func acceptsASymlinkWhoseTargetIsNamedSigsieve() async throws {
    let target = try script("#!/bin/sh\necho ok\n")
    let link = dir().appending(path: "sg")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
    #expect(try await run(link).stdout == "ok\n")
}

@Test func fixedToolsPointAtSystemBinaries() {
    #expect(Tool.sshAdd.url.path == "/usr/bin/ssh-add")
    #expect(Tool.sshKeygen.url.path == "/usr/bin/ssh-keygen")
}

@Test func fixedToolsRun() async throws {
    // ssh-keygen -Y with an unknown operation fails with a usage error; nothing about the user is read.
    let r = try await ProcessRunner().run(.sshKeygen, ["-Y", "bogus"], environment: try env(), stdin: nil, timeout: .seconds(5))
    #expect(r.exitCode != 0)
}

// MARK: - Running

@Test func returnsExitCodeAndOutput() async throws {
    let cli = try script("#!/bin/sh\necho out; echo err >&2; exit 2\n")
    let r = try await run(cli)
    #expect(r.exitCode == 2)
    #expect(r.stdout == "out\n")
    #expect(r.stderr == "err\n")
}

@Test func childSeesOnlyTheGivenEnvironment() async throws {
    // No setenv: it races getenv in parallel tests. Real parent variables must be absent instead.
    let cli = try script("#!/bin/sh\n/usr/bin/env\n")
    let r = try await run(cli)
    let names = Set(r.stdout.split(separator: "\n").compactMap { $0.split(separator: "=", maxSplits: 1).first.map(String.init) })
    #expect(names.subtracting(["HOME", "PATH", "LANG", "TMPDIR", "SSH_AUTH_SOCK", "PWD", "_", "SHLVL"]).isEmpty)
    let parent = Set(ProcessInfo.processInfo.environment.keys)
        .intersection(["USER", "SHELL", "LOGNAME", "XPC_SERVICE_NAME", "__CF_USER_TEXT_ENCODING"])
    for name in parent { #expect(!names.contains(name), "\(name) leaked into the child") }
    #expect(names.isSuperset(of: ["HOME", "PATH", "LANG", "TMPDIR", "SSH_AUTH_SOCK"]))
}

@Test func argumentsAreNotInterpretedByAShell() async throws {
    let cli = try script("#!/bin/sh\nprintf '%s\\n' \"$@\"\n")
    let r = try await run(cli, ["$(id)", "a b", "`x`"])
    #expect(r.stdout == "$(id)\na b\n`x`\n")
}

@Test func stdinIsDelivered() async throws {
    let cli = try script("#!/bin/sh\ncat\n")
    #expect(try await run(cli, stdin: Data("abc".utf8)).stdout == "abc")
}

@Test func noStdinMeansEndOfFile() async throws {
    let cli = try script("#!/bin/sh\ncat; echo done\n")
    #expect(try await run(cli).stdout == "done\n")
}

@Test func unreadStdinDoesNotCrashOrHang() async throws {
    // The child exits without reading 1 MB of stdin: the write fails with EPIPE, not SIGPIPE.
    let cli = try script("#!/bin/sh\nexit 0\n")
    let r = try await run(cli, stdin: Data(repeating: 65, count: 1_000_000))
    #expect(r.exitCode == 0)
}

@Test func largeOutputDoesNotDeadlock() async throws {
    let cli = try script("#!/bin/sh\nhead -c 1048576 /dev/zero | tr '\\0' x\nhead -c 1048576 /dev/zero | tr '\\0' y >&2\n")
    let r = try await run(cli)
    #expect(r.stdout.utf8.count == 1_048_576)
    #expect(r.stderr.utf8.count == 1_048_576)
}

@Test func cannotStartReportsTheReason() async throws {
    let cli = try script("not a program\n")   // executable, no shebang, not Mach-O
    do {
        _ = try await run(cli)
        Issue.record("expected cannotStart")
    } catch RunError.cannotStart(let reason) {
        #expect(!reason.isEmpty)
    }
}

// MARK: - Timeout and cancellation

@Test func timeoutKillsTheChild() async throws {
    let cli = try script("#!/bin/sh\nsleep 60\n")
    let started = ContinuousClock.now
    await #expect(throws: RunError.timedOut) { try await run(cli, timeout: .milliseconds(300)) }
    #expect(ContinuousClock.now - started < .seconds(40))   // far below the child's 60 s
}

@Test func timeoutLeavesNoOrphanedDescendant() async throws {
    let pidFile = dir().appending(path: "pid")
    let cli = try script("#!/bin/sh\nsleep 60 &\necho $! > '\(pidFile.path)'\nwait\n")
    let result = Task { try await run(cli, timeout: .seconds(5)) }
    let grandchild = try await readPid(pidFile)
    await #expect(throws: RunError.timedOut) { try await result.value }
    #expect(await goneSoon(grandchild))
}

@Test func aChildThatIgnoresSigtermIsKilled() async throws {
    let pidFile = dir().appending(path: "pid")
    let cli = try script("#!/bin/sh\ntrap '' TERM\necho $$ > '\(pidFile.path)'\nwhile :; do sleep 1; done\n")
    let started = ContinuousClock.now
    let result = Task { try await run(cli, timeout: .seconds(5)) }
    let pid = try await readPid(pidFile)
    await #expect(throws: RunError.timedOut) { try await result.value }
    #expect(ContinuousClock.now - started < .seconds(40))
    #expect(await goneSoon(pid))
}

@Test func cancellingTheTaskTerminatesTheChild() async throws {
    let pidFile = dir().appending(path: "pid")
    let cli = try script("#!/bin/sh\necho $$ > '\(pidFile.path)'\nsleep 30\n")
    let task = Task { try await run(cli, timeout: .seconds(60)) }
    let pid = try await readPid(pidFile)
    task.cancel()
    await #expect(throws: CancellationError.self) { try await task.value }
    #expect(await goneSoon(pid))
}

@Test func aTaskCancelledBeforeStartingStartsNothing() async throws {
    let marker = dir().appending(path: "marker")
    let cli = try script("#!/bin/sh\ntouch '\(marker.path)'\n")
    let task = Task {
        while !Task.isCancelled { await Task.yield() }
        return try await run(cli)
    }
    task.cancel()
    await #expect(throws: CancellationError.self) { try await task.value }
    #expect(!FileManager.default.fileExists(atPath: marker.path))
}

@Test func aDescendantInAnotherSessionCannotBlockTheCallForever() async throws {
    // perl's setsid puts the grandchild outside the child's process group, so the
    // group kill misses it and it keeps stdout open for 90 s.
    let pidFile = dir().appending(path: "pid")
    let cli = try script("""
        #!/bin/sh
        /usr/bin/perl -e 'use POSIX; if (fork == 0) { POSIX::setsid(); open(F, ">", $ARGV[0]); print F "$$\\n"; close F; exec "/bin/sleep", "90" } sleep 90' '\(pidFile.path)'
        """ + "\n")
    let started = ContinuousClock.now
    let task = Task { try await run(cli, timeout: .seconds(5)) }
    let stray = try await readPid(pidFile)
    defer { kill(stray, SIGKILL) }
    await #expect(throws: RunError.timedOut) { try await task.value }
    #expect(ContinuousClock.now - started < .seconds(60))   // the stray sleeps 90 s
}

/// F6 probe: the leader exits 0 at once; a same-group descendant keeps stdout open past the
/// timeout. Once the leader is reaped its pid/pgid must never be signalled, so the descendant
/// (the sentinel for "a signal reached the old group") is still alive when run() returns.
@Test func aReapedLeaderIsNeverSignalled() async throws {
    let pidFile = dir().appending(path: "pid")
    let cli = try script("#!/bin/sh\n/bin/sleep 30 &\necho $! > '\(pidFile.path)'\nexit 0\n")
    let task = Task { try await run(cli, timeout: .seconds(1)) }
    let sentinel = try await readPid(pidFile)
    defer { kill(sentinel, SIGKILL) }
    _ = try? await task.value
    try await Task.sleep(for: .seconds(3))   // past the delayed SIGKILL too
    #expect(isAlive(sentinel))
}

/// F6, timer path: the leader exits about when the timeout fires, while a same-group descendant
/// ignores SIGTERM and holds stdout. Whoever wins, the delayed SIGKILL comes after the leader is
/// gone, so it must never be sent and the descendant survives every round.
/// 10 rounds, two at a time: each round holds three global-queue threads for about 4 s, and ten
/// at once starve unrelated runs elsewhere in the suite.
@Test func aTimeoutRacingANormalExitNeverSignalsAfterTheReap() async throws {
    for _ in 0..<5 {
        try await withThrowingTaskGroup(of: Void.self) { pair in
            for _ in 0..<2 {
                pair.addTask {
                    let pidFile = dir().appending(path: "pid")
                    let cli = try script("#!/bin/sh\n(trap '' TERM; exec /bin/sleep 30) &\necho $! > '\(pidFile.path)'\n/bin/sleep 0.95\nexit 0\n")
                    let task = Task { try await run(cli, timeout: .seconds(1)) }
                    let sentinel = try await readPid(pidFile)
                    defer { kill(sentinel, SIGKILL) }
                    await #expect(throws: RunError.timedOut) { try await task.value }
                    try await Task.sleep(for: .milliseconds(500))   // the delayed SIGKILL (timeout + 2 s) precedes the return (timeout + 3 s)
                    #expect(isAlive(sentinel))
                }
            }
            try await pair.waitForAll()
        }
    }
}

/// F6 trade-off: after the leader is reaped, a same-group descendant holding the pipes is not
/// killed; the call still ends as timedOut within the bounded drain, and the descendant lives on.
@Test func aReapedLeaderWithAPipeHolderStillReturns() async throws {
    let pidFile = dir().appending(path: "pid")
    let cli = try script("#!/bin/sh\n/bin/sleep 90 &\necho $! > '\(pidFile.path)'\nexit 0\n")
    let started = ContinuousClock.now
    let task = Task { try await run(cli, timeout: .seconds(1)) }
    let descendant = try await readPid(pidFile)
    defer { kill(descendant, SIGKILL) }
    await #expect(throws: RunError.timedOut) { try await task.value }
    #expect(ContinuousClock.now - started < .seconds(60))   // the descendant sleeps 90 s
    #expect(isAlive(descendant))
}

/// F6, cancel path: cancelling after the leader was reaped sends neither SIGTERM nor the delayed SIGKILL.
@Test func cancelAfterTheLeaderIsReapedSignalsNothing() async throws {
    let pidFile = dir().appending(path: "pid")
    let cli = try script("#!/bin/sh\n/bin/sleep 30 &\necho $! > '\(pidFile.path)'\nexit 0\n")
    let task = Task { try await run(cli, timeout: .seconds(60)) }
    let sentinel = try await readPid(pidFile)
    defer { kill(sentinel, SIGKILL) }
    try await Task.sleep(for: .seconds(1))   // the leader has exited and been reaped
    task.cancel()
    await #expect(throws: CancellationError.self) { try await task.value }
    try await Task.sleep(for: .seconds(3))   // past the delayed SIGKILL
    #expect(isAlive(sentinel))
}
