import Foundation

/// The only programs the app starts. There is no case for an arbitrary path
/// except the CLI, and that one is checked again at run time.
public enum Tool: Sendable {
    case cli(URL)
    case sshAdd
    case sshKeygen

    public var url: URL {
        switch self {
        case .cli(let url): url
        case .sshAdd: URL(filePath: "/usr/bin/ssh-add")
        case .sshKeygen: URL(filePath: "/usr/bin/ssh-keygen")
        }
    }
}

public struct RunResult: Sendable {
    public let exitCode: Int32
    public let stdout: String
    public let stderr: String
}

public enum RunError: Error, Equatable {
    case timedOut
    /// The process could not be launched; the text is the system's reason.
    case cannotStart(String)
    /// The CLI path (symlinks resolved) is not a regular executable file named `sigsieve`.
    case notAllowed(String)
}

public protocol Running: Sendable {
    func run(_ tool: Tool, _ arguments: [String], environment: ChildEnvironment,
             stdin: Data?, timeout: Duration) async throws -> RunResult
}

/// The one controlled place that starts a process: no shell, an explicit
/// argument vector, a from-scratch environment, bounded by a timeout, and
/// terminated if the calling task is cancelled.
public struct ProcessRunner: Running {
    public init() {}

    public func run(_ tool: Tool, _ arguments: [String], environment: ChildEnvironment,
                    stdin: Data?, timeout: Duration) async throws -> RunResult {
        let executable = try Self.allowedExecutable(tool)
        let job = Job(executable: executable, arguments: arguments, environment: environment.dictionary,
                      stdin: stdin, timeout: timeout)
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                // The job blocks (pipes, waitpid): keep it off the Swift cooperative pool.
                DispatchQueue.global().async { continuation.resume(with: Result { try job.execute() }) }
            }
        } onCancel: {
            job.cancel()
        }
    }

    /// Resolves symlinks and launches the resolved path. This is a misconfiguration
    /// guard (a link or setting that points at some other program), not a defence
    /// against a local attacker: anyone who can write that directory can place any
    /// binary named `sigsieve`, or swap the file between this check and the launch.
    static func allowedExecutable(_ tool: Tool) throws -> URL {
        guard case .cli(let url) = tool else { return tool.url }
        guard let r = realpath(url.path, nil) else { throw RunError.notAllowed(url.path) }
        let resolved = String(cString: r)
        free(r)
        var st = stat()
        guard stat(resolved, &st) == 0, st.st_mode & S_IFMT == S_IFREG,
              access(resolved, X_OK) == 0,
              URL(filePath: resolved).lastPathComponent == "sigsieve"
        else { throw RunError.notAllowed(resolved) }
        return URL(filePath: resolved)
    }
}

/// One run. `execute` blocks until the child is gone and its pipes are
/// drained; `cancel` may be called from any thread at any time.
private final class Job: @unchecked Sendable {
    private let process = Process()
    private let stdin: Data?
    private let timeout: Duration
    private let lock = NSLock()
    private var cancelled = false
    private var timedOut = false
    private var started = false
    private var finished = false
    private var ownsGroup = false

    init(executable: URL, arguments: [String], environment: [String: String], stdin: Data?, timeout: Duration) {
        process.executableURL = executable
        process.arguments = arguments
        process.environment = environment
        self.stdin = stdin
        self.timeout = timeout
    }

    func cancel() {
        lock.lock()
        cancelled = true
        let running = started && !finished
        lock.unlock()
        if running { terminate() }
    }

    func execute() throws -> RunResult {
        let out = Pipe(), err = Pipe(), inp = Pipe()
        process.standardOutput = out
        process.standardError = err
        process.standardInput = stdin == nil ? FileHandle.nullDevice : inp

        lock.lock()
        if cancelled { lock.unlock(); throw CancellationError() }
        do { try process.run() } catch {
            lock.unlock()
            throw RunError.cannotStart(error.localizedDescription)
        }
        started = true
        // Foundation starts the child as its own process group leader; descendants
        // (a script's `sleep`) share the group and must die with it. Verified, not assumed.
        ownsGroup = getpgid(process.processIdentifier) == process.processIdentifier
        lock.unlock()

        let readers = DispatchGroup()
        let box = Output()
        for (pipe, isOut) in [(out, true), (err, false)] {
            readers.enter()
            DispatchQueue.global().async {
                box.drain(pipe.fileHandleForReading, isOut: isOut)
                readers.leave()
            }
        }
        if let stdin {
            let handle = inp.fileHandleForWriting
            // EPIPE as an error, not a SIGPIPE that kills the app, if the child never reads.
            _ = fcntl(handle.fileDescriptor, F_SETNOSIGPIPE, 1)
            DispatchQueue.global().async {
                try? handle.write(contentsOf: stdin)
                try? handle.close()
            }
        }

        let timer = DispatchWorkItem { [self] in
            lock.lock()
            let expire = !finished && !cancelled
            if expire { timedOut = true }
            lock.unlock()
            if expire { terminate() }
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + .nanoseconds(Self.nanoseconds(timeout)), execute: timer)

        process.waitUntilExit()
        // Normally the pipes reach EOF with the child. After a timeout or cancel a
        // descendant in another session (setsid) can still hold them: give the
        // SIGKILL grace plus a second, then stop reading instead of blocking forever.
        var giveUp: DispatchTime?
        while readers.wait(timeout: .now() + .milliseconds(50)) == .timedOut {
            lock.lock()
            let stopping = cancelled || timedOut
            lock.unlock()
            guard stopping else { continue }
            if giveUp == nil { giveUp = .now() + .seconds(3) }
            if .now() > giveUp! { box.abandon() }
        }
        timer.cancel()
        lock.lock()
        finished = true
        let (wasCancelled, didTimeOut) = (cancelled, timedOut)
        lock.unlock()

        if wasCancelled { throw CancellationError() }
        if didTimeOut { throw RunError.timedOut }
        let (o, e) = box.get()
        return RunResult(exitCode: process.terminationStatus,
                         stdout: String(decoding: o, as: UTF8.self), stderr: String(decoding: e, as: UTF8.self))
    }

    /// SIGTERM now, SIGKILL after 2 s, to the whole group when the child leads one.
    ///
    /// Accepted risk (security review F6, owner acceptance): `finished` is set only after the pipes
    /// are drained, so the delayed SIGKILL (or a late cancel or timeout) can run after the child was
    /// reaped. If every descendant had left the group (setsid) and the pid was reused for another
    /// group in that window, the signal could reach an unrelated process group of the same user.
    /// Impact: a signal could reach an unrelated process group of the same user, in a typically
    /// sub-second window (at most the 2 s kill delay plus the 1 s drain grace). Accepted because it
    /// needs a child that calls setsid, keeps the pipes open and outlives the CLI, plus pid
    /// wraparound inside that window; the real CLI does neither during a check, and descendants
    /// that hold the pipes are already handled by `abandon()`.
    private func terminate() {
        let pid = process.processIdentifier
        send(SIGTERM, pid)
        DispatchQueue.global().asyncAfter(deadline: .now() + .seconds(2)) { [self] in
            lock.lock()
            let done = finished
            lock.unlock()
            // Once the run is over the group id may belong to something else.
            if done { return }
            // Also after the leader is gone: a descendant that ignored SIGTERM may still hold the pipes.
            send(SIGKILL, pid)
        }
    }

    private func send(_ signal: Int32, _ pid: pid_t) {
        lock.lock()
        let group = ownsGroup
        lock.unlock()
        _ = group ? killpg(pid, signal) : kill(pid, signal)
    }

    private static func nanoseconds(_ d: Duration) -> Int {
        let c = d.components
        let (ns, overflow) = Int(clamping: max(0, c.seconds)).multipliedReportingOverflow(by: 1_000_000_000)
        return overflow ? Int.max : ns.addingReportingOverflow(Int(c.attoseconds / 1_000_000_000)).partialValue
    }
}

private final class Output: @unchecked Sendable {
    private let lock = NSLock()
    private var out = Data(), err = Data()
    private var abandoned = false

    /// Reads until EOF, or until `abandon()`; polls so a pipe held open by a
    /// stray descendant cannot block this thread forever. Closes the read end.
    func drain(_ handle: FileHandle, isOut: Bool) {
        let fd = handle.fileDescriptor
        var buffer = [UInt8](repeating: 0, count: 65536)
        loop: while true {
            lock.lock(); let stop = abandoned; lock.unlock()
            if stop { break }
            var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let ready = poll(&p, 1, 100)
            if ready < 0 { if errno == EINTR { continue } else { break } }
            if ready == 0 { continue }
            let n = read(fd, &buffer, buffer.count)
            if n < 0 { if errno == EINTR { continue } else { break loop } }
            if n == 0 { break }
            lock.lock()
            if isOut { out.append(contentsOf: buffer[0..<n]) } else { err.append(contentsOf: buffer[0..<n]) }
            lock.unlock()
        }
        try? handle.close()
    }
    func abandon() { lock.lock(); abandoned = true; lock.unlock() }
    func get() -> (Data, Data) {
        lock.lock(); defer { lock.unlock() }
        return (out, err)
    }
}
