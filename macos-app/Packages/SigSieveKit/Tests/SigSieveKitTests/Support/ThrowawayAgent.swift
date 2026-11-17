import CryptoKit
import Foundation
@testable import SigSieveKit

struct ThrowawayAgentError: Error, CustomStringConvertible {
    let description: String
}

/// A private `ssh-agent` holding freshly generated Ed25519 keys, in its own
/// temporary directory. Never touches `~/.ssh`, the user's agent or their keys.
/// `deinit` kills the agent and removes the directory.
final class ThrowawayAgent: @unchecked Sendable {
    let directory: URL
    let socket: String
    /// In generation order, computed from the public key files, not from the agent.
    /// A var with a default so every stored property is set before anything can
    /// throw: a failed init then still runs deinit and kills the agent.
    private(set) var fingerprints: [Fingerprint] = []
    /// The agent's pid, 0 once stopped. Spawned and reaped here, not through
    /// Foundation's Process: its waitUntilExit hung on the main thread under
    /// `swift test --no-parallel` after the agent had already exited.
    private var pid: pid_t = 0

    init(keys: Int) throws {
        // Short path: the socket must fit in sun_path (103 bytes).
        directory = TestDirectory.make()
        socket = directory.appending(path: "a.sock").path
        // -D keeps the agent as our child, so deinit can kill exactly it.
        pid = try Self.spawn("/usr/bin/ssh-agent", ["-D", "-a", socket])

        // Locked by `lock`; a class so the concurrent closure can share it.
        final class Results: @unchecked Sendable {
            var fps: [Fingerprint?]
            var failure: String?
            init(_ n: Int) { fps = Array(repeating: nil, count: n) }
        }
        let results = Results(keys)
        let lock = NSLock()
        let dir = directory
        // Four workers, not one per core: other tests in this run (filtering500KeysIsFast)
        // measure wall time and must not compete with hundreds of ssh-keygen processes.
        let workers = 4
        DispatchQueue.concurrentPerform(iterations: workers) { w in
            for i in stride(from: w, to: keys, by: workers) {
                do {
                    let path = dir.appending(path: "k\(i)").path
                    try Self.exec("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "k\(i)", "-f", path])
                    let fp = try Self.fingerprint(ofPublicKeyFile: path + ".pub")
                    lock.withLock { results.fps[i] = fp }
                } catch {
                    lock.withLock { results.failure = "\(error)" }
                }
            }
        }
        if let failure = results.failure { throw ThrowawayAgentError(description: failure) }
        fingerprints = results.fps.map { $0! }

        // Wait for the socket, then add every key in one ssh-add call.
        let deadline = Date().addingTimeInterval(10)
        while access(socket, F_OK) != 0 {
            let exited = waitpid(pid, nil, WNOHANG) != 0
            if exited { pid = 0 }
            guard Date() < deadline, !exited else {
                throw ThrowawayAgentError(description: "ssh-agent did not create \(socket)")
            }
            usleep(10_000)
        }
        if keys > 0 {
            try Self.exec("/usr/bin/ssh-add", ["-q"] + (0..<keys).map { dir.appending(path: "k\($0)").path },
                          environment: ["PATH": "/usr/bin:/bin", "SSH_AUTH_SOCK": socket])
        }
    }

    /// Kills the agent now; the directory stays until deinit.
    func stop() {
        guard pid > 0 else { return }
        kill(pid, SIGKILL)
        var status: Int32 = 0
        while waitpid(pid, &status, 0) < 0 && errno == EINTR {}
        pid = 0
    }

    deinit {
        stop()
        try? FileManager.default.removeItem(at: directory)
    }

    /// SHA-256 over the decoded key blob, unpadded base64: what OpenSSH prints.
    static func fingerprint(ofPublicKeyFile path: String) throws -> Fingerprint {
        let line = try String(contentsOfFile: path, encoding: .utf8)
        let fields = line.split(separator: " ")
        guard fields.count >= 2, let blob = Data(base64Encoded: String(fields[1])) else {
            throw ThrowawayAgentError(description: "unreadable public key \(path)")
        }
        let b64 = Data(SHA256.hash(data: blob)).base64EncodedString().replacingOccurrences(of: "=", with: "")
        guard let fp = Fingerprint("SHA256:" + b64) else { throw ThrowawayAgentError(description: "bad fingerprint \(b64)") }
        return fp
    }

    /// posix_spawn with stdin and stdout on /dev/null and stderr inherited.
    /// Every other descriptor is closed in the child (POSIX_SPAWN_CLOEXEC_DEFAULT):
    /// a long-lived agent must not hold another test's ProcessRunner pipe open.
    private static func spawn(_ tool: String, _ args: [String],
                              environment: [String: String] = ["PATH": "/usr/bin:/bin"]) throws -> pid_t {
        var actions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&actions)
        defer { posix_spawn_file_actions_destroy(&actions) }
        posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0)
        posix_spawn_file_actions_addopen(&actions, 1, "/dev/null", O_WRONLY, 0)
        posix_spawn_file_actions_addinherit_np(&actions, 2)
        var attr: posix_spawnattr_t?
        posix_spawnattr_init(&attr)
        defer { posix_spawnattr_destroy(&attr) }
        posix_spawnattr_setflags(&attr, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT))
        let argv = ([tool] + args).map { strdup($0) } + [nil]
        let envp = environment.map { strdup("\($0.key)=\($0.value)") } + [nil]
        defer { (argv + envp).forEach { free($0) } }
        var pid: pid_t = 0
        let rc = posix_spawn(&pid, tool, &actions, &attr, argv, envp)
        guard rc == 0 else { throw ThrowawayAgentError(description: "\(tool): \(String(cString: strerror(rc)))") }
        return pid
    }

    private static func exec(_ tool: String, _ args: [String],
                             environment: [String: String] = ["PATH": "/usr/bin:/bin"]) throws {
        let pid = try spawn(tool, args, environment: environment)
        var status: Int32 = 0
        while waitpid(pid, &status, 0) < 0 {
            guard errno == EINTR else { throw ThrowawayAgentError(description: "waitpid \(tool): \(errno)") }
        }
        guard status == 0 else {
            throw ThrowawayAgentError(description: "\(tool) \(args.prefix(4)) failed, wait status \(status)")
        }
    }
}
