import AppKit
import Foundation

public enum LauncherError: Error, Equatable, CustomStringConvertible {
    case unsafeTmpdir(String)
    case io(step: String, errno: Int32)
    case terminalMissing
    case openFailed(String)
    /// The profile's protection cannot be applied as chosen (`Profile.policyProblem`).
    case invalidPolicy(String)

    public var description: String {
        switch self {
        case .unsafeTmpdir(let p): "temporary directory \"\(p)\" is not an absolute path without . or .. components"
        case .io(let step, let e): "\(step) failed: \(String(cString: strerror(e)))"
        case .terminalMissing: "Terminal.app was not found at \(Launcher.terminalPath)"
        case .openFailed(let m): "Terminal could not open the launcher: \(m)"
        case .invalidPolicy(let m): m
        }
    }
}

/// Writes the private, self-deleting `connect.command` and opens it in
/// Terminal through NSWorkspace: no AppleScript, no Automation entitlement,
/// no child process started by the app.
public enum Launcher {
    static let prefix = "sigsieve-launch-"
    static let scriptName = "connect.command"
    static let terminalPath = "/System/Applications/Utilities/Terminal.app"

    /// Creates `<tmpdir>/sigsieve-launch-XXXXXX` (0700) holding `connect.command`
    /// (0700). `tmpdir` is the verified TMPDIR. Removes what it created on failure.
    public static func write(_ inputs: CheckInputs, under tmpdir: String) throws -> URL {
        if let problem = inputs.profile.policyProblem { throw LauncherError.invalidPolicy(problem) }
        let parts = tmpdir.split(separator: "/")
        guard tmpdir.hasPrefix("/"), !parts.contains("."), !parts.contains("..") else {
            throw LauncherError.unsafeTmpdir(tmpdir)
        }
        let parentFD = Darwin.open(tmpdir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parentFD >= 0 else { throw LauncherError.io(step: "opening the temporary directory", errno: errno) }
        defer { close(parentFD) }
        var template = Array((tmpdir + "/" + prefix + "XXXXXX").utf8CString)
        guard mkdtemp(&template) != nil else { throw LauncherError.io(step: "creating the launcher directory", errno: errno) }
        let dir = String(decoding: template.dropLast().map { UInt8(bitPattern: $0) }, as: UTF8.self)
        let dirName = String(dir.split(separator: "/").last ?? "")

        var dirFD: Int32 = -1
        var created = false
        // `e` is read by the caller straight after the failing call.
        func fail(_ step: String, _ e: Int32) -> LauncherError {
            if created { unlinkat(dirFD, scriptName, 0) }
            if dirFD >= 0 { close(dirFD) }
            unlinkat(parentFD, dirName, AT_REMOVEDIR)
            return .io(step: step, errno: e)
        }
        dirFD = Darwin.open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard dirFD >= 0 else { let e = errno; throw fail("opening the launcher directory", e) }
        guard fchmod(dirFD, 0o700) == 0 else { let e = errno; throw fail("setting the launcher directory mode", e) }

        let fd = openat(dirFD, scriptName, O_CREAT | O_EXCL | O_NOFOLLOW | O_WRONLY | O_CLOEXEC, 0o700)
        guard fd >= 0 else { let e = errno; throw fail("creating the script", e) }
        created = true
        // Regardless of umask.
        guard fchmod(fd, 0o700) == 0 else { let e = errno; close(fd); throw fail("setting the script mode", e) }

        let text = CommandBuilder.launcherScript(inputs.profile, cli: inputs.cli, environment: inputs.environment,
                                                 selfDirectory: dir)
        var rest = Array(text.utf8)[...]
        while !rest.isEmpty {
            let n = rest.withUnsafeBytes { Foundation.write(fd, $0.baseAddress, $0.count) }
            if n < 0 && errno == EINTR { continue }
            guard n > 0 else { let e = errno; close(fd); throw fail("writing the script", e) }
            rest = rest.dropFirst(n)
        }
        close(fd)
        close(dirFD)
        return URL(filePath: dir + "/" + scriptName)
    }

    /// Opens `script` in Terminal.app. Throws if Terminal is missing or
    /// NSWorkspace reports an error.
    public static func open(_ script: URL) async throws {
        let terminal = URL(filePath: terminalPath, directoryHint: .isDirectory)
        guard FileManager.default.fileExists(atPath: terminalPath) else { throw LauncherError.terminalMissing }
        do {
            _ = try await NSWorkspace.shared.open([script], withApplicationAt: terminal,
                                                  configuration: NSWorkspace.OpenConfiguration())
        } catch {
            throw LauncherError.openFailed(error.localizedDescription)
        }
    }

    /// Best-effort removal of launcher directories left by a script that never
    /// ran. Only direct children of `tmpdir` named `sigsieve-launch-*` that are
    /// real directories owned by this user, older than `olderThan`, and hold
    /// nothing but `connect.command` (a regular file) or nothing at all.
    /// Nothing is followed through a symlink; errors are ignored.
    public static func removeStale(under tmpdir: String, olderThan: TimeInterval = 3600, now: Date = .now) {
        let parts = tmpdir.split(separator: "/")
        guard tmpdir.hasPrefix("/"), !parts.contains("."), !parts.contains("..") else { return }
        let parent = Darwin.open(tmpdir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0 else { return }
        defer { close(parent) }
        guard let names = entryNames(parent) else { return }
        for name in names where name.hasPrefix(prefix) {
            let child = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard child >= 0 else { continue }
            defer { close(child) }
            var st = stat()
            guard fstat(child, &st) == 0, st.st_mode & S_IFMT == S_IFDIR, st.st_uid == getuid(),
                  now.timeIntervalSince1970 - Double(st.st_mtimespec.tv_sec) > olderThan,
                  let entries = entryNames(child)
            else { continue }
            if entries == [scriptName] {
                var fs = stat()
                guard fstatat(child, scriptName, &fs, AT_SYMLINK_NOFOLLOW) == 0, fs.st_mode & S_IFMT == S_IFREG,
                      unlinkat(child, scriptName, 0) == 0 else { continue }
            } else if !entries.isEmpty {
                continue
            }
            unlinkat(parent, name, AT_REMOVEDIR)
        }
    }

    /// Names in the directory `fd` (not `.` or `..`); `nil` if it cannot be read.
    /// Reads a duplicate, so `fd` stays open and unmoved.
    private static func entryNames(_ fd: Int32) -> [String]? {
        let copy = dup(fd)
        guard copy >= 0, let d = fdopendir(copy) else { if copy >= 0 { close(copy) }; return nil }
        defer { closedir(d) }
        var names: [String] = []
        while let e = readdir(d) {
            let name = withUnsafePointer(to: &e.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) { String(cString: $0) }
            }
            if name != "." && name != ".." { names.append(name) }
        }
        return names
    }
}
