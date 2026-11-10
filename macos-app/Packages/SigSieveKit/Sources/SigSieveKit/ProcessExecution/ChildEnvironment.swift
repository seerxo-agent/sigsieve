import Foundation

/// Why a temporary directory was refused. There is never a fallback to `/tmp`:
/// any of these blocks checks and connections.
public enum TempDirError: Error, Equatable, CustomStringConvertible {
    /// macOS did not report a per-user temporary directory.
    case unavailable
    case notAbsolute(String)
    case missing(String)
    case unresolvable(String)
    case unsupportedCharacters(String)
    case notADirectory(String)
    case wrongOwner(String)
    case notPrivate(String)
    case unsafeAncestor(String)

    public var description: String {
        switch self {
        case .unavailable: "macOS did not report a per-user temporary directory (confstr _CS_DARWIN_USER_TEMP_DIR)"
        case .notAbsolute(let p): "temporary directory \"\(p)\" is not an absolute path"
        case .missing(let p): "temporary directory \(p) does not exist"
        case .unresolvable(let p): "temporary directory \(p) cannot be resolved"
        case .unsupportedCharacters(let p): "temporary directory \(p) has characters other than ASCII letters, digits and /._-"
        case .notADirectory(let p): "temporary directory \(p) is not a directory"
        case .wrongOwner(let p): "temporary directory \(p) is not owned by the current user"
        case .notPrivate(let p): "temporary directory \(p) gives group or others access"
        case .unsafeAncestor(let p): "\(p), above the temporary directory, is writable by group or others without the sticky bit, or owned by another user"
        }
    }
}

/// A temporary directory that passed `TempDir.verified`. Only that function
/// creates one, so an unverified path cannot reach a child environment.
public struct VerifiedTempDir: Hashable, Sendable {
    public let path: String
    fileprivate init(_ path: String) { self.path = path }
}

public enum TempDir {
    /// The per-user temporary directory from `confstr`, never from the
    /// process environment (`TMPDIR` may be anything the launcher set).
    public static func system() throws -> String {
        let size = confstr(_CS_DARWIN_USER_TEMP_DIR, nil, 0)
        guard size > 1 else { throw TempDirError.unavailable }
        var buf = [CChar](repeating: 0, count: size)
        guard confstr(_CS_DARWIN_USER_TEMP_DIR, &buf, size) == size else { throw TempDirError.unavailable }
        return String(decoding: buf.prefix(size - 1).map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }

    /// Resolves symlinks, then requires: a directory, owned by `uid`, no group
    /// or other access, only ASCII letters, digits and `/._-` (what the CLI
    /// accepts in a socket path), and every ancestor owned by root or `uid`
    /// and not writable by group or others unless sticky (the CLI's rule).
    ///
    /// The ancestor rule is what makes the result usable later: only root or
    /// this user can replace the directory between this check and its use,
    /// and the CLI checks again when it creates its socket directory there.
    public static func verified(_ path: String, uid: uid_t = getuid()) throws -> VerifiedTempDir {
        guard path.hasPrefix("/") else { throw TempDirError.notAbsolute(path) }
        guard let r = realpath(path, nil) else {
            switch errno {
            case ENOENT: throw TempDirError.missing(path)
            case ENOTDIR: throw TempDirError.notADirectory(path)
            default: throw TempDirError.unresolvable(path)
            }
        }
        let resolved = String(cString: r)
        free(r)

        guard resolved.unicodeScalars.allSatisfy(isAllowed) else {
            throw TempDirError.unsupportedCharacters(resolved)
        }

        // The resolved path has no symlinks; O_NOFOLLOW makes sure one put
        // there since is refused rather than followed.
        let fd = open(resolved, O_SEARCH | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else {
            let e = errno
            throw e == ENOTDIR || e == ELOOP ? TempDirError.notADirectory(resolved) : TempDirError.unresolvable(resolved)
        }
        var st = stat()
        let ok = fstat(fd, &st) == 0
        close(fd)
        guard ok else { throw TempDirError.unresolvable(resolved) }
        guard st.st_mode & S_IFMT == S_IFDIR else { throw TempDirError.notADirectory(resolved) }
        guard st.st_uid == uid else { throw TempDirError.wrongOwner(resolved) }
        guard st.st_mode & 0o077 == 0 else { throw TempDirError.notPrivate(resolved) }

        var dir = resolved
        while dir != "/" {
            dir = (dir as NSString).deletingLastPathComponent
            var a = stat()
            guard lstat(dir, &a) == 0,
                  a.st_mode & S_IFMT == S_IFDIR,
                  a.st_uid == 0 || a.st_uid == uid,
                  a.st_mode & 0o022 == 0 || a.st_mode & S_ISVTX != 0
            else { throw TempDirError.unsafeAncestor(dir) }
        }
        return VerifiedTempDir(resolved)
    }

    private static func isAllowed(_ c: Unicode.Scalar) -> Bool {
        switch c {
        case "A"..."Z", "a"..."z", "0"..."9", "/", ".", "_", "-": true
        default: false
        }
    }
}

public struct EnvVar: Hashable, Sendable {
    public let name: String
    public let value: String
}

public enum ChildEnvironmentError: Error, Equatable {
    /// Not absolute, or holds `:` (a second PATH entry) or a control character.
    case unsafeCLIDirectory(String)
}

/// The whole environment of a child process, built from scratch: nothing is
/// copied from this process, so `SIGSIEVE_*` or any other variable in the
/// user's session cannot change what the CLI does.
public struct ChildEnvironment: Hashable, Sendable {
    /// In the documented order: HOME, PATH, LANG, TMPDIR, SSH_AUTH_SOCK.
    public let variables: [EnvVar]

    public var dictionary: [String: String] {
        Dictionary(uniqueKeysWithValues: variables.map { ($0.name, $0.value) })
    }

    public static func make(home: String, cliDirectory: String, tmpdir: VerifiedTempDir,
                            agent: AgentChoice) throws -> ChildEnvironment {
        guard cliDirectory.hasPrefix("/"), !cliDirectory.contains(":"),
              !cliDirectory.unicodeScalars.contains(where: { $0.properties.generalCategory == .control })
        else { throw ChildEnvironmentError.unsafeCLIDirectory(cliDirectory) }
        return ChildEnvironment(variables: [
            EnvVar(name: "HOME", value: home),
            EnvVar(name: "PATH", value: "/usr/bin:/bin:/usr/sbin:/sbin:\(cliDirectory)"),
            // Fixed so CLI and OpenSSH output is parsed in one language.
            EnvVar(name: "LANG", value: "en_US.UTF-8"),
            EnvVar(name: "TMPDIR", value: tmpdir.path),
            EnvVar(name: "SSH_AUTH_SOCK", value: agent.socketPath(home: home)),
        ])
    }
}

extension AgentChoice {
    /// The upstream agent socket: Secretive's fixed container path, or the chosen OpenSSH socket.
    public func socketPath(home: String) -> String {
        switch self {
        case .secretive: "\(home)/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh"
        case .openssh(let socket): socket
        }
    }
}
