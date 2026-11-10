import Foundation

public enum AgentChoice: Hashable, Sendable {
    case secretive
    case openssh(socket: String)
}

public enum ProtectionMode: String, Codable, Sendable {
    case filtering, binding
}

public struct Destination: Hashable, Codable, Sendable {
    public var name: String
    public var hostKeys: [Fingerprint]

    public init(name: String, hostKeys: [Fingerprint]) {
        self.name = name
        self.hostKeys = hostKeys
    }
}

public struct Profile: Hashable, Codable, Sendable {
    public var server: HostInput
    public var agent: AgentChoice
    public var forwardedKeys: [Fingerprint]
    public var mode: ProtectionMode
    public var destinations: [Destination]

    public init(server: HostInput, agent: AgentChoice, forwardedKeys: [Fingerprint],
                mode: ProtectionMode, destinations: [Destination]) {
        self.server = server
        self.agent = agent
        self.forwardedKeys = forwardedKeys
        self.mode = mode
        self.destinations = destinations
    }

    /// A server without a saved profile forwards no key.
    public static func empty(for server: HostInput, agent: AgentChoice) -> Profile {
        Profile(server: server, agent: agent, forwardedKeys: [], mode: .filtering, destinations: [])
    }
}

// `{ "kind": "secretive" }` or `{ "kind": "openssh", "socket": "/path" }`.
extension AgentChoice: Codable {
    private enum CodingKeys: String, CodingKey { case kind, socket }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        switch try c.decode(String.self, forKey: .kind) {
        case "secretive":
            self = .secretive
        case "openssh":
            let socket = try c.decode(String.self, forKey: .socket)
            guard socket.count > 1, socket.hasPrefix("/"),
                  !socket.unicodeScalars.contains(where: {
                      $0.properties.generalCategory == .control || $0.properties.generalCategory == .format
                  })
            else {
                throw DecodingError.dataCorruptedError(forKey: .socket, in: c,
                                                       debugDescription: "socket must be an absolute path")
            }
            self = .openssh(socket: socket)
        case let other:
            throw DecodingError.dataCorruptedError(forKey: .kind, in: c,
                                                   debugDescription: "unknown agent kind \(other)")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .secretive:
            try c.encode("secretive", forKey: .kind)
        case .openssh(let socket):
            try c.encode("openssh", forKey: .kind)
            try c.encode(socket, forKey: .socket)
        }
    }
}

public enum ProfileStoreError: Error, Equatable {
    /// The file has a `schemaVersion` this app does not write. Left untouched.
    case unsupportedVersion(Int)
    /// The file exists but cannot be read as version 1. Left untouched.
    case unreadable(String)
}

/// `profiles.json`: directory 0700, file 0600, replaced atomically. A file
/// that cannot be read, or has another schema version, is never overwritten.
///
/// Version 1 has exactly the fields of `Profile`. Unknown keys are ignored on
/// load and dropped on save, so adding a field means a new `schemaVersion`.
/// One writer is assumed (the app); concurrent writers would need a lock.
public struct ProfileStore: Sendable {
    public static let schemaVersion = 1
    /// Far above any real profile list; refuses to read a stray huge file.
    public static let maxFileSize: Int64 = 1 << 20

    public static var defaultDirectory: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appending(path: "Library/Application Support/SigSieve", directoryHint: .isDirectory)
    }

    public let directory: URL
    public var file: URL { directory.appending(path: "profiles.json") }

    public init(directory: URL) { self.directory = directory }

    private struct Envelope: Codable {
        var schemaVersion: Int
        var profiles: [Profile]
    }

    private struct VersionOnly: Decodable { var schemaVersion: Int }

    public func load() throws -> [Profile] {
        // lstat, not stat: a symlink would be read here but replaced by
        // save()'s rename, silently splitting the two. Refuse it, and any
        // directory, FIFO or other non-regular file.
        var st = stat()
        guard lstat(file.path, &st) == 0 else {
            let e = errno
            if e == ENOENT { return [] }
            throw posixError(e, "lstat", file.path)
        }
        guard st.st_mode & S_IFMT == S_IFREG else {
            throw ProfileStoreError.unreadable("\(file.path): not a regular file (symbolic links and special files are refused)")
        }
        guard st.st_size <= Self.maxFileSize else {
            throw ProfileStoreError.unreadable("\(file.path): larger than \(Self.maxFileSize) bytes")
        }
        let data: Data
        do {
            data = try Data(contentsOf: file)
        } catch {
            throw ProfileStoreError.unreadable("\(file.path): \(Self.underlying(error))")
        }
        return try decode(data, source: file.path)
    }

    public func save(_ profiles: [Profile]) throws {
        _ = try load() // an unreadable or newer file blocks saving

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let data: Data
        do {
            data = try encoder.encode(Envelope(schemaVersion: Self.schemaVersion, profiles: profiles))
        } catch {
            throw ProfileStoreError.unreadable("cannot encode profiles: \(error)")
        }
        // Never write a file that load() would refuse (for example a duplicate
        // server): it would block every later save.
        _ = try decode(data, source: "profiles to save")

        try makePrivateDirectory()
        try writeAtomically(data)
    }

    /// `source` names where the bytes came from in error messages.
    private func decode(_ data: Data, source: String) throws -> [Profile] {
        let decoder = JSONDecoder()
        // Read the version first, so a newer file with a different shape is
        // reported as newer rather than broken.
        guard let version = try? decoder.decode(VersionOnly.self, from: data).schemaVersion else {
            throw ProfileStoreError.unreadable("\(source): not a SigSieve profiles file")
        }
        guard version == Self.schemaVersion else { throw ProfileStoreError.unsupportedVersion(version) }

        let profiles: [Profile]
        do {
            profiles = try decoder.decode(Envelope.self, from: data).profiles
        } catch {
            throw ProfileStoreError.unreadable("\(source): \(Self.describe(error))")
        }
        var seen = Set<HostInput>()
        for p in profiles where !seen.insert(p.server).inserted {
            throw ProfileStoreError.unreadable("\(source): more than one profile for \(p.server.value)")
        }
        return profiles
    }

    private func makePrivateDirectory() throws {
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        } catch {
            throw ProfileStoreError.unreadable("\(directory.path): \(Self.underlying(error))")
        }
        // An existing directory keeps its mode on create; tighten it.
        guard chmod(directory.path, 0o700) == 0 else { throw posixError(errno, "chmod", directory.path) }
    }

    /// Temporary file in the same directory (O_EXCL, 0600), full sync, rename,
    /// then sync the directory so the rename itself is durable.
    private func writeAtomically(_ data: Data) throws {
        let temp = directory.appending(path: ".profiles.json.\(UUID().uuidString).tmp")
        let fd = open(temp.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw posixError(errno, "open", temp.path) }
        var renamed = false
        defer { if !renamed { unlink(temp.path) } }

        do {
            defer { close(fd) }
            // umask can only narrow 0600; set it exactly so the file stays readable and writable by us.
            guard fchmod(fd, 0o600) == 0 else { throw posixError(errno, "fchmod", temp.path) }
            try data.withUnsafeBytes { buf in
                var offset = 0
                while offset < buf.count {
                    let n = write(fd, buf.baseAddress! + offset, buf.count - offset)
                    if n < 0 {
                        if errno == EINTR { continue }
                        throw posixError(errno, "write", temp.path)
                    }
                    offset += n
                }
            }
            // fsync on macOS does not reach stable storage; F_FULLFSYNC does.
            // Some file systems refuse it, so fall back to fsync.
            if fcntl(fd, F_FULLFSYNC) != 0 && fsync(fd) != 0 { throw posixError(errno, "fsync", temp.path) }
        }

        guard rename(temp.path, file.path) == 0 else { throw posixError(errno, "rename", file.path) }
        renamed = true

        let dirFD = open(directory.path, O_RDONLY | O_CLOEXEC)
        if dirFD >= 0 {
            _ = fsync(dirFD) // best effort: the data is already in place
            close(dirFD)
        }
    }

    /// Callers pass `errno` as the first argument so it is read before anything
    /// else can allocate and change it.
    private func posixError(_ e: Int32, _ call: String, _ path: String) -> ProfileStoreError {
        .unreadable("\(path): \(call) failed: \(String(cString: strerror(e)))")
    }

    /// Foundation's message hides errno ("couldn't be opened"); prefer the POSIX cause.
    private static func underlying(_ error: Error) -> String {
        let ns = error as NSError
        return (ns.userInfo[NSUnderlyingErrorKey] as? NSError)?.localizedDescription ?? ns.localizedDescription
    }

    private static func describe(_ error: Error) -> String {
        guard let e = error as? DecodingError else { return "\(error)" }
        switch e {
        case .dataCorrupted(let c), .keyNotFound(_, let c), .typeMismatch(_, let c), .valueNotFound(_, let c):
            let path = c.codingPath.map { $0.intValue.map(String.init) ?? $0.stringValue }.joined(separator: ".")
            return path.isEmpty ? c.debugDescription : "\(path): \(c.debugDescription)"
        @unknown default:
            return "\(error)"
        }
    }
}
