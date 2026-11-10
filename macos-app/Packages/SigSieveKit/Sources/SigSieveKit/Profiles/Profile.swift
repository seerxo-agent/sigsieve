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
    /// The existing file, or the directory holding it, cannot be read as
    /// version 1. Left untouched.
    case unreadable(String)
    /// Saving failed in the file system: disk full, read-only volume, or a
    /// failed create, write, sync or rename. The existing file is left as it was.
    case writeFailed(String)
    /// The profile list given to `save` does not pass validation (for example
    /// the same server twice). Nothing was written.
    case invalidProfiles(String)
}

/// `profiles.json`: directory 0700, file 0600, replaced atomically. A file
/// that cannot be read, or has another schema version, is never overwritten.
///
/// Version 1 has exactly the fields of `Profile`. Unknown keys are ignored on
/// load and dropped on save, so adding a field means a new `schemaVersion`.
///
/// The profile directory (the last path component of `directory`) and the
/// file may not be symbolic links. The directory is opened once with
/// `O_NOFOLLOW` and every later step works relative to that descriptor, so a
/// link swapped in afterwards is not followed either. Parent directories are
/// resolved normally.
///
/// Known limits (v1):
/// - One writer, no lock. `save` replaces the whole file with the list it is
///   given. If two app instances are open, whichever saves last wins: profiles
///   the other instance saved after this one loaded are lost, however long
///   ago that was. The file itself is never left half written by a save.
/// - On a normal error the temporary file is removed. If the process dies
///   between creating it and the rename, a `.profiles.json.<uuid>.tmp` stays
///   in the directory; it is never read and is safe to delete.
/// - Power loss: on APFS, `F_FULLFSYNC` flushes the new contents before the
///   rename. Afterwards the file may be the old version, the new one, or
///   missing (first save); the rename and directory sync are not a durability
///   guarantee. On a volume without `F_FULLFSYNC` (some network and FAT
///   volumes) plain `fsync` is used and the file may be damaged; `load` then
///   reports it unreadable and leaves it alone.
public struct ProfileStore: Sendable {
    public static let schemaVersion = 1
    /// Far above any real profile list; refuses to read a stray huge file.
    public static let maxFileSize: Int64 = 1 << 20

    public static var defaultDirectory: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appending(path: "Library/Application Support/SigSieve", directoryHint: .isDirectory)
    }

    public let directory: URL
    public var file: URL { directory.appending(path: Self.fileName) }
    private static let fileName = "profiles.json"

    public init(directory: URL) { self.directory = directory }

    private struct Envelope: Codable {
        var schemaVersion: Int
        var profiles: [Profile]
    }

    private struct VersionOnly: Decodable { var schemaVersion: Int }

    public func load() throws -> [Profile] {
        guard let dir = try openDirectory() else { return [] }
        defer { close(dir) }
        return try readFile(in: dir)
    }

    public func save(_ profiles: [Profile]) throws {
        var dir = try openDirectory()
        defer { if let d = dir { close(d) } }
        if let d = dir { _ = try readFile(in: d) } // an unreadable or newer file blocks saving

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let data: Data
        do {
            data = try encoder.encode(Envelope(schemaVersion: Self.schemaVersion, profiles: profiles))
        } catch {
            throw ProfileStoreError.invalidProfiles("cannot encode profiles: \(error)")
        }
        // Never write a file that load() would refuse (for example a duplicate
        // server): it would block every later save. The fault is in the list,
        // not on disk.
        do {
            _ = try decode(data, source: "profiles to save")
        } catch ProfileStoreError.unreadable(let m) {
            throw ProfileStoreError.invalidProfiles(m)
        }

        if dir == nil { dir = try createDirectory() }
        let d = dir!
        var st = stat()
        guard fstat(d, &st) == 0 else { throw Self.writeFailed(errno, "fstat", directory.path) }
        if st.st_mode & 0o7777 != 0o700 {
            guard fchmod(d, 0o700) == 0 else { throw Self.writeFailed(errno, "fchmod", directory.path) }
        }
        try writeAtomically(data, in: d)
    }

    /// Opens the profile directory for search only, refusing a symbolic link,
    /// a non-directory, or one owned by another user. `nil` when it does not
    /// exist yet. The caller closes the descriptor.
    private func openDirectory() throws -> Int32? {
        let fd = open(directory.path, O_SEARCH | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else {
            let e = errno
            if e == ENOENT { return nil }
            if e == ELOOP || e == ENOTDIR {
                throw ProfileStoreError.unreadable("\(directory.path): not a directory (symbolic links are refused)")
            }
            throw ProfileStoreError.unreadable(Self.posix(e, "open", directory.path))
        }
        var st = stat()
        guard fstat(fd, &st) == 0 else {
            let e = errno
            close(fd)
            throw ProfileStoreError.unreadable(Self.posix(e, "fstat", directory.path))
        }
        guard st.st_uid == getuid() else {
            close(fd)
            throw ProfileStoreError.unreadable("\(directory.path): owned by another user")
        }
        return fd
    }

    private func createDirectory() throws -> Int32 {
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        } catch {
            throw ProfileStoreError.writeFailed("\(directory.path): \(Self.underlying(error))")
        }
        do {
            guard let fd = try openDirectory() else {
                throw ProfileStoreError.writeFailed("\(directory.path): missing right after it was created")
            }
            return fd
        } catch ProfileStoreError.unreadable(let m) {
            throw ProfileStoreError.writeFailed(m)
        }
    }

    /// Reads `profiles.json` inside `dir`: a regular file, not a symbolic link
    /// (a link would be read here but replaced by the rename on save), at most
    /// `maxFileSize` bytes. `O_NONBLOCK` keeps a FIFO from blocking the open.
    private func readFile(in dir: Int32) throws -> [Profile] {
        let fd = openat(dir, Self.fileName, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else {
            let e = errno
            if e == ENOENT { return [] }
            if e == ELOOP { throw Self.notRegular(file.path) }
            throw ProfileStoreError.unreadable(Self.posix(e, "open", file.path))
        }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0 else { throw ProfileStoreError.unreadable(Self.posix(errno, "fstat", file.path)) }
        guard st.st_mode & S_IFMT == S_IFREG else { throw Self.notRegular(file.path) }
        guard st.st_size <= Self.maxFileSize else { throw Self.tooLarge(file.path) }

        var data = Data()
        var buf = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let n = Darwin.read(fd, &buf, buf.count)
            if n < 0 {
                if errno == EINTR { continue }
                throw ProfileStoreError.unreadable(Self.posix(errno, "read", file.path))
            }
            if n == 0 { break }
            data.append(contentsOf: buf[0..<n])
            if data.count > Self.maxFileSize { throw Self.tooLarge(file.path) } // grew after fstat
        }
        return try decode(data, source: file.path)
    }

    /// Temporary file in `dir` (O_EXCL, 0600), full sync, rename, then a
    /// best-effort sync of the directory (see the limits above).
    private func writeAtomically(_ data: Data, in dir: Int32) throws {
        let tempName = ".profiles.json.\(UUID().uuidString).tmp"
        let tempPath = directory.appending(path: tempName).path
        let fd = openat(dir, tempName, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw Self.writeFailed(errno, "open", tempPath) }
        var renamed = false
        defer { if !renamed { unlinkat(dir, tempName, 0) } }

        do {
            defer { close(fd) }
            // umask can only narrow 0600; set it exactly so the file stays readable and writable by us.
            guard fchmod(fd, 0o600) == 0 else { throw Self.writeFailed(errno, "fchmod", tempPath) }
            try data.withUnsafeBytes { buf in
                var offset = 0
                while offset < buf.count {
                    let n = write(fd, buf.baseAddress! + offset, buf.count - offset)
                    if n < 0 {
                        if errno == EINTR { continue }
                        throw Self.writeFailed(errno, "write", tempPath)
                    }
                    offset += n
                }
            }
            try Self.fullSync(fd, tempPath)
        }

        guard renameat(dir, tempName, dir, Self.fileName) == 0 else {
            throw Self.writeFailed(errno, "rename", file.path)
        }
        renamed = true
        _ = fsync(dir) // best effort; see the limits above
    }

    /// `F_FULLFSYNC` flushes the drive cache; plain `fsync` on macOS does not.
    /// Fall back only when the file system does not support it; a real I/O
    /// error from `F_FULLFSYNC` is a failed write.
    private static func fullSync(_ fd: Int32, _ path: String) throws {
        if fcntl(fd, F_FULLFSYNC) == 0 { return }
        let e = errno
        guard e == ENOTSUP || e == EINVAL || e == ENOTTY else { throw writeFailed(e, "F_FULLFSYNC", path) }
        guard fsync(fd) == 0 else { throw writeFailed(errno, "fsync", path) }
    }

    private static func notRegular(_ path: String) -> ProfileStoreError {
        .unreadable("\(path): not a regular file (symbolic links and special files are refused)")
    }

    private static func tooLarge(_ path: String) -> ProfileStoreError {
        .unreadable("\(path): larger than \(maxFileSize) bytes")
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

    /// Callers pass `errno` as the first argument so it is read before anything
    /// else can allocate and change it.
    private static func posix(_ e: Int32, _ call: String, _ path: String) -> String {
        "\(path): \(call) failed: \(String(cString: strerror(e)))"
    }

    private static func writeFailed(_ e: Int32, _ call: String, _ path: String) -> ProfileStoreError {
        .writeFailed(posix(e, call, path))
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
