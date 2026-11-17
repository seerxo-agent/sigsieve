import Foundation

/// A file or directory an Include resolved to, as it looked then. Size -1
/// means it could not be stat'ed (for example an include target not created yet).
public struct FileStamp: Hashable, Sendable {
    public let path: String
    public let size: Int64
    public let modified: Date
    /// Identity: mode, device, inode and ctime (sec, nsec) from `lstat`, then the same from
    /// `stat`. A failed call records `-errno` instead, so ENOENT, EACCES and ENOTDIR differ.
    ///
    /// Security assumptions. Detects: a rewrite (even same size with the mtime restored), delete
    /// and recreate, a symlink retargeted or its target replaced, a mode change, and missing vs
    /// unreadable vs a FIFO or dangling link. Does not guarantee: ctime cannot be set from
    /// userland, but root can, and a filesystem without real ctime/inode semantics (some network
    /// or FUSE volumes) can defeat it. That is acceptable because the stamp only invalidates a
    /// stale check shown in the UI; it is not a security boundary. The Rust CLI and OpenSSH
    /// re-check at connect.
    public let identity: [Int64]

    init(path: String, size: Int64, modified: Date, identity: [Int64] = []) {
        self.path = path
        self.size = size
        self.modified = modified
        self.identity = identity
    }
}

public struct AliasDiscovery: Equatable, Sendable {
    public let aliases: [HostInput]
    public let stamps: [FileStamp]
    public let skippedIncludes: [String]
}

/// Host aliases from `~/.ssh/config`, for display only. This reads files and
/// runs nothing; it decides nothing about safety and is deliberately not a
/// full ssh_config parser (no Match evaluation, no variable expansion).
public enum SSHConfigAliases {
    private static let maxDepth = 16
    private static let maxFileSize: Int64 = 1_000_000
    // Total work per discovery, so a hostile or looping config cannot hang the app.
    private static let maxFiles = 256
    private static let maxBytes: Int64 = 8_000_000
    private static let maxIncludes = 1024

    public static func discover(config: URL, home: URL) -> AliasDiscovery {
        var d = Discovery(home: home)
        if statAny(config.path) != nil { d.stamp(config.path) }
        d.read(config.path, depth: 0)
        return AliasDiscovery(aliases: d.aliases, stamps: d.stamps, skippedIncludes: d.skipped)
    }

    public static func currentStamps(for stamps: [FileStamp]) -> [FileStamp] {
        self.stamps(for: stamps.map(\.path))
    }

    /// Stamps of the given paths as they are now (see `stampValue` and `FileStamp.identity`).
    public static func stamps(for paths: [String]) -> [FileStamp] {
        paths.map(stamp)
    }

    static func stamp(_ path: String) -> FileStamp {
        let (size, modified) = stampValue(path)
        return FileStamp(path: path, size: size, modified: modified, identity: identity(path))
    }

    private static func identity(_ path: String) -> [Int64] {
        func fields(_ call: (UnsafeMutablePointer<stat>) -> Int32) -> [Int64] {
            var st = stat()
            guard call(&st) == 0 else { return [-Int64(errno)] }
            return [Int64(st.st_mode), Int64(st.st_dev), Int64(bitPattern: UInt64(st.st_ino)),
                    Int64(st.st_ctimespec.tv_sec), Int64(st.st_ctimespec.tv_nsec)]
        }
        return fields { lstat(path, $0) } + fields { stat(path, $0) }
    }

    /// Size and mtime of a stamp; size -1 when the path is missing (or cannot be stat'ed), -2
    /// with the mtime when it exists but this user cannot read it. Size and mtime alone are not
    /// enough (see the security assumptions on `FileStamp.identity`).
    static func stampValue(_ path: String) -> (Int64, Date) {
        guard let (size, modified) = statAny(path) else { return (-1, .distantPast) }
        return access(path, R_OK) == 0 ? (size, modified) : (-2, modified)
    }

    /// Size and mtime of a regular file or directory (symlinks followed), else nil.
    private static func statAny(_ path: String) -> (Int64, Date)? {
        var st = stat()
        guard stat(path, &st) == 0, st.st_mode & S_IFMT == S_IFREG || st.st_mode & S_IFMT == S_IFDIR else { return nil }
        let t = st.st_mtimespec
        return (Int64(st.st_size), Date(timeIntervalSince1970: Double(t.tv_sec) + Double(t.tv_nsec) / 1e9))
    }

    private struct Discovery {
        let home: URL
        var aliases: [HostInput] = []
        var stamps: [FileStamp] = []
        var skipped: [String] = []
        private var seen: Set<HostInput> = []
        private var visited: Set<String> = []
        private var stamped: Set<String> = []
        private var listings: [String: [String]] = [:]
        private var filesRead = 0, bytesRead: Int64 = 0, includesSeen = 0
        private var limitHit = false, limitNoted = false

        init(home: URL) { self.home = home }

        /// One stamp per distinct path, even when its realpath was read already:
        /// a symlinked include that is retargeted must still be noticed.
        mutating func stamp(_ path: String) {
            guard stamped.insert(path).inserted else { return }
            stamps.append(SSHConfigAliases.stamp(path))
        }

        private mutating func noteLimit(_ arg: String) {
            limitHit = true
            if !limitNoted { limitNoted = true; skipped.append("\(arg) (limit reached)") }
        }

        mutating func read(_ path: String, depth: Int) {
            guard depth <= SSHConfigAliases.maxDepth,
                  let real = realpath(path),
                  visited.insert(real).inserted,
                  let (size, _) = SSHConfigAliases.statAny(real),
                  SSHConfigAliases.isRegularFile(real),
                  size <= SSHConfigAliases.maxFileSize
            else { return }
            // Charged before reading: a file that fails to read or decode still counts.
            guard filesRead < SSHConfigAliases.maxFiles, bytesRead + size <= SSHConfigAliases.maxBytes else {
                limitHit = true
                return
            }
            filesRead += 1
            bytesRead += size
            guard let data = FileManager.default.contents(atPath: real),
                  var text = String(data: data, encoding: .utf8)
            else { return }
            if text.unicodeScalars.first == "\u{FEFF}" { text.unicodeScalars.removeFirst() }

            var inMatch = false
            for line in text.split(whereSeparator: \.isNewline) {
                guard let (keyword, args) = Self.parse(line) else { continue }
                switch keyword {
                case "host":
                    inMatch = false
                    for a in args where !a.contains(where: { "*?".contains($0) }) && !a.hasPrefix("!") {
                        if let h = HostInput(a), seen.insert(h).inserted { aliases.append(h) }
                    }
                case "match":
                    inMatch = true
                case "include" where !inMatch:
                    for a in args { include(a, depth: depth) }
                default:
                    break
                }
            }
        }

        /// Keyword (lowercased) and arguments; nil for blank and comment lines.
        private static func parse(_ line: Substring) -> (String, [String])? {
            let l = line.drop(while: \.isWhitespace)
            guard let first = l.first, first != "#" else { return nil }
            let keyword = l.prefix { !$0.isWhitespace && $0 != "=" }
            var rest = l.dropFirst(keyword.count).drop(while: \.isWhitespace)
            if rest.first == "=" { rest = rest.dropFirst().drop(while: \.isWhitespace) }

            var args: [String] = []
            var cur = "", quoted = false, has = false, startedQuoted = false
            var comment = false
            // An unquoted token starting with # ends the arguments.
            func finish() {
                if has && !comment {
                    if !startedQuoted && cur.hasPrefix("#") { comment = true } else { args.append(cur) }
                }
                cur = ""; has = false
            }
            for c in rest {
                if c == "\"" { if !has { startedQuoted = true }; quoted.toggle(); has = true }
                else if c.isWhitespace && !quoted { finish() }
                else { if !has { startedQuoted = false }; cur.append(c); has = true }
            }
            finish()
            return (keyword.lowercased(), args)
        }

        private mutating func include(_ arg: String, depth: Int) {
            includesSeen += 1
            if limitHit || includesSeen > SSHConfigAliases.maxIncludes { noteLimit(arg); return }
            let unsupported = arg.contains { "$%[{\"\\".contains($0) } || (arg.hasPrefix("~") && !arg.hasPrefix("~/"))
            let path: String
            if arg.hasPrefix("~/") { path = home.path + "/" + arg.dropFirst(2) }
            else if arg.hasPrefix("/") { path = arg }
            else { path = home.path + "/.ssh/" + arg }
            let dir = (path as NSString).deletingLastPathComponent
            let last = (path as NSString).lastPathComponent
            let wild: (String) -> Bool = { $0.contains { "*?".contains($0) } }
            guard !unsupported, !wild(dir) else { skipped.append(arg); return }

            guard wild(last) else {
                stamp(path)
                read(path, depth: depth + 1)
                if limitHit { noteLimit(arg) }
                return
            }
            // The directory is stamped so that an added or removed entry is noticed.
            stamp(dir)
            if listings[dir] == nil {
                listings[dir] = ((try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? [])
                    .sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }
            }
            for n in listings[dir]! where fnmatch(last, n, FNM_PERIOD) == 0 {
                stamp(dir + "/" + n)
                read(dir + "/" + n, depth: depth + 1)
                if limitHit { noteLimit(arg); return }
            }
        }
    }

    private static func isRegularFile(_ path: String) -> Bool {
        var st = stat()
        return stat(path, &st) == 0 && st.st_mode & S_IFMT == S_IFREG
    }

    private static func realpath(_ path: String) -> String? {
        guard let p = Darwin.realpath(path, nil) else { return nil }
        defer { free(p) }
        return String(cString: p)
    }
}
