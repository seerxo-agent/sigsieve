import Foundation

/// A file that was read, as it looked then. Size -1 means it could not be stat'ed.
public struct FileStamp: Hashable, Sendable {
    public let path: String
    public let size: Int64
    public let modified: Date
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

    public static func discover(config: URL, home: URL) -> AliasDiscovery {
        var d = Discovery(home: home)
        d.read(config.path, depth: 0)
        return AliasDiscovery(aliases: d.aliases, stamps: d.stamps, skippedIncludes: d.skipped)
    }

    public static func currentStamps(for stamps: [FileStamp]) -> [FileStamp] {
        stamps.map { s in
            guard let (size, modified) = statFile(s.path) else {
                return FileStamp(path: s.path, size: -1, modified: .distantPast)
            }
            return FileStamp(path: s.path, size: size, modified: modified)
        }
    }

    /// Size and mtime of a regular file (symlinks followed), else nil.
    private static func statFile(_ path: String) -> (Int64, Date)? {
        var st = stat()
        guard stat(path, &st) == 0, st.st_mode & S_IFMT == S_IFREG else { return nil }
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

        init(home: URL) { self.home = home }

        mutating func read(_ path: String, depth: Int) {
            guard depth <= SSHConfigAliases.maxDepth,
                  let real = realpath(path),
                  visited.insert(real).inserted,
                  let (size, modified) = SSHConfigAliases.statFile(real),
                  size <= SSHConfigAliases.maxFileSize,
                  let data = FileManager.default.contents(atPath: real),
                  let text = String(data: data, encoding: .utf8)
            else { return }
            stamps.append(FileStamp(path: path, size: size, modified: modified))

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
            var cur = "", quoted = false, has = false
            for c in rest {
                if c == "\"" { quoted.toggle(); has = true }
                else if c.isWhitespace && !quoted {
                    if has { args.append(cur) }
                    cur = ""; has = false
                } else { cur.append(c); has = true }
            }
            if has { args.append(cur) }
            return (keyword.lowercased(), args)
        }

        private mutating func include(_ arg: String, depth: Int) {
            let unsupported = arg.contains { "$%[{\"\\".contains($0) } || (arg.hasPrefix("~") && !arg.hasPrefix("~/"))
            let path: String
            if arg.hasPrefix("~/") { path = home.path + "/" + arg.dropFirst(2) }
            else if arg.hasPrefix("/") { path = arg }
            else { path = home.path + "/.ssh/" + arg }
            let dir = (path as NSString).deletingLastPathComponent
            let last = (path as NSString).lastPathComponent
            let wild: (String) -> Bool = { $0.contains { "*?".contains($0) } }
            guard !unsupported, !wild(dir) else { skipped.append(arg); return }

            guard wild(last) else { read(path, depth: depth + 1); return }
            let names = ((try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? [])
                .filter { fnmatch(last, $0, FNM_PERIOD) == 0 }
                .sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }
            for n in names { read(dir + "/" + n, depth: depth + 1) }
        }
    }

    private static func realpath(_ path: String) -> String? {
        guard let p = Darwin.realpath(path, nil) else { return nil }
        defer { free(p) }
        return String(cString: p)
    }
}
