import Foundation

public struct KnownHostEntry: Hashable, Sendable {
    /// First host pattern of the line; `nil` for a hashed entry.
    public let name: String?
    public let fingerprint: Fingerprint
    /// The OpenSSH key type as `ssh-keygen` prints it (`ED25519`, `RSA`, ...), so the UI can disable RSA.
    public let type: String

    public init(name: String?, fingerprint: Fingerprint, type: String) {
        self.name = name
        self.fingerprint = fingerprint
        self.type = type
    }
}

public enum KnownHosts {
    static let maxFileBytes = 4 * 1024 * 1024

    private struct Kept {
        let name: String?
        let line: String
    }

    /// The known_hosts lines that may be offered: no comments, no `@` marker of any kind,
    /// and no key whose blob appears in any `@revoked` line. One line per entry, in file order.
    public static func selectableLines(_ text: String) -> String {
        kept(text).map(\.line).joined(separator: "\n")
    }

    private static func kept(_ text: String) -> [Kept] {
        // Only "\n" separates lines (as in AgentKeys.parse); a trailing "\r" is whitespace.
        let lines = text.unicodeScalars.split(separator: "\n", omittingEmptySubsequences: true).map {
            String(String.UnicodeScalarView($0)).trimmingCharacters(in: .whitespaces.union(.init(charactersIn: "\r")))
        }
        var revoked = Set<String>()
        var plain: [(fields: [Substring], line: String)] = []
        for line in lines where !line.hasPrefix("#") {
            let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard let first = fields.first else { continue }
            if first.hasPrefix("@") {
                // "@revoked <hosts> <type> <blob>"; every non-type field after the hosts counts, so a
                // malformed revoked line errs towards revoking more.
                if first.lowercased() == "@revoked" {
                    for f in fields.dropFirst(2) where !isKeyType(f) { revoked.insert(String(f)) }
                }
            } else if fields.count >= 3, !isKeyType(first) {
                // A line starting with a key type is a bare key, not a host line; ssh-keygen would
                // fingerprint it whatever follows, so it is never offered.
                plain.append((fields, line))
            }
        }
        return plain.compactMap { fields, line in
            guard !fields.contains(where: { revoked.contains(String($0)) }) else { return nil }
            let host = fields[0]
            // ponytail: name is the first pattern of the input line (output order is checked in entries).
            let name = host.hasPrefix("|1|") ? nil : String(host.split(separator: ",", omittingEmptySubsequences: false)[0])
            return Kept(name: name, line: line)
        }
    }

    private static func isKeyType(_ f: Substring) -> Bool {
        ["ssh-", "ecdsa-", "sk-", "rsa-"].contains { f.lowercased().hasPrefix($0) }
    }

    public static func entries(file: URL, runner: Running, environment: ChildEnvironment) async -> [KnownHostEntry] {
        guard let text = read(file) else { return [] }
        let kept = kept(text)
        guard !kept.isEmpty else { return [] }
        let stdin = Data(kept.map(\.line).joined(separator: "\n").utf8)
        let result: RunResult
        do {
            result = try await runner.run(.sshKeygen, ["-l", "-E", "sha256", "-f", "-"], environment: environment,
                                          stdin: stdin, timeout: .seconds(10))
        } catch {
            return []
        }
        guard result.exitCode == 0 else { return [] }
        let outLines = result.stdout.unicodeScalars.split(separator: "\n", omittingEmptySubsequences: true)
            .map { String(String.UnicodeScalarView($0)) }
        // One output line per kept input line, by order. ssh-keygen skips lines it cannot
        // parse, which would shift every later name: fail closed rather than misattribute.
        guard outLines.count == kept.count else { return [] }
        var seen = Set<Fingerprint>()
        var entries: [KnownHostEntry] = []
        for (line, item) in zip(outLines, kept) {
            guard let (fingerprint, type) = parseOutput(line), seen.insert(fingerprint).inserted else { continue }
            entries.append(KnownHostEntry(name: item.name, fingerprint: fingerprint, type: type))
        }
        return entries
    }

    /// One read path: a symlink is resolved first (a symlinked known_hosts is supported), then the
    /// path is opened without following links or blocking, and the descriptor itself must be a
    /// regular file of at most 4 MB. At most 4 MB + 1 bytes are read; more means "no entries".
    private static func read(_ file: URL) -> String? {
        guard let r = realpath(file.path, nil) else { return nil }
        defer { free(r) }
        let fd = open(r, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var st = stat()
        guard fstat(fd, &st) == 0, st.st_mode & S_IFMT == S_IFREG, st.st_size <= maxFileBytes,
              let data = try? handle.read(upToCount: maxFileBytes + 1), data.count <= maxFileBytes else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    /// `<bits> SHA256:<43> <host field> (<TYPE>)`; the host field is not used.
    private static func parseOutput(_ raw: String) -> (Fingerprint, String)? {
        var line = Substring(raw)
        if line.unicodeScalars.last == "\r" { line = line.dropLast() }
        let parts = line.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count == 3, let bits = Int(parts[0]), bits > 0, let fingerprint = Fingerprint(String(parts[1])) else { return nil }
        let rest = parts[2]
        guard rest.hasSuffix(")"), let open = rest.range(of: " (", options: .backwards) else { return nil }
        let type = rest[open.upperBound...].dropLast()
        guard !type.isEmpty, type.unicodeScalars.allSatisfy({ ("A"..."Z").contains($0) || ("0"..."9").contains($0) || $0 == "-" })
        else { return nil }
        return (fingerprint, String(type))
    }
}
