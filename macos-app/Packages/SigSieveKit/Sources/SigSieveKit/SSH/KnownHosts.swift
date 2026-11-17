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

/// Compatibility impact of the ASCII-only rule: only lines made of printable ASCII (plus space and
/// tab) are offered. A line with a non-ASCII comment or host name is dropped and not offered. A
/// non-ASCII or control byte in an `@revoked` line empties the whole list, because that revocation
/// could not be applied. ssh-keygen tokenises bytes, the app must too.
public enum KnownHosts {
    static let maxFileBytes = 4 * 1024 * 1024

    private struct Kept {
        let name: String?
        let host: String
        let line: String
    }

    private struct Parsed {
        var kept: [Kept]
        /// Revoked lines without their marker, ready for ssh-keygen.
        var revokedLines: [(host: String, line: String)]
    }

    /// The known_hosts lines that may be offered by text alone: no comments, no `@` marker of any
    /// kind, only byte-clean lines, and no key whose fields match a `@revoked` line. One line per
    /// entry, in file order. `entries` adds revocation by fingerprint on top of this.
    public static func selectableLines(_ text: String) -> String {
        (parse(Data(text.utf8))?.kept ?? []).map(\.line).joined(separator: "\n")
    }

    /// Works on bytes, because ssh-keygen tokenises bytes: a line is clean only if every byte is
    /// printable ASCII, space or tab (one trailing CR is dropped). An unclean line is dropped, but
    /// one that is or hides an `@revoked` line makes the whole file unusable (nil): its revocation
    /// could not be applied.
    private static func parse(_ data: Data) -> Parsed? {
        var parsed = Parsed(kept: [], revokedLines: [])
        var revoked = Set<String>()
        var plain: [(fields: [Substring], line: String)] = []
        for var raw in data.split(separator: 0x0A, omittingEmptySubsequences: true) {
            if raw.last == 0x0D { raw = raw.dropLast() }
            let clean = raw.allSatisfy { ($0 >= 0x20 && $0 <= 0x7E) || $0 == 0x09 }
            guard clean else {
                if raw.lowercasedASCIIContains("@revoked") { return nil }
                continue
            }
            let line = String(decoding: raw, as: UTF8.self).trimmingCharacters(in: .whitespaces)
            guard !line.hasPrefix("#") else { continue }
            let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard let first = fields.first else { continue }
            if first.hasPrefix("@") {
                // "@revoked <hosts> <type> <blob>"; every non-type field after the hosts counts, so a
                // malformed revoked line errs towards revoking more.
                if first.lowercased() == "@revoked" {
                    for f in fields.dropFirst(2) where !isKeyType(f) { revoked.insert(String(f)) }
                    if fields.count >= 2 { parsed.revokedLines.append((String(fields[1]), fields.dropFirst().joined(separator: " "))) }
                }
            } else if fields.count >= 3, !isKeyType(first) {
                // A line starting with a key type is a bare key, not a host line; ssh-keygen would
                // fingerprint it whatever follows, so it is never offered.
                plain.append((fields, line))
            }
        }
        parsed.kept = plain.compactMap { fields, line in
            guard !fields.contains(where: { revoked.contains(String($0)) }) else { return nil }
            let host = fields[0]
            // ponytail: name is the first pattern of the input line (output order is checked in entries).
            let name = host.hasPrefix("|1|") ? nil : String(host.split(separator: ",", omittingEmptySubsequences: false)[0])
            return Kept(name: name, host: String(host), line: line)
        }
        return parsed
    }

    private static func isKeyType(_ f: Substring) -> Bool {
        ["ssh-", "ecdsa-", "sk-", "rsa-"].contains { f.lowercased().hasPrefix($0) }
    }

    public static func entries(file: URL, runner: Running, environment: ChildEnvironment) async -> [KnownHostEntry] {
        guard let data = read(file), let parsed = parse(data), !parsed.kept.isEmpty else { return [] }
        // Revocation by meaning: the revoked keys are fingerprinted the same way, so any spelling
        // ssh-keygen accepts for a key is caught. A failed or short run loses revocations: fail closed.
        var revokedFingerprints = Set<Fingerprint>()
        if !parsed.revokedLines.isEmpty {
            guard let found = await fingerprints(parsed.revokedLines.map { ($0.host, $0.line) }, runner, environment) else { return [] }
            revokedFingerprints = Set(found.map(\.0))
        }
        guard let found = await fingerprints(parsed.kept.map { ($0.host, $0.line) }, runner, environment) else { return [] }
        var seen = Set<Fingerprint>()
        var entries: [KnownHostEntry] = []
        for ((fingerprint, type), item) in zip(found, parsed.kept) {
            guard !revokedFingerprints.contains(fingerprint), seen.insert(fingerprint).inserted else { continue }
            entries.append(KnownHostEntry(name: item.name, fingerprint: fingerprint, type: type))
        }
        return entries
    }

    /// Runs `ssh-keygen -l -E sha256 -f -` over the lines and returns one result per line, by
    /// order. nil (fail closed) on a failed run, a count that differs from the input, an
    /// unparseable output line, or an output line whose echoed host field is not the host field
    /// of the input line at that position (a skipped line would otherwise shift every later one).
    private static func fingerprints(_ items: [(host: String, line: String)], _ runner: Running,
                                     _ environment: ChildEnvironment) async -> [(Fingerprint, String)]? {
        guard let result = try? await runner.run(.sshKeygen, ["-l", "-E", "sha256", "-f", "-"], environment: environment,
                                                 stdin: Data(items.map(\.line).joined(separator: "\n").utf8),
                                                 timeout: .seconds(10)),
              result.exitCode == 0 else { return nil }
        let lines = result.stdout.unicodeScalars.split(separator: "\n", omittingEmptySubsequences: true)
            .map { String(String.UnicodeScalarView($0)) }
        guard lines.count == items.count else { return nil }
        var found: [(Fingerprint, String)] = []
        for (line, item) in zip(lines, items) {
            guard let (fingerprint, type, comment) = parseOutput(line), comment == item.host else { return nil }
            found.append((fingerprint, type))
        }
        return found
    }

    /// One read path: a symlink is resolved first (a symlinked known_hosts is supported), then the
    /// path is opened without following links or blocking, and the descriptor itself must be a
    /// regular file of at most 4 MB. At most 4 MB + 1 bytes are read; more means "no entries".
    private static func read(_ file: URL) -> Data? {
        guard let r = realpath(file.path, nil) else { return nil }
        defer { free(r) }
        // A device node or FIFO is never opened.
        var pre = stat()
        guard stat(r, &pre) == 0, pre.st_mode & S_IFMT == S_IFREG else { return nil }
        let fd = open(r, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var st = stat()
        guard fstat(fd, &st) == 0, st.st_mode & S_IFMT == S_IFREG, st.st_size <= maxFileBytes,
              let data = try? handle.read(upToCount: maxFileBytes + 1), data.count <= maxFileBytes else { return nil }
        return data
    }

    /// `<bits> SHA256:<43> <host field> (<TYPE>)`; returns fingerprint, type and host field.
    private static func parseOutput(_ raw: String) -> (Fingerprint, String, String)? {
        var line = Substring(raw)
        if line.unicodeScalars.last == "\r" { line = line.dropLast() }
        let parts = line.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count == 3, let bits = Int(parts[0]), bits > 0, let fingerprint = Fingerprint(String(parts[1])) else { return nil }
        let rest = parts[2]
        guard rest.hasSuffix(")"), let open = rest.range(of: " (", options: .backwards) else { return nil }
        let type = rest[open.upperBound...].dropLast()
        guard !type.isEmpty, type.unicodeScalars.allSatisfy({ ("A"..."Z").contains($0) || ("0"..."9").contains($0) || $0 == "-" })
        else { return nil }
        return (fingerprint, String(type), String(rest[..<open.lowerBound]))
    }
}

private extension Data.SubSequence {
    func lowercasedASCIIContains(_ needle: String) -> Bool {
        String(decoding: map { $0 >= 0x41 && $0 <= 0x5A ? $0 + 32 : $0 }, as: UTF8.self).contains(needle)
    }
}
