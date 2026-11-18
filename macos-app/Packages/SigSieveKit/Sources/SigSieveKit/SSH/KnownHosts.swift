import Foundation

public struct KnownHostEntry: Hashable, Sendable {
    /// First host pattern of the line that is not a negation (`!`); `nil` for a hashed entry or none.
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
/// tab, and no double quote) are offered. A line with a non-ASCII comment or host name is dropped
/// and not offered. A non-ASCII or control byte in an `@revoked` or `@cert-authority` line empties the
/// whole list, because that exclusion could not be applied. ssh-keygen tokenises bytes, the app must too.
///
/// Only host lines with a plain `ssh-ed25519`, `ecdsa-sha2-nistp256/384/521` or `ssh-rsa` key are
/// offered (RSA so the UI can show it disabled). Certificates, security-key and unknown types are
/// never offered, but still feed revocation.
///
/// Listed keys were found in local known_hosts files. A key on an `@revoked` or `@cert-authority`
/// line is never offered, even from an unmarked line of another host. Those marked lines come only
/// from the file and from `revocationFiles` (the App passes `/etc/ssh/ssh_known_hosts`,
/// `/etc/ssh/ssh_known_hosts2` and `~/.ssh/known_hosts2`). Custom `UserKnownHostsFile`,
/// `GlobalKnownHostsFile`, `KnownHostsCommand` and `RevokedHostKeys` settings are not read (the
/// app never runs `ssh -G`), so an empty revocation result does not mean every source was checked.
public enum KnownHosts {
    static let maxFileBytes = 4 * 1024 * 1024
    private static let offeredTypes: Set<String> = ["ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
                                                    "ecdsa-sha2-nistp521", "ssh-rsa"]

    private struct Kept {
        let name: String?
        let host: String
        let line: String
    }

    private struct Parsed {
        var plain: [(fields: [Substring], line: String)] = []
        /// `@revoked` and `@cert-authority` lines as `host type blob`, ready for ssh-keygen. Their
        /// keys are excluded, by fields here and by fingerprint in `entries`.
        var revokedLines: [(host: String, line: String)] = []
        var revokedFields = Set<String>()
    }

    /// The known_hosts lines that may be offered by text alone: no comments, no `@` marker of any
    /// kind, only byte-clean lines of an offered key type, and no key whose fields match a
    /// `@revoked` or `@cert-authority` line. One line per entry, in file order. `entries` adds revocation by fingerprint.
    public static func selectableLines(_ text: String) -> String {
        guard let parsed = parse(Data(text.utf8), offer: true) else { return "" }
        return kept(parsed).map(\.line).joined(separator: "\n")
    }

    /// Works on bytes, because ssh-keygen tokenises bytes: a line is clean only if every byte is
    /// printable ASCII, space or tab (one trailing CR is dropped). An unclean line is dropped, but
    /// one that is or hides an `@revoked` or `@cert-authority` line makes the whole file unusable
    /// (nil): its exclusion could not be applied. With `offer` false only marked lines are collected.
    private static func parse(_ data: Data, offer: Bool) -> Parsed? {
        var parsed = Parsed()
        for var raw in data.split(separator: 0x0A, omittingEmptySubsequences: true) {
            if raw.last == 0x0D { raw = raw.dropLast() }
            // '"' is unclean: ssh-keygen skips a quoted host field (it may hold spaces) while ssh
            // reads the host up to the first space, so such a line means different things to each.
            let clean = raw.allSatisfy { (($0 >= 0x20 && $0 <= 0x7E) && $0 != 0x22) || $0 == 0x09 }
            guard clean else {
                if raw.lowercasedASCIIContains("@revoked") || raw.lowercasedASCIIContains("@cert-authority") { return nil }
                continue
            }
            let line = String(decoding: raw, as: UTF8.self).trimmingCharacters(in: .whitespaces)
            guard !line.hasPrefix("#") else { continue }
            let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard let first = fields.first else { continue }
            if first.hasPrefix("@") {
                // ssh knows exactly (case-sensitively) "@revoked" and "@cert-authority", followed by
                // hosts, not by another marker; anything else is a malformed (possibly revoking) line.
                guard first == "@revoked" || first == "@cert-authority",
                      !fields.dropFirst().contains(where: { $0.hasPrefix("@") }) else { return nil }
                // Both markers exclude their key (DESIGN: a CA key is never offered either). A marked
                // line without host, type and blob cannot be applied, nor one whose all-digit host
                // ssh-keygen would skip: refuse the file.
                guard fields.count >= 4, !isNumeric(fields[1]) else { return nil }
                // Permissive on purpose: certs, sk and unknown types still exclude.
                for f in fields.dropFirst(2) where !isKeyType(f) { parsed.revokedFields.insert(String(f)) }
                parsed.revokedLines.append((String(fields[1]), fields[1...3].joined(separator: " ")))
            } else if offer, fields.count >= 3, offeredTypes.contains(String(fields[1])), fields[0] != fields[2],
                      !isNumeric(fields[0]) {
                // ssh-keygen gets exactly "host type blob" and never the raw line: it tokenises
                // differently from ssh (quoted fields, trailing comments), so what it fingerprints
                // must be built from the fields this code and ssh agree on. The type allowlist (not a
                // guess about bare keys) decides what is a host line; a line whose host is its blob is
                // a bare key; an all-digit host is skipped by ssh-keygen, which would shift the output.
                parsed.plain.append((fields, fields[0...2].joined(separator: " ")))
            }
        }
        return parsed
    }

    private static func kept(_ parsed: Parsed) -> [Kept] {
        parsed.plain.compactMap { fields, line in
            guard !fields.contains(where: { parsed.revokedFields.contains(String($0)) }) else { return nil }
            let host = fields[0]
            // The label is the first pattern that is not a negation; none (or hashed) means nil.
            let name = host.hasPrefix("|1|") ? nil
                : host.split(separator: ",").first { !$0.hasPrefix("!") }.map(String.init)
            return Kept(name: name, host: String(host), line: line)
        }
    }

    private static func isNumeric(_ f: Substring) -> Bool {
        let digits = f.hasPrefix("+") || f.hasPrefix("-") ? f.dropFirst() : f
        return !digits.isEmpty && digits.utf8.allSatisfy { $0 >= 0x30 && $0 <= 0x39 }
    }

    private static func isKeyType(_ f: Substring) -> Bool {
        ["ssh-", "ecdsa-", "sk-", "rsa-"].contains { f.lowercased().hasPrefix($0) }
    }

    /// `revocationFiles` contribute only their `@revoked` and `@cert-authority` lines. A missing one is skipped; one that
    /// exists but cannot be read safely, or holds an unusable `@revoked` line, gives [].
    public static func entries(file: URL, revocationFiles: [URL] = [], runner: Running,
                               environment: ChildEnvironment) async -> [KnownHostEntry] {
        guard let data = read(file), var parsed = parse(data, offer: true) else { return [] }
        for extra in revocationFiles {
            var st = stat()
            if lstat(extra.path, &st) != 0, errno == ENOENT { continue }
            guard let d = read(extra), let p = parse(d, offer: false) else { return [] }
            parsed.revokedLines += p.revokedLines
            parsed.revokedFields.formUnion(p.revokedFields)
        }
        let kept = kept(parsed)
        guard !kept.isEmpty else { return [] }
        // Revocation by meaning: the revoked keys are fingerprinted the same way, so any spelling
        // ssh-keygen accepts for a key is caught. A failed or short run loses revocations: fail closed.
        var revokedFingerprints = Set<Fingerprint>()
        if !parsed.revokedLines.isEmpty {
            guard let found = await fingerprints(parsed.revokedLines.map { ($0.host, $0.line) }, runner, environment) else { return [] }
            revokedFingerprints = Set(found.map(\.0))
        }
        guard let found = await fingerprints(kept.map { ($0.host, $0.line) }, runner, environment) else { return [] }
        var seen = Set<Fingerprint>()
        var entries: [KnownHostEntry] = []
        for ((fingerprint, type), item) in zip(found, kept) {
            guard !type.hasSuffix("-CERT"), !revokedFingerprints.contains(fingerprint),
                  seen.insert(fingerprint).inserted else { continue }
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
