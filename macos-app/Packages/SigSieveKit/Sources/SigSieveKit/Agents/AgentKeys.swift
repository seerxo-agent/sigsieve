import Foundation

public struct AgentKey: Hashable, Identifiable, Sendable {
    public let fingerprint: Fingerprint
    public let bits: Int
    public let type: String
    public let comment: String
    /// The fingerprint, not the comment: comments may be empty or repeat.
    public var id: Fingerprint { fingerprint }

    public init(fingerprint: Fingerprint, bits: Int, type: String, comment: String) {
        self.fingerprint = fingerprint
        self.bits = bits
        self.type = type
        self.comment = comment
    }
}

public enum AgentState: Equatable, Sendable {
    case keys([AgentKey])
    /// The agent answered and holds no keys.
    case empty
    /// The agent could not be asked; the text says why.
    case unreachable(String)
}

public enum AgentKeys {
    /// Parses `ssh-add -l -E sha256` output: `<bits> SHA256:<43> <comment> (<TYPE>)` per line.
    /// Bits and fingerprint come from the left, the type from the right; what remains is the
    /// comment. Malformed lines are skipped; a repeated fingerprint keeps its first line.
    public static func parse(_ output: String) -> [AgentKey] {
        var seen = Set<Fingerprint>()
        var keys: [AgentKey] = []
        // Only "\n" separates lines (and a trailing "\r" is dropped), so U+2028, U+2029 and NEL
        // inside a comment stay in the comment. Split on the scalar: "\r\n" is one Character.
        for raw in output.unicodeScalars.split(separator: "\n", omittingEmptySubsequences: true) {
            var line = Substring(String(String.UnicodeScalarView(raw)))
            if line.unicodeScalars.last == "\r" { line = line.dropLast() }
            guard let key = parseLine(line), seen.insert(key.fingerprint).inserted else { continue }
            keys.append(key)
        }
        return keys
    }

    private static func parseLine(_ line: Substring) -> AgentKey? {
        let parts = line.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count == 3, let bits = Int(parts[0]), bits > 0,
              let fingerprint = Fingerprint(String(parts[1])) else { return nil }
        // "<comment> (<TYPE>)": the last " (" starts the type, so the comment may hold parentheses.
        let rest = parts[2]
        guard rest.hasSuffix(")"), let open = rest.range(of: " (", options: .backwards) else { return nil }
        let type = rest[open.upperBound...].dropLast()
        guard !type.isEmpty, type.unicodeScalars.allSatisfy({ ("A"..."Z").contains($0) || ("0"..."9").contains($0) || $0 == "-" })
        else { return nil }
        return AgentKey(fingerprint: fingerprint, bits: bits, type: String(type), comment: String(rest[..<open.lowerBound]))
    }

    public static func list(runner: Running, environment: ChildEnvironment) async -> AgentState {
        let result: RunResult
        do {
            result = try await runner.run(.sshAdd, ["-l", "-E", "sha256"], environment: environment,
                                          stdin: nil, timeout: .seconds(10))
        } catch {
            switch error as? RunError {
            case .timedOut?: return .unreachable("ssh-add did not answer within 10 seconds")
            case .cannotStart(let reason)?: return .unreachable("ssh-add could not start: \(reason)")
            case .notAllowed?: return .unreachable("ssh-add was not allowed to run")
            case nil: return .unreachable("ssh-add failed: \(error.localizedDescription)")
            }
        }
        switch result.exitCode {
        case 0:
            let keys = parse(result.stdout)
            return keys.isEmpty ? .empty : .keys(keys)
        case 1:
            return .empty
        default:
            let reason = result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            return .unreachable(reason.isEmpty ? "ssh-add exited with code \(result.exitCode)" : reason)
        }
    }
}

public enum KeyFilter {
    /// Case-insensitive substring over comment, type and fingerprint; an empty query keeps all.
    public static func filter(_ keys: [AgentKey], query: String) -> [AgentKey] {
        guard !query.isEmpty else { return keys }
        // Stdlib String comparison is canonically equivalent (NFC == NFD) and does not fold
        // diacritics; lowercasing both sides gives case-insensitivity without NSString bridging.
        let q = query.lowercased()
        return keys.filter {
            $0.comment.lowercased().contains(q) || $0.type.lowercased().contains(q)
                || $0.fingerprint.value.lowercased().contains(q)
        }
    }
}
