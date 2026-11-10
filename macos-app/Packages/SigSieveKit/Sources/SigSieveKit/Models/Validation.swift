import Foundation

// Checks run on Unicode scalars, not NSRegularExpression: there `$` also
// matches before a final newline, which would let "SHA256:<43>\n" through.

/// An OpenSSH SHA-256 key fingerprint: `SHA256:` plus 43 unpadded base64 characters.
public struct Fingerprint: Hashable, Sendable {
    public let value: String

    public init?(_ s: String) {
        let prefix = "SHA256:".unicodeScalars
        guard s.unicodeScalars.starts(with: prefix) else { return nil }
        let body = s.unicodeScalars.dropFirst(prefix.count)
        guard body.count == 43, body.allSatisfy(Self.isBase64) else { return nil }
        value = s
    }

    /// `SHA256:` plus the first 8 characters of the hash and `…`.
    public var short: String { String(value.prefix(7 + 8)) + "…" }

    private static func isBase64(_ c: Unicode.Scalar) -> Bool {
        switch c {
        case "A"..."Z", "a"..."z", "0"..."9", "+", "/": true
        default: false
        }
    }
}

/// A server as the user typed it: what `sigsieve connect` receives as its destination.
public struct HostInput: Hashable, Sendable {
    public let value: String

    public init?(_ s: String) {
        guard let first = s.unicodeScalars.first, first != "-" else { return nil }
        // Format characters (bidi overrides, zero-width, BOM) are invisible, so
        // the host shown in the UI could differ from the bytes sent to the CLI.
        guard !s.unicodeScalars.contains(where: {
            $0.properties.isWhitespace
                || $0.properties.generalCategory == .control
                || $0.properties.generalCategory == .format
        }) else { return nil }
        value = s
    }

    // Byte equality, not String's canonical equivalence: "h\u{E9}" and
    // "he\u{301}" are different destinations to the CLI and must not share a profile.
    public static func == (a: HostInput, b: HostInput) -> Bool { a.value.utf8.elementsEqual(b.value.utf8) }
    public func hash(into h: inout Hasher) {
        h.combine(value.utf8.count)
        for b in value.utf8 { h.combine(b) }
    }
}

// Both encode as a plain string, and decoding re-validates, so a stored file
// can never yield a value the initializer would refuse.

extension Fingerprint: Codable {
    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        let s = try c.decode(String.self)
        guard let v = Fingerprint(s) else {
            throw DecodingError.dataCorruptedError(in: c, debugDescription: "invalid fingerprint")
        }
        self = v
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(value)
    }
}

extension HostInput: Codable {
    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        let s = try c.decode(String.self)
        guard let v = HostInput(s) else {
            throw DecodingError.dataCorruptedError(in: c, debugDescription: "invalid host")
        }
        self = v
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(value)
    }
}
