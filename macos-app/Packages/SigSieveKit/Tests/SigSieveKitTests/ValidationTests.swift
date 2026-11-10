import Foundation
import Testing
@testable import SigSieveKit

@Test func fingerprintAcceptsExactly43Base64Characters() {
    #expect(Fingerprint("SHA256:" + String(repeating: "A", count: 43)) != nil)
    #expect(Fingerprint("SHA256:" + String(repeating: "A", count: 42)) == nil)
    #expect(Fingerprint("SHA256:" + String(repeating: "A", count: 44)) == nil)
    #expect(Fingerprint("MD5:" + String(repeating: "A", count: 43)) == nil)
    #expect(Fingerprint("SHA256:" + String(repeating: "A", count: 42) + "'") == nil)
    #expect(Fingerprint("SHA256:" + String(repeating: "A", count: 43) + "\n") == nil)
}

@Test func fingerprintAcceptsTheWholeBase64Alphabet() {
    let body = "abcXYZ019+/" + String(repeating: "Q", count: 32)
    #expect(Fingerprint("SHA256:" + body)?.value == "SHA256:" + body)
    #expect(Fingerprint("SHA256:" + String(repeating: "A", count: 42) + "=") == nil)
    #expect(Fingerprint("SHA256:" + String(repeating: "A", count: 42) + "é") == nil)
    #expect(Fingerprint("sha256:" + String(repeating: "A", count: 43)) == nil)
    #expect(Fingerprint(" SHA256:" + String(repeating: "A", count: 43)) == nil)
}

@Test func fingerprintShortForm() {
    let fp = Fingerprint("SHA256:abcdefgh" + String(repeating: "Z", count: 34) + "w")!
    #expect(fp.short == "SHA256:abcdefgh…")
}

@Test(arguments: ["", "-oProxyCommand=x", "a b", "a\tb", "a\nb", "a\u{0}b", "a\u{7f}"])
func hostInputRejects(_ s: String) { #expect(HostInput(s) == nil) }

@Test(arguments: ["a\u{85}b", "a\u{a0}b", "a\u{2028}b", "a\u{3000}b", "a\r", "-"])
func hostInputRejectsUnicodeWhitespaceAndControls(_ s: String) { #expect(HostInput(s) == nil) }

@Test(arguments: ["build-host", "deploy@10.0.0.5", "user@host.example", "[::1]"])
func hostInputAccepts(_ s: String) { #expect(HostInput(s)?.value == s) }

@Test func codableIsAPlainStringAndDecodingRevalidates() throws {
    let fp = Fingerprint("SHA256:" + String(repeating: "A", count: 43))!
    let data = try JSONEncoder().encode([fp])
    #expect(String(decoding: data, as: UTF8.self) == "[\"\(fp.value)\"]")
    #expect(try JSONDecoder().decode([Fingerprint].self, from: data) == [fp])
    #expect(throws: DecodingError.self) { try JSONDecoder().decode([Fingerprint].self, from: Data("[\"SHA256:x\"]".utf8)) }

    let host = HostInput("build-host")!
    #expect(try JSONDecoder().decode([HostInput].self, from: JSONEncoder().encode([host])) == [host])
    #expect(throws: DecodingError.self) { try JSONDecoder().decode([HostInput].self, from: Data("[\"-oX\"]".utf8)) }
    #expect(throws: DecodingError.self) { try JSONDecoder().decode([HostInput].self, from: Data("[\"a b\"]".utf8)) }
}

// Review regressions: the first scalar decides "leading -", and CRLF is one
// Character in Swift but two scalars here.
@Test(arguments: ["-\u{301}oProxyCommand=x", "a\r\nb"])
func hostInputChecksScalarsNotCharacters(_ s: String) { #expect(HostInput(s) == nil) }

// Invisible format characters would let the UI show something other than
// what the CLI receives ("\u{FEFF}-oX" displays as "-oX").
@Test(arguments: ["a\u{202E}b", "\u{FEFF}-oX", "a\u{200B}b", "a\u{AD}b", "a\u{2066}b"])
func hostInputRejectsFormatCharacters(_ s: String) { #expect(HostInput(s) == nil) }

@Test func canonicallyEquivalentHostsAreDifferentHosts() {
    let composed = HostInput("h\u{E9}")!, decomposed = HostInput("he\u{301}")!
    #expect(composed != decomposed)
    #expect(Set([composed, decomposed]).count == 2)
    #expect(HostInput("build-host") == HostInput("build-host"))
}

@Test func fingerprintRejectsCombiningMarks() {
    #expect(Fingerprint("SHA256:\u{301}" + String(repeating: "A", count: 43)) == nil)
    #expect(Fingerprint("SHA256:" + String(repeating: "A", count: 43) + "\u{301}") == nil)
}

// Same strictness as the CLI: the last of 43 characters must leave the 2 spare
// bits zero, so only 16 characters are allowed there.
@Test func fingerprintLastCharacterMatchesTheCLI() {
    let allowed = Set("AEIMQUYcgkosw048")
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    for c in alphabet {
        let fp = Fingerprint("SHA256:" + String(repeating: "A", count: 42) + String(c))
        #expect((fp != nil) == allowed.contains(c), "last character \(c)")
    }
}

@Test(arguments: ["B", "Z", "z", "/", "+", "1"])
func fingerprintRejectsNonzeroSpareBits(_ last: String) {
    #expect(Fingerprint("SHA256:" + String(repeating: "A", count: 42) + last) == nil)
}

// SHA-256 of empty input, base64 without padding: a real 256-bit hash.
@Test func fingerprintAcceptsARealOpenSSHValue() {
    #expect(Fingerprint("SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU") != nil)
}
