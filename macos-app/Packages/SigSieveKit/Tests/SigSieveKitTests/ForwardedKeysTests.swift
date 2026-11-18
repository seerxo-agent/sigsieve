import Testing
@testable import SigSieveKit

private func fp(_ c: Character) -> Fingerprint { Fingerprint("SHA256:" + String(repeating: c, count: 43))! }
private let f1 = fp("A"), f2 = fp("E"), f3 = fp("I"), f9 = fp("U")
private func key(_ f: Fingerprint, _ comment: String) -> AgentKey {
    AgentKey(fingerprint: f, bits: 256, type: "ED25519", comment: comment)
}
private let k1 = key(f1, "Development Key"), k2 = key(f2, "Two"), k3 = key(f3, "Development Key")

@Test func matchesByFingerprintOnly() {
    #expect(ForwardedKeys.rows(forwarded: [f1, f2], agentKeys: [k1, k3]) == [.inAgent(k1), .notInAgent(f2)])
}

@Test func reappearingKeyUsesAgentData() {
    #expect(ForwardedKeys.rows(forwarded: [f1], agentKeys: []) == [.notInAgent(f1)])
    let renamed = key(f1, "renamed")
    #expect(ForwardedKeys.rows(forwarded: [f1], agentKeys: [renamed]) == [.inAgent(renamed)])
}

@Test func allMissingWhenAgentEmpty() {
    #expect(ForwardedKeys.rows(forwarded: [f1, f2], agentKeys: []) == [.notInAgent(f1), .notInAgent(f2)])
}

@Test func unchangedSelectionIsIdentical() {
    #expect(ForwardedKeys.applying(selection: [f1, f2], to: [f2, f1], agentKeys: [k1, k2]) == [f2, f1])
}

@Test func newKeysAppendInAgentOrder() {
    #expect(ForwardedKeys.applying(selection: [f3, f2, f1], to: [f2], agentKeys: [k1, k2, k3]) == [f2, f1, f3])
}

@Test func deselectedRemoved() {
    #expect(ForwardedKeys.applying(selection: [f2], to: [f1, f2], agentKeys: [k1, k2]) == [f2])
}

@Test func missingKeyKeptOnlyIfSelected() {
    #expect(ForwardedKeys.applying(selection: [f9], to: [f9], agentKeys: [k1]) == [f9])
    #expect(ForwardedKeys.applying(selection: [], to: [f9], agentKeys: [k1]) == [])
}

@Test func openAndSaveKeepsMissingKeys() {
    let current = [f1, f9]
    #expect(ForwardedKeys.applying(selection: Set(current), to: current, agentKeys: [k1]) == [f1, f9])
}

@Test func presentIsIntersectionByFingerprint() {
    #expect(ForwardedKeys.present(forwarded: [f1, f2], agentKeys: [k1, k3]) == [f1])
    #expect(ForwardedKeys.present(forwarded: [f1, f2], agentKeys: []) == [])
    // K3 shares K1's comment but is a different key: with K1 gone, F1 stays absent.
    #expect(ForwardedKeys.present(forwarded: [f1], agentKeys: [k3]) == [])
}

@Test func selectionOfUnknownFingerprintIgnored() {
    #expect(ForwardedKeys.applying(selection: [f9], to: [], agentKeys: [k1]) == [])
}
