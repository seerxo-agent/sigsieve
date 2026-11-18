public enum ForwardedKeyRow: Hashable, Identifiable, Sendable {
    case inAgent(AgentKey)
    case notInAgent(Fingerprint)

    public var id: Fingerprint {
        switch self {
        case .inAgent(let key): key.fingerprint
        case .notInAgent(let fingerprint): fingerprint
        }
    }
}

/// Display and Save helpers only. A key missing from the agent is never usable here, and
/// nothing is compared but the SHA256 fingerprint: comments and types are ignored.
public enum ForwardedKeys {
    /// One row per forwarded fingerprint, in profile order; matched to agent keys by fingerprint only.
    public static func rows(forwarded: [Fingerprint], agentKeys: [AgentKey]) -> [ForwardedKeyRow] {
        let byFingerprint = index(agentKeys)
        return forwarded.map { f in byFingerprint[f].map(ForwardedKeyRow.inAgent) ?? .notInAgent(f) }
    }

    /// The new forwardedKeys after a sheet's Save: kept keys in their current order, then
    /// newly selected agent keys in agent order. Fingerprints not in the agent are kept iff selected.
    public static func applying(selection: Set<Fingerprint>, to current: [Fingerprint], agentKeys: [AgentKey]) -> [Fingerprint] {
        let kept = current.filter(selection.contains)
        var seen = Set(current)
        let added = agentKeys.map(\.fingerprint).filter { selection.contains($0) && seen.insert($0).inserted }
        return kept + added
    }

    /// The forwarded fingerprints the agent currently holds. AppModel compares this set at check
    /// time and after each agent refresh; any difference clears the check.
    public static func present(forwarded: [Fingerprint], agentKeys: [AgentKey]) -> Set<Fingerprint> {
        Set(forwarded).intersection(agentKeys.map(\.fingerprint))
    }

    private static func index(_ keys: [AgentKey]) -> [Fingerprint: AgentKey] {
        Dictionary(keys.map { ($0.fingerprint, $0) }, uniquingKeysWith: { first, _ in first })
    }
}
