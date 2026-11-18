import SigSieveKit
import SwiftUI

/// Status strings shared by the main window, the menu bar panel and Settings.
@MainActor
enum StatusText {
    /// The agent name and its state, as one line.
    static func agentSummary(_ model: AppModel) -> String {
        if case .unreachable = model.agentState { return agentState(model) }
        return "\(model.agentName) \(agentState(model))"
    }

    /// "· N keys", "· no keys", or why the agent is not reachable.
    static func agentState(_ model: AppModel) -> String {
        switch model.agentState {
        case .keys(let k): "· \(k.count) key\(k.count == 1 ? "" : "s")"
        case .empty: "· no keys"
        case .unreachable(let why): "Agent not reachable: \(why)"
        }
    }

    static func blockingErrors(_ model: AppModel) -> [String] {
        var errors: [String] = []
        if let p = model.cliSettingProblem { errors.append(p) }
        if case .failure(let e) = model.cli { errors.append(describe(e)) }
        if case .failure(let e) = model.tmpdir { errors.append("Blocked: \(e.description). There is no fallback to /tmp.") }
        if let e = model.storeError {
            errors.append("Profiles file \(model.store.file.path): \(describe(e)). Editing is disabled.")
        }
        return errors
    }

    static func describe(_ e: CLIError) -> String {
        switch e {
        // Only when the lookup ended with an error other than CLIError, such as a cancelled
        // `--version` run (AppModel.locateCLI): no list of searched locations exists then.
        case .notFound(let searched) where searched.isEmpty:
            "SigSieve CLI lookup was interrupted before it finished."
        case .notFound(let searched) where searched.count == 1:
            "The CLI path set in Settings does not exist: \(searched[0])"
        case .notFound(let searched):
            "SigSieve CLI not found. Searched: \(searched.joined(separator: ", "))"
        case .notExecutable(let p):
            "\(p) is not an executable file that SigSieve can run"
        case .unsupportedVersion(let p, let out):
            "\(p) is not sigsieve 1.x (reported: \(out.trimmingCharacters(in: .whitespacesAndNewlines)))"
        }
    }

    static func describe(_ e: ProfileStoreError) -> String {
        switch e {
        case .unsupportedVersion(let v): "schema version \(v) is not supported; the file is left untouched"
        case .unreadable(let m): "cannot be read (\(m)); the file is left untouched"
        case .writeFailed(let m): "cannot be saved (\(m))"
        case .invalidProfiles(let m): "not saved (\(m))"
        }
    }
}
