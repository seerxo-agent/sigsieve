import SigSieveKit
import SwiftUI

/// Agent, key count and CLI version; each blocking error in red.
struct StatusRow: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(agentSummary)
                Spacer()
                Text(cliSummary).foregroundStyle(.secondary)
            }
            .font(.callout)
            ForEach(blockingErrors, id: \.self) { message in
                Label(message, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var agentSummary: String {
        switch model.agentState {
        case .keys(let k): "\(model.agentName) · \(k.count) key\(k.count == 1 ? "" : "s")"
        case .empty: "\(model.agentName) · no keys"
        case .unreachable(let why): "Agent not reachable: \(why)"
        }
    }

    private var cliSummary: String {
        switch model.cli {
        case .success(let info): info.version
        case .failure: "CLI error"
        case nil: "CLI …"
        }
    }

    private var blockingErrors: [String] {
        var errors: [String] = []
        if let p = model.cliSettingProblem { errors.append(p) }
        if case .failure(let e) = model.cli { errors.append(Self.describe(e)) }
        if case .failure(let e) = model.tmpdir { errors.append("Blocked: \(e.description). There is no fallback to /tmp.") }
        if let e = model.storeError {
            errors.append("Profiles file \(model.store.file.path): \(Self.describe(e)). Editing is disabled.")
        }
        return errors
    }

    static func describe(_ e: CLIError) -> String {
        switch e {
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
