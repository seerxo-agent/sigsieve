import AppKit
import SigSieveKit
import SwiftUI

/// Check Connection, its result, then Connect in Terminal and the copyable command.
struct CheckSection: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Button("Check Connection") { Task { await model.runCheck() } }
                    .disabled(model.inputsProblem != nil || isRunning)
                if case .running(let step) = model.checkState {
                    ProgressView().controlSize(.small)
                    Text(step == .waitingForAgent ? "Waiting for agent…" : "Checking…").font(.caption)
                }
            }
            if model.discovery.untracked {
                Text("Some Include files cannot be tracked; SigSieve checks again when you connect.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if let problem = model.inputsProblem {
                Text(problem).font(.caption).foregroundStyle(.secondary)
            }
            if case .finished(let result) = model.checkState {
                if result.passed {
                    if model.canConnect { PassedResult(result: result) }
                } else {
                    FailedResult(result: result)
                }
            }
            if let error = model.connectError {
                Text(error).font(.caption).foregroundStyle(.red).textSelection(.enabled)
            }
        }
    }

    private var isRunning: Bool {
        if case .running = model.checkState { return true }
        return false
    }
}

private struct PassedResult: View {
    @EnvironmentObject var model: AppModel
    let result: CheckResult

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Label("Check passed", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
            ForEach(Array(lines.enumerated()), id: \.offset) { _, line in
                HStack(alignment: .firstTextBaseline) {
                    Text(line.label).foregroundStyle(.secondary)
                    Spacer()
                    Text(line.value).multilineTextAlignment(.trailing)
                }
                .font(.caption)
            }
            // A passed check exists only without a policyProblem, so binding here always has a host key.
            if model.selectedProfile?.mode != .binding {
                Text("Forwarded key can sign for any server while connected").font(.caption)
            }
            OutputDisclosure(raw: raw)
            Button("Connect in Terminal") { Task { await model.connect() } }
                .keyboardShortcut(.defaultAction)
                .disabled(!model.canConnect)
            if let command = model.copyableCommand {
                HStack(alignment: .top) {
                    ScrollView(.horizontal) {
                        Text(command).font(.caption.monospaced()).textSelection(.enabled).fixedSize()
                    }
                    Button {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(command, forType: .string)
                    } label: { Image(systemName: "doc.on.doc") }
                    .buttonStyle(.borderless)
                    .help("Copy command")
                }
            }
            Text("SigSieve checks again when it connects").font(.caption).foregroundStyle(.secondary)
        }
    }

    private var lines: [ResultLine] { result.doctor.lines + (result.dryRun?.lines ?? []) }
    private var raw: String { [result.doctor.raw, result.dryRun?.raw ?? ""].filter { !$0.isEmpty }.joined(separator: "\n\n") }
}

private struct FailedResult: View {
    let result: CheckResult

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Label(title, systemImage: "xmark.octagon.fill").foregroundStyle(.red)
            if let hint = failing.hint {
                Text(hint).font(.caption).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            }
            OutputDisclosure(raw: raw)
            Text("If the server's host key is not in known_hosts, OpenSSH refuses the connection. Add it only after comparing its fingerprint with the one the server's administrator gives you.")
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    /// The step that did not pass: doctor, else the dry run.
    private var failing: StepResult { result.doctor.outcome == .passed ? (result.dryRun ?? result.doctor) : result.doctor }

    private var title: String {
        let step = result.doctor.outcome == .passed ? "sigsieve connect --dry-run" : "sigsieve doctor"
        return switch failing.outcome {
        case .invalidConfiguration: "\(step): invalid configuration"
        case .timedOut: "\(step) did not finish in time"
        default: "\(step) failed"
        }
    }

    private var raw: String { [result.doctor.raw, result.dryRun?.raw ?? ""].filter { !$0.isEmpty }.joined(separator: "\n\n") }
}

private struct OutputDisclosure: View {
    let raw: String

    var body: some View {
        DisclosureGroup("Show output") {
            ScrollView {
                Text(raw.isEmpty ? "(no output)" : raw)
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(height: 120)
        }
        .font(.caption)
    }
}
