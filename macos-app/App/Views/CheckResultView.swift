import SigSieveKit
import SwiftUI

/// The check result (a pass only while it opens the gate), then the untracked-Include note and
/// any connect error, which stay visible after connect() resets the check.
/// Every warning sits above "Details", never inside it (AC3).
struct CheckResultView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if case .finished(let result) = model.checkState {
                if result.passed {
                    if model.canConnect { PassedResult(result: result) }
                } else {
                    FailedResult(result: result)
                }
            }
            if model.discovery.untracked {
                Text("Some Include files cannot be tracked; SigSieve checks again when you connect.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let error = model.connectError {
                Text(error)
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

private struct PassedResult: View {
    @EnvironmentObject var model: AppModel
    let result: CheckResult

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(title, systemImage: "checkmark.circle.fill")
                .font(.headline)
                .foregroundStyle(.green)
            // The filtering warning is not repeated here: ProtectionLine shows it at all times (owner 2026-11-19).
            CLIWarnings(lines: lines)
            Text("SigSieve checks again when it connects")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Details(result: result, command: model.copyableCommand)
        }
    }

    private var lines: [ResultLine] { result.doctor.lines + (result.dryRun?.lines ?? []) }

    private var title: String {
        guard let time = model.checkFinishedAt else { return "Check passed" }
        return "Check passed · \(time.formatted(date: .omitted, time: .shortened))"
    }
}

private struct FailedResult: View {
    let result: CheckResult

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(title, systemImage: "xmark.octagon.fill")
                .font(.headline)
                .foregroundStyle(.red)
            if let hint = failing.hint {
                Text(hint).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            }
            Text("If the server's host key is not in known_hosts, OpenSSH refuses the connection. Add it only after comparing its fingerprint with the one the server's administrator gives you.")
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            CLIWarnings(lines: lines)
            Details(result: result, command: nil)
        }
    }

    private var lines: [ResultLine] { result.doctor.lines + (result.dryRun?.lines ?? []) }

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
}

/// Each `sigsieve: warning: …` line from the CLI, word for word, above Details (AC3).
/// They stay in Details too, with the other result lines.
private struct CLIWarnings: View {
    let lines: [ResultLine]

    var body: some View {
        ForEach(Array(lines.filter { $0.label == "sigsieve" && $0.value.hasPrefix("warning:") }.enumerated()), id: \.offset) { _, line in
            Label {
                Text(line.value)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            } icon: {
                Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange)
            }
        }
    }
}

/// Collapsed by default. Result lines, the raw output (no inner scrolling) and, for a pass, the command.
private struct Details: View {
    let result: CheckResult
    let command: String?

    var body: some View {
        DisclosureGroup("Details") {
            VStack(alignment: .leading, spacing: 10) {
                if !lines.isEmpty {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(Array(lines.enumerated()), id: \.offset) { _, line in
                            LabeledContent(line.label) {
                                Text(line.value).multilineTextAlignment(.trailing).textSelection(.enabled)
                            }
                        }
                    }
                    .font(.caption)
                }
                Text(raw.isEmpty ? "(no output)" : raw)
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
                    .groupBox()
                if let command {
                    HStack(alignment: .top, spacing: 8) {
                        Text(command)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        Button {
                            copyToPasteboard(command)
                        } label: {
                            Image(systemName: "doc.on.doc")
                        }
                        .buttonStyle(.borderless)
                        .help("Copy command")
                    }
                    .padding(10)
                    .groupBox()
                }
            }
            .padding(.top, 6)
        }
    }

    private var lines: [ResultLine] { result.doctor.lines + (result.dryRun?.lines ?? []) }
    private var raw: String { [result.doctor.raw, result.dryRun?.raw ?? ""].filter { !$0.isEmpty }.joined(separator: "\n\n") }
}
