import AppKit
import SigSieveKit
import SwiftUI

/// Default agent, optional CLI path, and what was resolved.
struct SettingsView: View {
    @EnvironmentObject var model: AppModel
    @State private var cliPath = ""
    @State private var socket = ""
    @State private var socketError: String?
    /// What the picker shows; separate from the model so choosing OpenSSH can reveal the socket row without saving.
    @State private var agentKind = AgentKind.secretive

    private enum AgentKind { case secretive, openssh }

    private enum Pane: String, CaseIterable, Identifiable {
        case agent = "Agent", commandLine = "Command Line", files = "Files"
        var id: Self { self }
        var symbol: String {
            switch self {
            case .agent: "key.fill"
            case .commandLine: "terminal.fill"
            case .files: "doc.fill"
            }
        }
        var tint: Color {
            switch self {
            case .agent: .blue
            case .commandLine: .gray
            case .files: .orange
            }
        }
    }

    @State private var pane = Pane.agent

    var body: some View {
        HStack(spacing: 0) {
            List(Pane.allCases, selection: $pane) { p in
                Label {
                    Text(p.rawValue)
                } icon: {
                    Image(systemName: p.symbol)
                        .font(.footnote.weight(.semibold))
                        .foregroundStyle(.white)
                        .frame(width: 22, height: 22)
                        .background(p.tint, in: RoundedRectangle(cornerRadius: 5))
                }
                .tag(p)
            }
            .listStyle(.sidebar)
            .frame(width: 180)
            Divider()
            VStack(alignment: .leading, spacing: 0) {
                Text(pane.rawValue).font(.title.bold())
                    .padding(.horizontal, 20).padding(.top, 14)
                Form {
                    switch pane {
                    case .agent: agentPane
                    case .commandLine: commandLinePane
                    case .files: filesPane
                    }
                }
                .formStyle(.grouped)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(minWidth: 600, minHeight: 360)
        .onAppear {
            cliPath = model.cliPathSetting
            if case .openssh(let s) = model.defaultAgent { socket = s; agentKind = .openssh }
            else {
                agentKind = .secretive
                if case .openssh(let s) = AppModel.appAgent { socket = s }
            }
        }
        .onChange(of: agentKind) { kind in
            // Secretive applies at once (unless already the default); OpenSSH only reveals the socket row.
            if kind == .secretive, model.defaultAgent != .secretive { useAgent(.secretive) }
        }
    }

    @ViewBuilder private var agentPane: some View {
        Section {
            Picker("Agent", selection: $agentKind) {
                Text("Secretive").tag(AgentKind.secretive)
                Text("OpenSSH agent").tag(AgentKind.openssh)
            }
            .pickerStyle(.menu)
            if agentKind == .openssh {
                LabeledContent("Socket") {
                    HStack {
                        TextField("Socket", text: $socket)
                            .labelsHidden()
                            .textFieldStyle(.roundedBorder)
                            .frame(minWidth: 200, maxWidth: 340)
                        Button("Use") { useAgent(.openssh(socket: socket)) }
                    }
                }
                if model.defaultAgent != .openssh(socket: socket) {
                    Text("Not saved yet. The default agent is still \(model.agentName(for: model.defaultAgent)).")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let socketError {
                    Text(socketError).font(.caption).foregroundStyle(.red)
                }
            }
        } header: {
            Text("Default agent for new servers")
        } footer: {
            Text("Existing servers keep their own agent.")
        }
    }

    @ViewBuilder private var commandLinePane: some View {
        Section {
            LabeledContent("Path (optional, absolute)") {
                HStack {
                    TextField("Path", text: $cliPath, prompt: Text("Found automatically when empty"))
                        .labelsHidden()
                        .textFieldStyle(.roundedBorder)
                        .frame(minWidth: 200, maxWidth: 340)
                    Button("Save") { Task { await model.setCLIPath(cliPath) } }
                }
            }
            if let error = model.cliPathError {
                Text(error).font(.caption).foregroundStyle(.red)
            }
            switch model.cli {
            case .success(let info):
                pathRow("CLI", info.path.path(percentEncoded: false))
                row("Version", info.version)
            case .failure(let e):
                row("CLI", StatusText.describe(e))
            case nil:
                row("CLI", "not resolved")
            }
        } header: {
            Text("SigSieve CLI")
        }
    }

    @ViewBuilder private var filesPane: some View {
        Section {
            pathRow("Profiles file", model.store.file.path)
        }
    }

    private func useAgent(_ agent: AgentChoice) {
        if model.setDefaultAgent(agent) {
            socketError = nil
        } else {
            socketError = socket.isEmpty
                ? "Enter the agent socket path to use the OpenSSH agent. The default agent is unchanged."
                : "The agent socket must be an absolute path (starting with /) without control characters. The default agent is unchanged."
        }
    }

    /// Read-only value that wraps rather than truncates: the CLI path says which executable runs.
    private func row(_ label: String, _ value: String, help: String? = nil) -> some View {
        LabeledContent(label) {
            Text(value).font(.body.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                .multilineTextAlignment(.trailing)
                .fixedSize(horizontal: false, vertical: true)
                .help(help ?? value)
        }
    }

    /// A path shown with the home directory as `~`; the full path is the tooltip.
    private func pathRow(_ label: String, _ path: String) -> some View {
        row(label, (path as NSString).abbreviatingWithTildeInPath, help: path)
    }
}
