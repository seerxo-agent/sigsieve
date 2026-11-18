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

    var body: some View {
        Form {
            Section {
                Picker("Agent", selection: $agentKind) {
                    Text("Secretive").tag(AgentKind.secretive)
                    Text("OpenSSH agent").tag(AgentKind.openssh)
                }
                .pickerStyle(.menu)
                if agentKind == .openssh {
                    LabeledContent("Agent socket path") {
                        HStack {
                            TextField("Agent socket path", text: $socket)
                                .labelsHidden()
                                .textFieldStyle(.roundedBorder)
                            Button("Use") { useAgent(.openssh(socket: socket)) }
                        }
                    }
                    if model.defaultAgent != .openssh(socket: socket) {
                        Text("Not saved yet. The default agent is unchanged.")
                            .font(.caption).foregroundStyle(.secondary)
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

            Section {
                LabeledContent("Path (optional, absolute)") {
                    HStack {
                        TextField("Path", text: $cliPath, prompt: Text("Found automatically when empty"))
                            .labelsHidden()
                            .textFieldStyle(.roundedBorder)
                        Button("Save") { Task { await model.setCLIPath(cliPath) } }
                    }
                }
                if let error = model.cliPathError {
                    Text(error).font(.caption).foregroundStyle(.red)
                }
                switch model.cli {
                case .success(let info):
                    row("CLI", info.path.path(percentEncoded: false))
                    row("Version", info.version)
                case .failure(let e):
                    row("CLI", StatusText.describe(e))
                case nil:
                    row("CLI", "not resolved")
                }
            } header: {
                Text("SigSieve CLI")
            }

            Section {
                row("Profiles file", model.store.file.path)
            }
        }
        .formStyle(.grouped)
        .frame(width: 500)
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
    private func row(_ label: String, _ value: String) -> some View {
        LabeledContent(label) {
            Text(value).font(.body.monospaced()).textSelection(.enabled)
                .multilineTextAlignment(.trailing)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
