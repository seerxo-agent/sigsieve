import AppKit
import SigSieveKit
import SwiftUI

/// Footer: Settings and Quit.
struct FooterView: View {
    @Binding var showSettings: Bool

    var body: some View {
        HStack {
            Button(showSettings ? "Done" : "Settings…") { showSettings.toggle() }
            Spacer()
            Button("Quit") { NSApplication.shared.terminate(nil) }
        }
    }
}

/// Default agent, optional CLI path, and what was resolved.
struct SettingsView: View {
    @EnvironmentObject var model: AppModel
    @State private var cliPath = ""
    @State private var socket = ""
    @State private var socketError: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Settings").font(.headline)

            Text("Default agent for new servers").font(.subheadline)
            Picker("", selection: Binding(
                get: { model.defaultAgent == .secretive ? 0 : 1 },
                set: { $0 == 0 ? useAgent(.secretive) : useAgent(.openssh(socket: socket)) })) {
                Text("Secretive").tag(0)
                Text("OpenSSH agent").tag(1)
            }
            .pickerStyle(.radioGroup)
            .labelsHidden()
            HStack {
                TextField("Agent socket path", text: $socket)
                    .textFieldStyle(.roundedBorder)
                Button("Use") { useAgent(.openssh(socket: socket)) }
            }
            if let socketError {
                Text(socketError).font(.caption).foregroundStyle(.red)
            }

            Text("SigSieve CLI path (optional, absolute)").font(.subheadline)
            HStack {
                TextField("Found automatically when empty", text: $cliPath)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { Task { await model.setCLIPath(cliPath) } }
                Button("Save") { Task { await model.setCLIPath(cliPath) } }
            }
            if let error = model.cliPathError {
                Text(error).font(.caption).foregroundStyle(.red)
            }

            Group {
                switch model.cli {
                case .success(let info):
                    row("CLI", info.path.path(percentEncoded: false))
                    row("Version", info.version)
                case .failure(let e):
                    row("CLI", StatusText.describe(e))
                case nil:
                    row("CLI", "not resolved")
                }
                row("Profiles file", model.store.file.path)
            }
        }
        .onAppear {
            cliPath = model.cliPathSetting
            if case .openssh(let s) = model.defaultAgent { socket = s }
            else if case .openssh(let s) = AppModel.appAgent { socket = s }
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

    private func row(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.caption.monospaced()).textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
