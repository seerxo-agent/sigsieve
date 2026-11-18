import SigSieveKit
import SwiftUI

/// Chooses the protection mode as a draft; nothing reaches the model until Save.
struct ProtectionSheet: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let server: HostInput
    @State private var draft: ProtectionMode

    init(server: HostInput, profile: Profile) {
        self.server = server
        _draft = State(initialValue: profile.mode)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            option(.filtering, title: "Identity filtering only",
                   lines: ["Forwarded key can sign for any server while connected"])
            option(.binding, title: "Destination binding", lines: [
                "Destination binding names the servers the forwarded key may log in to onward from this server, for example github.com. It does not protect the login to this server itself.",
                "Binding needs OpenSSH hostbound authentication on the onward server.",
                "RSA host keys cannot bind.",
                "With Secretive, a cancelled Touch ID prompt means reconnecting.",
            ])
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Save") {
                    if model.setMode(draft, for: server) { dismiss() }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!model.canEdit)
            }
        }
        .padding(20)
        .frame(width: 440)
        .onChange(of: model.selectedServer) { _ in dismiss() }
    }

    private func option(_ mode: ProtectionMode, title: String, lines: [String]) -> some View {
        Button { draft = mode } label: {
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: draft == mode ? "largecircle.fill.circle" : "circle")
                    .foregroundStyle(draft == mode ? Color.accentColor : .secondary)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 4) {
                    Text(title).font(.headline)
                    ForEach(lines, id: \.self) { Text($0) }
                        .font(.caption).foregroundStyle(.secondary)
                }
                .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(title)
        .accessibilityHint(lines.joined(separator: " "))
        .accessibilityAddTraits(draft == mode ? .isSelected : [])
    }
}
