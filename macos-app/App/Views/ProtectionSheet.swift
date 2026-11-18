import SigSieveKit
import SwiftUI

/// Chooses the protection mode as a draft; nothing reaches the model until Save.
struct ProtectionSheet: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let server: HostInput
    @State private var draft = ProtectionMode.filtering

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            option(.filtering, title: "Identity filtering only") {
                Text("Forwarded key can sign for any server while connected")
            }
            option(.binding, title: "Destination binding") {
                Text("Destination binding names the servers the forwarded key may log in to onward from this server, for example github.com. It does not protect the login to this server itself.")
                VStack(alignment: .leading, spacing: 2) {
                    Text("Binding needs OpenSSH hostbound authentication on the onward server.")
                    Text("RSA host keys cannot bind.")
                    Text("With Secretive, a cancelled Touch ID prompt means reconnecting.")
                }
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Save") {
                    model.setMode(draft, for: server)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!model.canEdit)
            }
        }
        .padding(20)
        .frame(width: 440)
        .onAppear { draft = model.selectedProfile?.mode ?? .filtering }
        .onChange(of: model.selectedServer) { _ in dismiss() }
    }

    private func option<Detail: View>(_ mode: ProtectionMode, title: String, @ViewBuilder detail: () -> Detail) -> some View {
        Button { draft = mode } label: {
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: draft == mode ? "largecircle.fill.circle" : "circle")
                    .foregroundStyle(draft == mode ? Color.accentColor : .secondary)
                VStack(alignment: .leading, spacing: 4) {
                    Text(title).font(.headline)
                    detail().font(.caption).foregroundStyle(.secondary)
                }
                .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(draft == mode ? .isSelected : [])
    }
}
