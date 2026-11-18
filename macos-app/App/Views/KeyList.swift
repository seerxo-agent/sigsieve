import AppKit
import SigSieveKit
import SwiftUI

/// The forwarded-agent policy for the selected server. There is no "select all".
struct KeyList: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        let forwarded = Set(model.selectedProfile?.forwardedKeys ?? [])
        VStack(alignment: .leading, spacing: 6) {
            Text("Keys sessions on this server may use (forwarded agent)").font(.headline)
            TextField("Search keys", text: $model.keyQuery)
                .textFieldStyle(.roundedBorder)
            List(model.filteredKeys) { key in
                KeyRow(key: key, isOn: forwarded.contains(key.fingerprint))
            }
            .listStyle(.bordered(alternatesRowBackgrounds: false))
            .frame(height: 180)
            Text("\(forwarded.count) forwarded to this server · applies to new connections")
                .font(.caption)
            Text("Login uses \(model.agentName), unfiltered.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }
}

private struct KeyRow: View {
    @EnvironmentObject var model: AppModel
    let key: AgentKey
    let isOn: Bool

    var body: some View {
        HStack {
            Toggle(isOn: Binding(get: { isOn }, set: { _ in model.toggleKey(key.fingerprint) })) {
                VStack(alignment: .leading, spacing: 1) {
                    Text(key.comment.isEmpty ? "(no comment)" : key.comment)
                        .lineLimit(1).truncationMode(.middle)
                    Text("\(key.type) \(key.bits) · \(key.fingerprint.short)")
                        .font(.caption.monospaced()).foregroundStyle(.secondary)
                }
            }
            .toggleStyle(.checkbox)
            .disabled(!model.canEdit)
            Spacer()
            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(key.fingerprint.value, forType: .string)
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .help("Copy fingerprint")
        }
        .help(key.fingerprint.value)
    }
}
