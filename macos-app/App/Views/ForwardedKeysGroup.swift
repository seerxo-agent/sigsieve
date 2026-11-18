import SigSieveKit
import SwiftUI

/// The forwarded-agent policy, read only. Every change goes through Edit Keys and Save.
struct ForwardedKeysGroup: View {
    @EnvironmentObject var model: AppModel
    let editKeys: () -> Void

    var body: some View {
        let rows = model.forwardedRows
        VStack(alignment: .leading, spacing: 10) {
            Text("Keys sessions on this server may use (forwarded agent)").font(.headline)
            VStack(spacing: 0) {
                if rows.isEmpty {
                    Text("No keys forwarded")
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 12).padding(.vertical, 10)
                }
                ForEach(Array(rows.enumerated()), id: \.element.id) { index, row in
                    if index > 0 { Divider().padding(.leading, 38) }
                    KeyRow(row: row)
                }
            }
            .groupBox()
            Button("Edit Keys…", action: editKeys)
                .buttonStyle(.link)
                .disabled(!model.canEdit)
            VStack(alignment: .leading, spacing: 2) {
                Text("\(Set(model.selectedProfile?.forwardedKeys ?? []).count) forwarded to this server · applies to new connections")
                    .font(.caption)
                Text("Login uses \(model.agentName), unfiltered.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

/// Not a toggle: a click does nothing. A key missing from the agent shows only its fingerprint.
private struct KeyRow: View {
    let row: ForwardedKeyRow

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "key")
                .foregroundStyle(.secondary)
                .frame(width: 16)
            switch row {
            case .inAgent(let key):
                Text(key.comment.isEmpty ? "(no comment)" : key.comment)
                    .lineLimit(1).truncationMode(.middle)
                Spacer(minLength: 8)
                Text("\(key.type) · \(key.fingerprint.short)")
                    .font(.callout.monospaced()).foregroundStyle(.secondary)
                    .lineLimit(1)
                    .layoutPriority(1)
            case .notInAgent(let fingerprint):
                Text(fingerprint.short)
                    .font(.callout.monospaced()).foregroundStyle(.secondary)
                    .lineLimit(1)
                Text("Not in the agent").foregroundStyle(.secondary)
                Spacer(minLength: 8)
            }
            Button {
                copyToPasteboard(row.id.value)
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .help("Copy fingerprint")
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .help(row.id.value)
    }
}
