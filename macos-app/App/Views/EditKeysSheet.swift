import SigSieveKit
import SwiftUI

/// Edits a draft of the forwarded keys; nothing reaches the model until Save.
struct EditKeysSheet: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let server: HostInput
    @State private var draft: Set<Fingerprint>
    @State private var query = ""

    /// The draft starts as all saved fingerprints, including the ones missing from the agent.
    init(server: HostInput, profile: Profile) {
        self.server = server
        _draft = State(initialValue: Set(profile.forwardedKeys))
    }

    var body: some View {
        let missing = model.forwardedRows.compactMap { row -> Fingerprint? in
            if case .notInAgent(let fingerprint) = row { return fingerprint }
            return nil
        }
        VStack(alignment: .leading, spacing: 12) {
            Text("Keys sessions on this server may use (forwarded agent)").font(.headline)
            TextField("Search keys", text: $query)
                .textFieldStyle(.roundedBorder)
            List {
                if !missing.isEmpty {
                    Section("Not in the agent") {
                        ForEach(missing, id: \.self) { fingerprint in
                            Toggle(isOn: binding(fingerprint)) {
                                Text(fingerprint.short)
                                    .font(.callout.monospaced()).foregroundStyle(.secondary)
                            }
                            .toggleStyle(.checkbox)
                            .help(fingerprint.value)
                        }
                    }
                }
                Section {
                    ForEach(KeyFilter.filter(model.agentKeys, query: query)) { key in
                        Toggle(isOn: binding(key.fingerprint)) {
                            VStack(alignment: .leading, spacing: 1) {
                                Text(key.comment.isEmpty ? "(no comment)" : key.comment)
                                    .lineLimit(1).truncationMode(.middle)
                                Text("\(key.type) \(key.bits) · \(key.fingerprint.short)")
                                    .font(.caption.monospaced()).foregroundStyle(.secondary)
                            }
                        }
                        .toggleStyle(.checkbox)
                        .help(key.fingerprint.value)
                    }
                }
            }
            .listStyle(.bordered(alternatesRowBackgrounds: false))
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Save") {
                    if model.setForwardedKeys(selection: draft, for: server) { dismiss() }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!model.canEdit)
            }
        }
        .padding(20)
        .frame(width: 460, height: 460)
        .onChange(of: model.selectedServer) { _ in dismiss() }
    }

    private func binding(_ fingerprint: Fingerprint) -> Binding<Bool> {
        Binding(
            get: { draft.contains(fingerprint) },
            set: { if $0 { draft.insert(fingerprint) } else { draft.remove(fingerprint) } })
    }
}
