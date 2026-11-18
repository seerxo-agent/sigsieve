import SigSieveKit
import SwiftUI

/// Binding mode only: the onward host keys, their captions and the CLI's limits.
/// Remove saves at once, an explicit single action (owner exception to Save-only editing).
struct BindingSection: View {
    @EnvironmentObject var model: AppModel
    let addHostKey: () -> Void

    var body: some View {
        let destinations = model.selectedProfile?.destinations ?? []
        VStack(alignment: .leading, spacing: 10) {
            if let problem = model.selectedProfile?.policyProblem {
                Label {
                    Text(problem).fixedSize(horizontal: false, vertical: true)
                } icon: {
                    Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange)
                }
            }
            Text("Onward servers the key may log in to").font(.headline)
            if !destinations.isEmpty {
                VStack(spacing: 0) {
                    ForEach(Array(rows(destinations).enumerated()), id: \.offset) { index, row in
                        if index > 0 { Divider().padding(.leading, 12) }
                        HostKeyRow(name: row.name, key: row.key)
                    }
                }
                .groupBox()
            }
            Button("Add Host Key…", action: addHostKey)
                .buttonStyle(.link)
                .disabled(!model.canEdit)
            VStack(alignment: .leading, spacing: 4) {
                Text("Destination binding names the servers the forwarded key may log in to onward from this server, for example github.com. It does not protect the login to this server itself.")
                Text("SigSieve does not verify that these host keys belong to the server.")
            }
            .font(.caption).foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            VStack(alignment: .leading, spacing: 2) {
                Text("Limits").font(.subheadline.weight(.medium))
                Group {
                    Text("Binding needs OpenSSH hostbound authentication on the onward server.")
                    Text("RSA host keys cannot bind.")
                    Text("With Secretive, a cancelled Touch ID prompt means reconnecting.")
                }
                .font(.caption)
                .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func rows(_ destinations: [Destination]) -> [(name: String, key: Fingerprint)] {
        destinations.flatMap { d in d.hostKeys.map { (d.name, $0) } }
    }
}

private struct HostKeyRow: View {
    @EnvironmentObject var model: AppModel
    let name: String
    let key: Fingerprint

    var body: some View {
        HStack(spacing: 10) {
            Text(name).lineLimit(1).truncationMode(.middle)
            Text(detail)
                .font(.callout.monospaced()).foregroundStyle(.secondary)
                .lineLimit(1).truncationMode(.middle)
            Spacer(minLength: 8)
            Button("Remove") { model.removeHostKey(key) }
                .buttonStyle(.link)
                .disabled(!model.canEdit)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .help(key.value)
    }

    /// Type and "from your known_hosts" only when the key is in the list read from there.
    private var detail: String {
        guard let entry = model.knownHosts.first(where: { $0.fingerprint == key }) else { return key.short }
        return "\(entry.type) \(entry.fingerprint.short) · from your known_hosts"
    }
}
