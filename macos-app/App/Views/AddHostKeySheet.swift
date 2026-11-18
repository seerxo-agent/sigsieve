import SigSieveKit
import SwiftUI

/// known_hosts picker and manual entry. Each Add saves at once, as it always has.
struct AddHostKeySheet: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var manualName = ""
    @State private var manualFingerprint = ""
    @State private var manualInvalid = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            knownHostsPicker
            manualEntry
            HStack {
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 480)
    }

    private var knownHostsPicker: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Add a host key").font(.subheadline)
            Text("SigSieve does not verify that these host keys belong to the server.")
                .font(.caption).foregroundStyle(.secondary)
            Text("Listed keys were found in your local known_hosts files. Custom UserKnownHostsFile, GlobalKnownHostsFile, KnownHostsCommand and RevokedHostKeys settings are not read.")
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            List(model.knownHosts, id: \.self) { entry in
                SheetKnownHostRow(entry: entry)
            }
            .listStyle(.bordered(alternatesRowBackgrounds: false))
            .frame(height: 160)
            if let error = model.knownHostsError {
                Text(error).font(.caption).foregroundStyle(.red)
            }
        }
    }

    private var manualEntry: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                TextField("Name", text: $manualName).frame(width: 100)
                TextField("SHA256:…", text: $manualFingerprint)
                Button("Add") {
                    guard let fp = Fingerprint(manualFingerprint), !manualName.isEmpty else { manualInvalid = true; return }
                    model.addDestination(Destination(name: manualName, hostKeys: [fp]))
                    manualName = ""; manualFingerprint = ""; manualInvalid = false
                }
                .disabled(!model.canEdit)
            }
            .textFieldStyle(.roundedBorder)
            if manualInvalid {
                Text("Enter a name and a full SHA256: fingerprint.").font(.caption).foregroundStyle(.red)
            }
            Text("Ask the server's administrator for the fingerprint, or read it on that server's console with ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub. SigSieve never fetches host keys from the network.")
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

private struct SheetKnownHostRow: View {
    @EnvironmentObject var model: AppModel
    let entry: KnownHostEntry

    private var isRSA: Bool { entry.type.uppercased().hasPrefix("RSA") }

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 1) {
                // Names may be patterns such as * or [host]:2222; shown exactly as written.
                Text(entry.name ?? "hashed entry").lineLimit(1).truncationMode(.middle)
                Text("\(entry.type) \(entry.fingerprint.short) · from your known_hosts")
                    .font(.caption).foregroundStyle(.secondary)
                if isRSA { Text("RSA host keys cannot bind").font(.caption).foregroundStyle(.orange) }
            }
            Spacer()
            Button("Add") {
                Task { await model.addKnownHost(entry) }
            }
            .disabled(isRSA || !model.canEdit)
        }
        .help(entry.fingerprint.value)
        .opacity(isRSA ? 0.5 : 1)
    }
}
