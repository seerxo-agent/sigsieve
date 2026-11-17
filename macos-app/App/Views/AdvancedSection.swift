import SigSieveKit
import SwiftUI

/// Agent for this server, protection mode, allowed host keys for binding, and the CLI's limits.
struct AdvancedSection: View {
    @EnvironmentObject var model: AppModel
    @State private var expanded = false
    @State private var manualName = ""
    @State private var manualFingerprint = ""
    @State private var manualInvalid = false

    var body: some View {
        DisclosureGroup("Advanced", isExpanded: $expanded) {
            VStack(alignment: .leading, spacing: 8) {
                agentPicker
                Picker("Protection", selection: Binding(
                    get: { model.selectedProfile?.mode ?? .filtering },
                    set: { model.setMode($0) })) {
                    Text("Identity filtering").tag(ProtectionMode.filtering)
                    Text("Destination binding").tag(ProtectionMode.binding)
                }
                .disabled(!model.canEdit)
                Text("Destination binding names the servers the forwarded key may log in to onward from this server, for example github.com. It does not protect the login to this server itself.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if model.selectedProfile?.mode == .binding {
                    destinations
                    knownHostsPicker
                    manualEntry
                }
                limits
            }
            .padding(.top, 4)
        }
    }

    private var agentPicker: some View {
        let options = agentOptions
        return Picker("Agent", selection: Binding(
            get: { model.selectedProfile?.agent ?? model.defaultAgent },
            set: { model.setAgent($0) })) {
            ForEach(options, id: \.self) { Text(model.agentName(for: $0)).tag($0) }
        }
        .disabled(!model.canEdit)
    }

    private var agentOptions: [AgentChoice] {
        var all: [AgentChoice] = [.secretive, model.defaultAgent, AppModel.appAgent]
        if let current = model.selectedProfile?.agent { all.append(current) }
        var seen = Set<AgentChoice>()
        return all.filter { seen.insert($0).inserted }
    }

    @ViewBuilder private var destinations: some View {
        let list = model.selectedProfile?.destinations ?? []
        if let problem = model.selectedProfile?.policyProblem {
            Text(problem)
                .font(.caption).foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
        }
        ForEach(list, id: \.self) { d in
            ForEach(d.hostKeys, id: \.self) { key in
                HStack {
                    Text(d.name).lineLimit(1)
                    Text(key.short).font(.caption.monospaced()).foregroundStyle(.secondary)
                    Spacer()
                    Button("Remove") { model.removeHostKey(key) }
                        .buttonStyle(.link)
                        .disabled(!model.canEdit)
                }
                .help(key.value)
            }
        }
    }

    private var knownHostsPicker: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Add a host key").font(.subheadline)
            Text("SigSieve does not verify that these host keys belong to the server.")
                .font(.caption).foregroundStyle(.secondary)
            Text("Listed keys were found in your local known_hosts files. Custom UserKnownHostsFile, GlobalKnownHostsFile, KnownHostsCommand and RevokedHostKeys settings are not read.")
                .font(.caption).foregroundStyle(.secondary)
            List(model.knownHosts, id: \.self) { entry in
                KnownHostRow(entry: entry)
            }
            .listStyle(.bordered(alternatesRowBackgrounds: false))
            .frame(height: 110)
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

    private var limits: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("Limits").font(.subheadline)
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

private struct KnownHostRow: View {
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
                model.addDestination(Destination(name: entry.name ?? entry.fingerprint.short, hostKeys: [entry.fingerprint]))
            }
            .disabled(isRSA || !model.canEdit)
        }
        .help(entry.fingerprint.value)
        .opacity(isRSA ? 0.5 : 1)
    }
}
