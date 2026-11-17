import SigSieveKit
import SwiftUI

/// Aliases from SSH configuration plus servers with a profile; search and "Add server…".
struct ServerPicker: View {
    @EnvironmentObject var model: AppModel
    @State private var adding = false
    @State private var newServer = ""
    @State private var invalid = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Server").font(.headline)
                Spacer()
                Button("Add server…") { adding.toggle() }
                    .buttonStyle(.link)
                    .disabled(model.storeError != nil)
            }
            if adding {
                HStack {
                    TextField("alias or user@host", text: $newServer)
                        .textFieldStyle(.roundedBorder)
                        .onSubmit(add)
                    Button("Add", action: add).disabled(newServer.isEmpty)
                }
                if invalid {
                    Text("Not a valid server: no leading -, spaces or control characters.")
                        .font(.caption).foregroundStyle(.red)
                }
            }
            TextField("Search servers", text: $model.serverQuery)
                .textFieldStyle(.roundedBorder)
            List(model.filteredServers, id: \.self, selection: $model.selectedServer) { server in
                Text(server.value).lineLimit(1).truncationMode(.middle)
            }
            .listStyle(.bordered(alternatesRowBackgrounds: false))
            .frame(height: 120)
            if !model.discovery.skippedIncludes.isEmpty {
                Text("Include not read: \(model.discovery.skippedIncludes.joined(separator: ", "))")
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.tail)
                    .help(model.discovery.skippedIncludes.joined(separator: "\n"))
            }
        }
    }

    private func add() {
        if model.addServer(newServer) {
            newServer = ""
            invalid = false
            adding = false
        } else {
            invalid = true
        }
    }
}
