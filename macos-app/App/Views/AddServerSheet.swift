import SigSieveKit
import SwiftUI

struct AddServerSheet: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var newServer = ""
    @State private var invalid = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                TextField("alias or user@host", text: $newServer)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit(add)
                Button("Add", action: add)
                    .keyboardShortcut(.defaultAction)
                    .disabled(newServer.isEmpty)
            }
            if invalid {
                Text("Not a valid server: no leading -, spaces or control characters.")
                    .font(.caption).foregroundStyle(.red)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
            }
        }
        .padding(20)
        .frame(width: 380)
    }

    private func add() {
        if model.addServer(newServer) {
            dismiss()
        } else {
            invalid = true
        }
    }
}
