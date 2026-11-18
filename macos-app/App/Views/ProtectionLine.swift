import SigSieveKit
import SwiftUI

/// The protection mode in one line, and in filtering mode its warning, always visible (AC3).
struct ProtectionLine: View {
    @EnvironmentObject var model: AppModel
    let change: () -> Void

    var body: some View {
        let binding = model.selectedProfile?.mode == .binding
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: binding ? "checkmark.shield" : "shield")
                    .foregroundStyle(.secondary)
                Text(binding ? "Destination binding" : "Identity filtering only")
                    .fontWeight(.medium)
                Button("Change…", action: change)
                    .buttonStyle(.link)
                    .disabled(!model.canEdit)
            }
            if !binding {
                Label {
                    Text("Forwarded key can sign for any server while connected")
                } icon: {
                    Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange)
                }
            }
        }
    }
}
