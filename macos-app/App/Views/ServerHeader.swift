import SigSieveKit
import SwiftUI

/// Each blocking error as a red-icon line of selectable text.
struct BlockingErrors: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        let errors = StatusText.blockingErrors(model)
        if !errors.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                ForEach(errors, id: \.self) { message in
                    Label {
                        Text(message).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                    } icon: {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red)
                    }
                }
            }
        }
    }
}

/// The server name, its agent (a menu that saves at once) and the agent's state.
struct ServerHeader: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(model.selectedServer?.value ?? "")
                .font(.title2.weight(.semibold))
                .lineLimit(1).truncationMode(.middle)
                .textSelection(.enabled)
            HStack(spacing: 4) {
                agentMenu
                if !unreachable {
                    Text(StatusText.agentState(model))
                        .foregroundStyle(.secondary)
                        .layoutPriority(1)
                }
            }
            if unreachable {
                Text(StatusText.agentState(model))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var unreachable: Bool {
        if case .unreachable = model.agentState { return true }
        return false
    }

    private var agentMenu: some View {
        Menu {
            Picker("", selection: Binding(
                get: { model.selectedProfile?.agent ?? model.defaultAgent },
                set: { model.setAgent($0) })) {
                ForEach(agentOptions, id: \.self) { Text(model.agentName(for: $0)).tag($0) }
            }
            .pickerStyle(.inline)
            .labelsHidden()
        } label: {
            Text(model.agentName).lineLimit(1).truncationMode(.middle)
        }
        .menuStyle(.borderlessButton)
        .fixedSize(horizontal: false, vertical: true)
        .help(model.agentName)
        .disabled(!model.canEdit)
    }

    private var agentOptions: [AgentChoice] {
        var all: [AgentChoice] = [.secretive, model.defaultAgent, AppModel.appAgent]
        if let current = model.selectedProfile?.agent { all.append(current) }
        var seen = Set<AgentChoice>()
        return all.filter { seen.insert($0).inserted }
    }
}
