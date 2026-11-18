import AppKit
import SigSieveKit
import SwiftUI

/// The main window: servers in the sidebar, the selected server's detail, and a fixed bottom bar.
struct MainWindow: View {
    @EnvironmentObject var model: AppModel
    @State private var showEditKeys = false
    @State private var showProtection = false
    @State private var showAddHostKey = false
    @State private var showAddServer = false

    var body: some View {
        NavigationSplitView {
            Sidebar(showAddServer: $showAddServer)
                .navigationSplitViewColumnWidth(min: 180, ideal: 210, max: 320)
        } detail: {
            VStack(spacing: 0) {
                if model.selectedServer != nil {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 20) {
                            BlockingErrors()
                            ServerHeader()
                            ProtectionLine { showProtection = true }
                            ForwardedKeysGroup { showEditKeys = true }
                            if model.selectedProfile?.mode == .binding {
                                BindingSection { showAddHostKey = true }
                            }
                            CheckResultView()
                        }
                        .padding(20)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                } else {
                    VStack(alignment: .leading, spacing: 0) {
                        BlockingErrors().padding(20)
                        Spacer()
                        Text("Choose a server.")
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity)
                        Spacer()
                    }
                }
                Divider()
                BottomBar()
            }
        }
        .frame(minWidth: 640, minHeight: 460)
        // Task 4 supplies the sheet views.
        .sheet(isPresented: $showEditKeys) { Text("…").padding(40) }
        .sheet(isPresented: $showProtection) { Text("…").padding(40) }
        .sheet(isPresented: $showAddHostKey) { Text("…").padding(40) }
        .sheet(isPresented: $showAddServer) { Text("…").padding(40) }
    }
}

private struct Sidebar: View {
    @EnvironmentObject var model: AppModel
    @Binding var showAddServer: Bool

    /// Only a real choice is written back. The list writes nil when it appears before the
    /// servers load or when the search filters the selection out; such a write would erase the
    /// remembered server (AppModel.selectedServer's didSet). The detail stays on the selection.
    /// ponytail: this also ignores a ⌘-click deselect; nothing needs "no selection" by hand.
    private var selection: Binding<HostInput?> {
        Binding(
            get: { model.selectedServer },
            set: { if let s = $0, s != model.selectedServer { model.selectedServer = s } })
    }

    var body: some View {
        List(model.filteredServers, id: \.self, selection: selection) { server in
            Text(server.value).lineLimit(1).truncationMode(.middle)
        }
        .listStyle(.sidebar)
        .searchable(text: $model.serverQuery, placement: .sidebar)
        .safeAreaInset(edge: .bottom, spacing: 0) {
            VStack(alignment: .leading, spacing: 8) {
                if !model.discovery.skippedIncludes.isEmpty {
                    Text("Include not read: \(model.discovery.skippedIncludes.joined(separator: ", "))")
                        .font(.caption).foregroundStyle(.secondary).lineLimit(2).truncationMode(.tail)
                        .help(model.discovery.skippedIncludes.joined(separator: "\n"))
                }
                Button("+ Add Server") { showAddServer = true }
                    .buttonStyle(.borderless)
                    .disabled(model.storeError != nil)
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

private struct BottomBar: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        HStack(spacing: 12) {
            if case .running = model.checkState {
                ProgressView().controlSize(.small)
            }
            Text(status)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 12)
            Button(hasResult ? "Check Again" : "Check Connection") { Task { await model.runCheck() } }
                .disabled(isRunning || model.inputsProblem != nil)
            Button("Connect in Terminal") { Task { await model.connect() } }
                .keyboardShortcut(.defaultAction)
                .disabled(!model.canConnect)
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 12)
    }

    private var isRunning: Bool {
        if case .running = model.checkState { return true }
        return false
    }

    private var hasResult: Bool {
        if case .finished = model.checkState { return true }
        return false
    }

    private var status: String {
        if let problem = model.inputsProblem { return problem }
        switch model.checkState {
        case .running(let step): return step == .waitingForAgent ? "Waiting for agent…" : "Checking…"
        case .finished(let result) where !result.passed: return "Fix the problem above, then check again."
        // A pass that no longer opens the gate is not shown, so it reads as unchecked.
        case .finished where model.canConnect: return ""
        case .idle, .finished: return "Check before connecting."
        }
    }
}

extension View {
    /// A System Settings style group: plain background, hairline border, 8 pt corners.
    func groupBox() -> some View {
        background(.background, in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Color(nsColor: .separatorColor)))
    }
}

func copyToPasteboard(_ text: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(text, forType: .string)
}
