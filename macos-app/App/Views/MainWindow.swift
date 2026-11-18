import AppKit
import SigSieveKit
import SwiftUI

/// The main window: servers in the sidebar, the selected server's detail, and a fixed bottom bar.
struct MainWindow: View {
    @EnvironmentObject var model: AppModel
    @State private var editKeys: SheetTarget?
    @State private var protection: SheetTarget?
    @State private var showAddHostKey = false
    @State private var showAddServer = false

    private func target() -> SheetTarget? {
        model.selectedServer.map { SheetTarget(server: $0, profile: model.profile(for: $0)) }
    }

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
                            ProtectionLine { protection = target() }
                            ForwardedKeysGroup { editKeys = target() }
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
        // Dock and ⌘Tab only while this window is open. The policy goes back on willClose of
        // this NSWindow, not on onDisappear, so a sheet, a minimise or a column swap never drops it.
        .background(WindowEvents(
            onWindow: { window in MainWindowRef.window = window },
            onBecomeKey: {
                NSApp.setActivationPolicy(.regular)
                Task { await model.refresh() }
            },
            onClose: {
                MainWindowRef.window = nil
                NSApp.setActivationPolicy(.accessory)
            }))
        .onAppear {
            NSApp.setActivationPolicy(.regular)
            NSApp.activate(ignoringOtherApps: true)
            Task { await model.refresh() }
        }
        .sheet(item: $editKeys) { EditKeysSheet(server: $0.server, profile: $0.profile) }
        .sheet(item: $protection) { ProtectionSheet(server: $0.server, profile: $0.profile) }
        .sheet(isPresented: $showAddHostKey) { AddHostKeySheet() }
        .sheet(isPresented: $showAddServer) { AddServerSheet() }
    }
}

/// The open main window, so the menu bar can bring it back when minimised. Set from the
/// captured NSWindow and cleared on its willClose, so a closed window is never reused.
@MainActor
enum MainWindowRef {
    static weak var window: NSWindow?
}

/// Calls back with the NSWindow that hosts this view, and when that window becomes key or is
/// about to close. The observers take that window as their object, so other windows (Settings,
/// the menu bar panel, sheets: each its own NSWindow) never trigger them.
struct WindowEvents: NSViewRepresentable {
    var onWindow: (NSWindow) -> Void = { _ in }
    let onBecomeKey: () -> Void
    var onClose: () -> Void = {}

    func makeNSView(context: Context) -> Observer {
        let view = Observer()
        updateNSView(view, context: context)
        return view
    }

    func updateNSView(_ view: Observer, context: Context) {
        view.onWindow = onWindow
        view.onBecomeKey = onBecomeKey
        view.onClose = onClose
    }

    final class Observer: NSView {
        var onWindow: (NSWindow) -> Void = { _ in }
        var onBecomeKey: () -> Void = {}
        var onClose: () -> Void = {}

        // Selector observers: delivered on the main thread that posts window notifications,
        // and removed automatically when this view is deallocated.
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            let center = NotificationCenter.default
            center.removeObserver(self)
            guard let window else { return }
            onWindow(window)
            center.addObserver(self, selector: #selector(becameKey), name: NSWindow.didBecomeKeyNotification, object: window)
            center.addObserver(self, selector: #selector(willClose), name: NSWindow.willCloseNotification, object: window)
        }

        /// Reports the window again: SwiftUI may reuse a closed window without moving this view.
        @objc private func becameKey(_ note: Notification) {
            if let window { onWindow(window) }
            onBecomeKey()
        }
        @objc private func willClose(_ note: Notification) { onClose() }
    }
}

/// The server and its saved profile as they were when a sheet was opened; the sheet only ever gets this one.
private struct SheetTarget: Identifiable {
    let id = UUID()
    let server: HostInput
    let profile: Profile
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
            let selected = server == model.selectedServer
            HStack(spacing: 8) {
                Text(server.value).fontWeight(selected ? .semibold : .regular)
                    .lineLimit(1).truncationMode(.middle)
                Spacer(minLength: 0)
                // Only the selected server: SigSieve keeps one check, for the selected server only.
                if selected { CheckIndicator() }
            }
            .padding(.vertical, 5).padding(.horizontal, 8)
            .listRowInsets(EdgeInsets())
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
            // 10 pt sidebar inset + the rows' 8 pt text padding, so the button lines up with the row text.
            .padding(.horizontal, 18).padding(.top, 6).padding(.bottom, 12)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

/// The current check state of the selected server, as in the menu bar: the gate first, so a
/// pass that no longer opens it reads as not checked.
private struct CheckIndicator: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        let state = self.state
        Group {
            if state.running {
                ProgressView().controlSize(.small).scaleEffect(0.6).frame(width: 10, height: 10)
            } else if let color = state.color {
                Circle().fill(color).frame(width: 8, height: 8)
            } else {
                Circle().strokeBorder(Color.gray, lineWidth: 1.3).frame(width: 8, height: 8)
            }
        }
        .help(state.text)
        .accessibilityElement()
        .accessibilityLabel(state.text)
    }

    private var state: (text: String, color: Color?, running: Bool) {
        if model.canConnect { return ("Check passed", .green, false) }
        switch model.checkState {
        case .running: return ("Checking…", nil, true)
        case .finished(let result) where !result.passed: return ("Check failed", .red, false)
        case .idle, .finished: return ("Not checked", nil, false)
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
