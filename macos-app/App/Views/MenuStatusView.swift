import AppKit
import SwiftUI

/// The menu bar panel: the selected server and its check state, the first blocking error,
/// and the ways to the windows. It shows state only; it never checks or connects.
struct MenuStatusView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                if let server = model.selectedServer {
                    Text(server.value)
                        .font(.headline)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    checkState.foregroundStyle(.secondary)
                } else {
                    Text("No server selected").foregroundStyle(.secondary)
                }
            }
            if let error = StatusText.blockingErrors(model).first {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.red)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .help(error)
            }
            Divider()
            Button("Open SigSieve") {
                openWindow(id: "main")
                if let window = MainWindowRef.window {
                    if window.isMiniaturized { window.deminiaturize(nil) }
                    window.makeKeyAndOrderFront(nil)
                }
                NSApp.activate(ignoringOtherApps: true)
                // A window that is already key does not become key again, so refresh here too.
                Task { await model.refresh() }
            }
            .keyboardShortcut(.defaultAction)
            .frame(maxWidth: .infinity, alignment: .leading)
            HStack {
                Button("Settings…") {
                    openWindow(id: "settings")
                    // Activation only; the Dock state belongs to the main window.
                    NSApp.activate(ignoringOtherApps: true)
                }
                Spacer()
                Button("Quit SigSieve") { NSApp.terminate(nil) }
            }
        }
        .padding(12)
        .frame(width: 260)
        // Fresh state while the main window is closed. Reading only; never a check.
        // onAppear may not fire on every reopen of a .window panel; becoming key does.
        .onAppear { Task { await model.refresh() } }
        .background(WindowEvents(onBecomeKey: { Task { await model.refresh() } }))
    }

    @ViewBuilder private var checkState: some View {
        if model.canConnect {
            Text("Check passed\(passedTime)")
        } else {
            switch model.checkState {
            case .running: Text("Checking…")
            case .finished(let result) where !result.passed: Text("Check failed")
            case .idle, .finished: Text("Not checked")
            }
        }
    }

    /// " · HH:mm" for a finished check, as in the detail pane.
    private var passedTime: String {
        guard case .finished = model.checkState, let time = model.checkFinishedAt else { return "" }
        return " · \(time.formatted(date: .omitted, time: .shortened))"
    }
}
