import AppKit
import SwiftUI

/// The menu bar panel: the selected server and its check state, the first blocking error,
/// and the ways to the windows. It shows state only; it never checks or connects.
struct MenuStatusView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                Image(nsImage: NSApp.applicationIconImage)
                    .resizable()
                    .frame(width: 32, height: 32)
                VStack(alignment: .leading, spacing: 1) {
                    if let server = model.selectedServer {
                        Text(server.value)
                            .font(.points(13.5, .semibold))
                            .lineLimit(1)
                            .truncationMode(.middle)
                        checkState
                    } else {
                        status(Dot(color: nil), "No server selected")
                    }
                }
            }
            .padding(.horizontal, 8).padding(.top, 8).padding(.bottom, 10)
            if let error = StatusText.blockingErrors(model).first {
                // Full text, wrapping: a warning is never shortened.
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(.points(11.5))
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, 8).padding(.bottom, 8)
            }
            separator
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
            .buttonStyle(MenuRowStyle(hint: "↩", prominent: true))
            .keyboardShortcut(.defaultAction)
            Button("Settings…") {
                openWindow(id: "settings")
                // Activation only; the Dock state belongs to the main window.
                NSApp.activate(ignoringOtherApps: true)
            }
            .buttonStyle(MenuRowStyle(hint: "⌘,"))
            .keyboardShortcut(",", modifiers: .command)
            separator
            Button("Quit SigSieve") { NSApp.terminate(nil) }
                .buttonStyle(MenuRowStyle(hint: "⌘Q"))
                .keyboardShortcut("q", modifiers: .command)
        }
        .padding(6)
        .frame(width: 280)
        // Fresh state while the main window is closed. Reading only; never a check.
        // onAppear may not fire on every reopen of a .window panel; becoming key does.
        .onAppear { Task { await model.refresh() } }
        .background(WindowEvents(onBecomeKey: { Task { await model.refresh() } }))
    }

    private var separator: some View {
        Divider().padding(.horizontal, 8).padding(.vertical, 4)
    }

    private func status(_ indicator: some View, _ text: String) -> some View {
        HStack(spacing: 6) {
            indicator.frame(width: 10, height: 10)
            Text(text)
        }
        .font(.callout)
        .foregroundStyle(.secondary)
    }

    @ViewBuilder private var checkState: some View {
        if model.canConnect {
            status(Dot(color: .green), "Check passed\(passedTime)")
        } else {
            switch model.checkState {
            case .running: status(ProgressView().controlSize(.small).scaleEffect(0.5), "Checking…")
            case .finished(let result) where !result.passed: status(Dot(color: .red), "Check failed")
            case .idle, .finished: status(Dot(color: nil), "Not checked")
            }
        }
    }

    /// " · HH:mm" for a finished check, as in the detail pane.
    private var passedTime: String {
        guard case .finished = model.checkState, let time = model.checkFinishedAt else { return "" }
        return " · \(time.formatted(date: .omitted, time: .shortened))"
    }
}

/// The status dot: filled in the outcome colour, or a hollow grey ring when there is no outcome.
private struct Dot: View {
    let color: Color?

    var body: some View {
        if let color {
            Circle().fill(color).frame(width: 7, height: 7)
        } else {
            Circle().strokeBorder(Color.gray, lineWidth: 1.3).frame(width: 7, height: 7)
        }
    }
}

/// A native-menu row: full width, accent fill and white text on hover, the shortcut hint trailing.
private struct MenuRowStyle: ButtonStyle {
    let hint: String
    var prominent = false

    func makeBody(configuration: Configuration) -> some View {
        MenuRow(configuration: configuration, hint: hint, prominent: prominent)
    }

    private struct MenuRow: View {
        let configuration: ButtonStyleConfiguration
        let hint: String
        let prominent: Bool
        @State private var hovering = false

        var body: some View {
            let lit = hovering || configuration.isPressed
            HStack {
                configuration.label.font(prominent ? .body.weight(.semibold) : .body)
                Spacer(minLength: 12)
                Text(hint).foregroundStyle(lit ? Color.white : Color(nsColor: .tertiaryLabelColor))
            }
            .foregroundStyle(lit ? Color.white : Color.primary)
            .padding(.vertical, 5).padding(.horizontal, 8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(lit ? Color.accentColor : Color.clear, in: RoundedRectangle(cornerRadius: 6))
            .contentShape(Rectangle())
            .onHover { hovering = $0 }
            // The panel can close mid-hover; it must not reopen highlighted.
            .onDisappear { hovering = false }
        }
    }
}
