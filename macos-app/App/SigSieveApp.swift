import AppKit
import SwiftUI

@main
struct SigSieveApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        // The first scene opens at launch.
        Window("SigSieve", id: "main") {
            MainWindow()
                .environmentObject(model)
        }
        .defaultSize(width: 820, height: 600)
        .commands {
            CommandGroup(replacing: .appSettings) { SettingsCommand() }
        }

        // A Window, not a Settings scene: opening that one needs SettingsLink (macOS 14).
        Window("Settings", id: "settings") {
            SettingsView()
                .environmentObject(model)
        }
        // No title-bar strip; the window takes its size from SettingsView (height fits the pane).
        .windowStyle(.hiddenTitleBar)
        .windowResizability(.contentSize)

        MenuBarExtra {
            MenuStatusView()
                .environmentObject(model)
        } label: {
            Image(nsImage: MenuBarIcon.image(error: model.hasBlockingError))
                .accessibilityLabel(model.hasBlockingError ? "SigSieve, needs attention" : "SigSieve")
        }
        .menuBarExtraStyle(.window)
    }
}

/// ⌘, opens the Settings window. A view, because openWindow comes from the environment.
private struct SettingsCommand: View {
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Button("Settings…") { openWindow(id: "settings") }
            .keyboardShortcut(",")
    }
}

/// `key.horizontal` as a template; for a blocking error, `key.horizontal.fill`
/// with a dot badge drawn into the same template image.
enum MenuBarIcon {
    @MainActor
    static func image(error: Bool) -> NSImage {
        let name = error ? "key.horizontal.fill" : "key.horizontal"
        guard let symbol = NSImage(systemSymbolName: name, accessibilityDescription: "SigSieve") else { return NSImage() }
        guard error else {
            symbol.isTemplate = true
            return symbol
        }
        let size = NSSize(width: symbol.size.width + 5, height: max(symbol.size.height, 16))
        let badged = NSImage(size: size, flipped: false) { rect in
            symbol.draw(in: NSRect(x: 0, y: (rect.height - symbol.size.height) / 2,
                                   width: symbol.size.width, height: symbol.size.height))
            NSColor.black.setFill()
            NSBezierPath(ovalIn: NSRect(x: rect.width - 6, y: rect.height - 6, width: 6, height: 6)).fill()
            return true
        }
        badged.isTemplate = true
        return badged
    }
}
