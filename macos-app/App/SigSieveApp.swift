import AppKit
import SwiftUI

@main
struct SigSieveApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        MenuBarExtra {
            MenuWindow()
                .environmentObject(model)
        } label: {
            Image(nsImage: MenuBarIcon.image(error: model.hasBlockingError))
                .accessibilityLabel(model.hasBlockingError ? "SigSieve, needs attention" : "SigSieve")
        }
        .menuBarExtraStyle(.window)
    }
}

/// One window: status row, server picker, key list, Advanced, Check, footer.
struct MenuWindow: View {
    @EnvironmentObject var model: AppModel
    @State private var showSettings = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            StatusRow()
            Divider()
            if showSettings {
                SettingsView()
            } else if model.selectedServer == nil {
                ServerPicker()
            } else {
                // Fixed maximum height; the lists inside keep their own fixed heights.
                ScrollView {
                    VStack(alignment: .leading, spacing: 10) {
                        ServerPicker()
                        KeyList()
                        AdvancedSection()
                        CheckSection()
                    }
                    .padding(.trailing, 8)
                }
                .frame(height: 600)
            }
            Divider()
            FooterView(showSettings: $showSettings)
        }
        .padding(12)
        .frame(width: 380)
        .onAppear { Task { await model.refresh() } }
        // onAppear is not guaranteed to fire on every reopen of a .window MenuBarExtra;
        // its panel becomes key each time it opens. This app has no other window.
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.didBecomeKeyNotification)) { _ in
            Task { await model.refresh() }
        }
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
