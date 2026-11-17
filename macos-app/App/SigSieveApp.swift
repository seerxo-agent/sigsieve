import SwiftUI

@main
struct SigSieveApp: App {
    var body: some Scene {
        MenuBarExtra("SigSieve", systemImage: "key.horizontal") {
            Text("SigSieve")
                .padding()
        }
        .menuBarExtraStyle(.window)
    }
}
