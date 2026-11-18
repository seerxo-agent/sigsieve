import AppKit
import SigSieveKit
import SwiftUI

/// Default agent, optional CLI path, and what was resolved.
struct SettingsView: View {
    @EnvironmentObject var model: AppModel
    @State private var cliPath = ""
    @State private var socket = ""
    @State private var socketError: String?
    /// What the picker shows; separate from the model so choosing OpenSSH can reveal the socket row without saving.
    @State private var agentKind = AgentKind.secretive

    private enum AgentKind { case secretive, openssh }

    private enum Pane: String, CaseIterable, Identifiable {
        case agent = "Agent", commandLine = "Command Line", files = "Files"
        var id: Self { self }
        var symbol: String {
            switch self {
            case .agent: "key.fill"
            case .commandLine: "terminal.fill"
            case .files: "doc.fill"
            }
        }
        var tint: Color {
            switch self {
            case .agent: .blue
            case .commandLine: .gray
            case .files: .orange
            }
        }
    }

    @State private var pane = Pane.agent
    /// The hidden title bar's top safe-area inset, measured. The window adds it to the content's height.
    @State private var titleBarInset: CGFloat = 0

    var body: some View {
        HStack(alignment: .top, spacing: 0) {
            sidebar
            VStack(alignment: .leading, spacing: 0) {
                // One small title on the traffic-light band, as in System Settings.
                Text(pane.rawValue).font(.points(15, .semibold))
                    .frame(height: 52)
                    .padding(.horizontal, 20)
                VStack(alignment: .leading, spacing: 0) {
                    switch pane {
                    case .agent: agentPane
                    case .commandLine: commandLinePane
                    case .files: filesPane
                    }
                }
                .padding(.horizontal, 20).padding(.top, 4).padding(.bottom, 20)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(minWidth: 600, idealWidth: 640, maxWidth: 820)
        // Short panes still fit the three sidebar items with normal bottom padding.
        .frame(minHeight: 220, alignment: .top)
        // The window is exactly as tall as the current pane; switching panes may change it.
        .fixedSize(horizontal: false, vertical: true)
        .background(alignment: .leading) {
            // Full-height sidebar material behind the traffic lights; no separate title-bar strip.
            HStack(spacing: 0) {
                SidebarMaterial().frame(width: 200)
                Divider()
                Color(nsColor: .controlBackgroundColor)
            }
            .ignoresSafeArea()
        }
        // Lay out inside the safe area, so the window (content + inset) ends at the content's bottom,
        // then draw up under the traffic lights. Ignoring the safe area here instead leaves an empty
        // inset-tall band at the bottom of the window.
        .padding(.top, -titleBarInset)
        .background(GeometryReader { proxy in
            Color.clear
                .onAppear { titleBarInset = proxy.safeAreaInsets.top }
                .onChange(of: proxy.safeAreaInsets.top) { titleBarInset = $0 }
        })
        .onAppear {
            cliPath = model.cliPathSetting
            if case .openssh(let s) = model.defaultAgent { socket = s; agentKind = .openssh }
            else {
                agentKind = .secretive
                if case .openssh(let s) = AppModel.appAgent { socket = s }
            }
        }
        .onChange(of: agentKind) { kind in
            // Secretive applies at once (unless already the default); OpenSSH only reveals the socket row.
            if kind == .secretive, model.defaultAgent != .secretive { useAgent(.secretive) }
        }
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 1) {
            ForEach(Pane.allCases) { p in
                let selected = p == pane
                Button { pane = p } label: {
                    HStack(spacing: 9) {
                        Image(systemName: p.symbol)
                            .font(.points(12, .semibold))
                            .foregroundStyle(.white)
                            .frame(width: 22, height: 22)
                            .background(p.tint.gradient, in: RoundedRectangle(cornerRadius: 6))
                        Text(p.rawValue)
                    }
                    .padding(.vertical, 5).padding(.horizontal, 8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .foregroundStyle(selected ? Color.white : Color.primary)
                    .background(selected ? Color.accentColor : Color.clear, in: RoundedRectangle(cornerRadius: 7))
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
        }
        // Items start below the traffic lights.
        .padding(.top, 46).padding(.horizontal, 10).padding(.bottom, 14)
        .frame(width: 200)
    }

    @ViewBuilder private var agentPane: some View {
        caption("Default agent for new servers")
        card {
            row("Agent") {
                Picker("Agent", selection: $agentKind) {
                    Text("Secretive").tag(AgentKind.secretive)
                    Text("OpenSSH agent").tag(AgentKind.openssh)
                }
                .labelsHidden()
                .pickerStyle(.menu)
                .frame(width: 150)
            }
            if agentKind == .openssh {
                Divider()
                row("Socket") {
                    TextField("Socket", text: $socket)
                        .labelsHidden()
                        .textFieldStyle(.roundedBorder)
                        .font(.mono(12))
                        .frame(maxWidth: 300)
                    Button("Use") { useAgent(.openssh(socket: socket)) }
                }
                if model.defaultAgent != .openssh(socket: socket) {
                    note(Text("Not saved yet. The default agent is still \(model.agentName(for: model.defaultAgent)).")
                        .foregroundColor(.orange))
                }
                if let socketError {
                    note(Text(socketError).foregroundColor(.red))
                }
            }
        }
        footer("Existing servers keep their own agent.")
    }

    @ViewBuilder private var commandLinePane: some View {
        caption("SigSieve CLI")
        card {
            row("Path") {
                TextField("Path", text: $cliPath, prompt: Text("Found automatically when empty"))
                    .labelsHidden()
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 300)
                Button("Save") { Task { await model.setCLIPath(cliPath) } }
            }
            if let error = model.cliPathError {
                note(Text(error).foregroundColor(.red))
            }
            Divider()
            switch model.cli {
            case .success(let info):
                valueRow("CLI", (info.path.path(percentEncoded: false) as NSString).abbreviatingWithTildeInPath,
                         help: info.path.path(percentEncoded: false))
                Divider()
                valueRow("Version", info.version)
            case .failure(let e):
                valueRow("CLI", StatusText.describe(e))
            case nil:
                valueRow("CLI", "not resolved")
            }
        }
        footer("Path is optional and must be absolute.")
    }

    @ViewBuilder private var filesPane: some View {
        let path = model.store.file.path
        card {
            VStack(alignment: .leading, spacing: 2) {
                Text("Profiles file")
                // A path shown with the home directory as `~`; the full path is the tooltip.
                Text((path as NSString).abbreviatingWithTildeInPath)
                    .font(.mono(11.5)).foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .help(path)
            }
            .frame(maxWidth: .infinity, minHeight: 38, alignment: .leading)
            .padding(.horizontal, 12).padding(.vertical, 8)
        }
    }

    private func useAgent(_ agent: AgentChoice) {
        if model.setDefaultAgent(agent) {
            socketError = nil
        } else {
            socketError = socket.isEmpty
                ? "Enter the agent socket path to use the OpenSSH agent. The default agent is unchanged."
                : "The agent socket must be an absolute path (starting with /) without control characters. The default agent is unchanged."
        }
    }

    private func caption(_ text: String) -> some View {
        Text(text).font(.points(12, .semibold)).foregroundStyle(.secondary)
            .padding(.horizontal, 6).padding(.top, 2).padding(.bottom, 6)
    }

    private func footer(_ text: String) -> some View {
        Text(text).font(.points(11.5)).foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.horizontal, 6).padding(.top, 6)
    }

    /// A grouped card: rows on a rounded 10 pt fill with a hairline border; callers put a Divider between rows.
    private func card<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 0) { content() }
            .background(Color.primary.opacity(0.04), in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.primary.opacity(0.08)))
    }

    /// One line: label left, control or value right. The content wins the width; the label never squeezes.
    private func row<Content: View>(_ label: String, @ViewBuilder _ content: () -> Content) -> some View {
        HStack(spacing: 8) {
            Text(label).fixedSize()
            Spacer(minLength: 12)
            HStack(spacing: 8) { content() }.layoutPriority(1)
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .frame(minHeight: 38)
    }

    /// Text under a row inside the card (unsaved caption, errors): full text, wraps, never truncates.
    private func note(_ text: Text) -> some View {
        text.font(.points(11.5))
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 12).padding(.bottom, 9)
    }

    /// Read-only value that wraps rather than truncates: the CLI path says which executable runs.
    private func valueRow(_ label: String, _ value: String, help: String? = nil) -> some View {
        row(label) {
            Text(value).font(.mono(12)).foregroundStyle(.secondary).textSelection(.enabled)
                .multilineTextAlignment(.trailing)
                .fixedSize(horizontal: false, vertical: true)
                .help(help ?? value)
        }
    }
}

extension Font {
    /// An exact point size. Spelled through NSFont so App sources never contain the libc call text the source rules forbid.
    static func points(_ size: CGFloat, _ weight: NSFont.Weight = .regular) -> Font {
        Font(NSFont.systemFont(ofSize: size, weight: weight) as CTFont)
    }

    static func mono(_ size: CGFloat) -> Font {
        Font(NSFont.monospacedSystemFont(ofSize: size, weight: .regular) as CTFont)
    }
}

/// The translucent sidebar material, behind the window, as in System Settings.
private struct SidebarMaterial: NSViewRepresentable {
    func makeNSView(context: Context) -> NSVisualEffectView {
        let view = NSVisualEffectView()
        view.material = .sidebar
        view.blendingMode = .behindWindow
        view.state = .followsWindowActiveState
        return view
    }

    func updateNSView(_ view: NSVisualEffectView, context: Context) {}
}
