import Foundation
import SigSieveKit

/// The whole window state. Every decision about safety stays in the CLI; this
/// model only gathers inputs, runs the Kit and keeps the check-to-connect gate.
@MainActor
final class AppModel: ObservableObject {
    enum CheckStep: Equatable { case checking, waitingForAgent }

    enum CheckState: Equatable {
        case idle
        case running(CheckStep)
        case finished(CheckResult)
    }

    @Published private(set) var cli: Result<CLIInfo, CLIError>?
    @Published private(set) var tmpdir: Result<String, TempDirError> = .failure(.unavailable)
    @Published private(set) var agentState: AgentState = .unreachable("not asked yet")
    @Published private(set) var discovery: AliasDiscovery
    @Published private(set) var knownHosts: [KnownHostEntry] = []
    /// Set when a picker Add was refused because the files behind the list changed.
    @Published private(set) var knownHostsError: String?
    /// `knownHostsStamps` taken just before `knownHosts` was read; an Add compares them with now.
    private var knownHostsLoadedStamps: [FileStamp] = []
    @Published private(set) var profiles: [Profile] = []
    @Published var selectedServer: HostInput? {
        didSet {
            if let v = selectedServer?.value { defaults.set(v, forKey: Self.selectedServerKey) } else { defaults.removeObject(forKey: Self.selectedServerKey) }
            if oldValue != selectedServer { inputsChanged(agentMayDiffer: true) }
        }
    }
    @Published var keyQuery = ""
    @Published var serverQuery = ""
    @Published private(set) var checkState: CheckState = .idle
    /// When the last check finished; nil whenever the check is idle.
    @Published private(set) var checkFinishedAt: Date?
    @Published private(set) var storeError: ProfileStoreError?
    /// A refused CLI path setting (ruling 1). The refused text is never used.
    @Published private(set) var cliPathError: String?
    @Published private(set) var connectError: String?
    /// Settings, persisted in UserDefaults.
    @Published private(set) var defaultAgent: AgentChoice
    @Published private(set) var cliPathSetting: String

    let store = ProfileStore(directory: ProfileStore.defaultDirectory)
    private let runner = ProcessRunner()
    private let defaults = UserDefaults.standard
    private let home = FileManager.default.homeDirectoryForCurrentUser.path
    private var verifiedTmp: VerifiedTempDir?
    private var gate = CheckGate()
    /// Inputs of the last check, and whether the root ssh config existed then (ruling 2).
    private var checked: (inputs: CheckInputs, rootExisted: Bool)?
    private var checkTask: Task<Void, Never>?
    private var waitingTask: Task<Void, Never>?
    private var removedStale = false
    private var refreshing = false
    private var restoredSelection = false
    /// Which forwarded keys were in the agent when the last check started.
    private var checkedKeyPresence: Set<Fingerprint>?

    private static let agentKey = "defaultAgent"
    private static let cliPathKey = "cliPath"
    static let selectedServerKey = "selectedServer"

    init() {
        let stored = defaults.data(forKey: Self.agentKey).flatMap { try? JSONDecoder().decode(AgentChoice.self, from: $0) }
        defaultAgent = stored ?? Self.appAgent
        // A stored value that is not usable is kept and blocks (see cliSettingProblem),
        // never silently replaced by another binary (rulings 1 and 3).
        cliPathSetting = defaults.string(forKey: Self.cliPathKey) ?? ""
        discovery = Self.discover(home: home)
        // Launch-time work (stale launcher cleanup, the icon's error badge) must not wait for the window.
        Task { await self.refresh() }
    }

    /// The saved CLI path is unusable (only possible if edited outside the app).
    var cliSettingProblem: String? { Self.cliPathProblem(cliPathSetting).map { "Saved CLI path \"\(cliPathSetting)\": \($0)" } }

    /// The app's own `SSH_AUTH_SOCK` as an OpenSSH agent, else Secretive.
    static var appAgent: AgentChoice {
        if let s = ProcessInfo.processInfo.environment["SSH_AUTH_SOCK"], isUsableSocket(s) { return .openssh(socket: s) }
        return .secretive
    }

    // MARK: Derived state

    var rootConfig: URL { URL(filePath: home).appending(path: ".ssh/config") }
    /// Files the picker reads besides ~/.ssh/known_hosts; only their @revoked lines count.
    var revocationFiles: [String] { ["/etc/ssh/ssh_known_hosts", "/etc/ssh/ssh_known_hosts2", home + "/.ssh/known_hosts2"] }
    /// Every file the picker reads. A change to any of them invalidates a passed check.
    var knownHostsStamps: [FileStamp] {
        SSHConfigAliases.stamps(for: [knownHostsFile.path] + revocationFiles)
    }
    var knownHostsFile: URL { URL(filePath: home).appending(path: ".ssh/known_hosts") }

    var servers: [HostInput] {
        var seen = Set<HostInput>(), all: [HostInput] = []
        for s in discovery.aliases + profiles.map(\.server) where seen.insert(s).inserted { all.append(s) }
        return all
    }

    var filteredServers: [HostInput] {
        let q = serverQuery.lowercased()
        return q.isEmpty ? servers : servers.filter { $0.value.lowercased().contains(q) }
    }

    var agentKeys: [AgentKey] {
        if case .keys(let k) = agentState { return k }
        return []
    }

    var filteredKeys: [AgentKey] { KeyFilter.filter(agentKeys, query: keyQuery) }

    /// The saved profile, or the empty one a server without a profile has: no key forwarded.
    var selectedProfile: Profile? {
        guard let s = selectedServer else { return nil }
        return profiles.first { $0.server == s } ?? .empty(for: s, agent: defaultAgent)
    }

    func agentName(for agent: AgentChoice) -> String {
        switch agent {
        case .secretive: "Secretive"
        case .openssh(let socket): "OpenSSH agent (\(socket))"
        }
    }

    /// The selected server's agent, else the default one.
    var agentName: String { agentName(for: selectedProfile?.agent ?? defaultAgent) }

    var canEdit: Bool { storeError == nil && selectedServer != nil }

    var hasBlockingError: Bool {
        if case .failure = cli { return true }
        if case .failure = tmpdir { return true }
        return storeError != nil || cliSettingProblem != nil
    }

    /// Why Check is disabled, in plain words; nil when it can run.
    var inputsProblem: String? {
        if storeError != nil { return "The profiles file cannot be used." }
        if let p = cliSettingProblem { return p }
        guard case .success = cli else { return "The SigSieve CLI is not available." }
        if verifiedTmp == nil { return "The temporary directory failed verification." }
        guard let p = selectedProfile else { return "Choose a server." }
        if p.forwardedKeys.isEmpty { return "Choose at least one key to forward." }
        if let problem = p.policyProblem { return problem }
        if currentInputs == nil { return "The agent socket or CLI location cannot be used." }
        return nil
    }

    /// nil when the CLI or TMPDIR is in error, the profiles file is unusable,
    /// no server is selected, no key is forwarded, or the profile has a
    /// `policyProblem` (binding without a host key is never downgraded).
    var currentInputs: CheckInputs? {
        guard storeError == nil, case .success(let info) = cli, let tmp = verifiedTmp,
              let profile = selectedProfile, !profile.forwardedKeys.isEmpty,
              profile.policyProblem == nil,
              let env = try? ChildEnvironment.make(home: home, cliDirectory: Self.directory(of: info),
                                                   tmpdir: tmp, agent: profile.agent)
        else { return nil }
        return CheckInputs(profile: profile, cli: info, environment: env, configStamps: discovery.stamps + knownHostsStamps)
    }

    /// Also requires a finished check: after a reset the gate stays closed
    /// even if the inputs change back to what was checked.
    var canConnect: Bool {
        guard case .finished = checkState, let i = currentInputs else { return false }
        return gate.canConnect(i)
    }

    /// Only for a passed check of exactly the current inputs.
    var copyableCommand: String? {
        guard case .finished(let r) = checkState, r.passed, canConnect, let i = currentInputs else { return nil }
        return CommandBuilder.copyableCommand(i.profile, cli: i.cli, environment: i.environment)
    }

    // MARK: Refresh

    /// When the window opens: TMPDIR, profiles, CLI, SSH config, agent keys, known_hosts.
    func refresh() async {
        // ponytail: overlapping refreshes (launch + window open) are dropped, not queued.
        guard !refreshing else { return }
        refreshing = true
        defer { refreshing = false }
        verifyTmpdir()
        if !removedStale, let tmp = verifiedTmp {
            removedStale = true
            Launcher.removeStale(under: tmp.path)
        }
        loadProfiles()
        rediscover()
        await locateCLI()
        await refreshAgent()
        if !(await reloadKnownHostsIfChanged()) { await loadKnownHosts() }
        if !restoredSelection {
            restoredSelection = true
            if selectedServer == nil {
                if let stored = defaults.string(forKey: Self.selectedServerKey), let host = HostInput(stored), servers.contains(host) {
                    selectedServer = host
                }
            }
        }
        inputsChanged()
    }

    private func verifyTmpdir() {
        do {
            let v = try TempDir.verified(TempDir.system())
            verifiedTmp = v
            tmpdir = .success(v.path)
        } catch let e as TempDirError {
            verifiedTmp = nil
            tmpdir = .failure(e)
        } catch {
            verifiedTmp = nil
            tmpdir = .failure(.unavailable)
        }
    }

    private func loadProfiles() {
        do {
            profiles = try store.load()
            storeError = nil
        } catch {
            profiles = []
            storeError = Self.storeError(error)
        }
    }

    private func rediscover() { discovery = Self.discover(home: home) }

    private static func discover(home: String) -> AliasDiscovery {
        let h = URL(filePath: home)
        return SSHConfigAliases.discover(config: h.appending(path: ".ssh/config"), home: h)
    }

    private func locateCLI() async {
        guard cliSettingProblem == nil, let tmp = verifiedTmp,
              let fallback = try? ChildEnvironment.make(home: home, cliDirectory: "/usr/bin", tmpdir: tmp, agent: .secretive)
        else { cli = nil; return }
        let home = self.home
        let locator = CLILocator(runner: runner, userPath: cliPathSetting.isEmpty ? nil : cliPathSetting,
                                 appPATH: ProcessInfo.processInfo.environment["PATH"])
        do {
            // `--version` needs no agent; the environment shape is the same as for checks.
            let info = try await locator.locate { @Sendable url in
                (try? ChildEnvironment.make(home: home, cliDirectory: (url.path(percentEncoded: false) as NSString).deletingLastPathComponent,
                                            tmpdir: tmp, agent: .secretive)) ?? fallback
            }
            cli = .success(info)
        } catch let e as CLIError {
            cli = .failure(e)
        } catch {
            cli = .failure(.notFound(searched: []))
        }
    }

    private func refreshAgent() async {
        guard let tmp = verifiedTmp else { agentState = .unreachable("the temporary directory failed verification"); return }
        let agent = selectedProfile?.agent ?? defaultAgent
        do {
            let env = try ChildEnvironment.make(home: home, cliDirectory: "/usr/bin", tmpdir: tmp, agent: agent)
            let state = await AgentKeys.list(runner: runner, environment: env)
            // A slower answer for an agent that is no longer selected must not overwrite the current one.
            if agent == (selectedProfile?.agent ?? defaultAgent) {
                agentState = state
                if checkState != .idle, let p = checkedKeyPresence,
                   ForwardedKeys.present(forwarded: selectedProfile?.forwardedKeys ?? [], agentKeys: agentKeys) != p { resetCheck() }
            }
        } catch {
            agentState = .unreachable("the agent socket \(agent.socketPath(home: home)) cannot be used")
        }
    }

    private func loadKnownHosts() async {
        // Stamped before reading, and stored with the list it describes, so a change during the
        // read is caught at the next Add.
        let stamps = knownHostsStamps
        guard let tmp = verifiedTmp,
              let env = try? ChildEnvironment.make(home: home, cliDirectory: "/usr/bin", tmpdir: tmp, agent: .secretive)
        else { knownHosts = []; knownHostsLoadedStamps = stamps; return }
        let list = await KnownHosts.entries(file: knownHostsFile, revocationFiles: revocationFiles.map { URL(filePath: $0) },
                                            runner: runner, environment: env)
        knownHosts = list
        knownHostsLoadedStamps = stamps
    }

    /// When a file behind the picker changed since the list was loaded (a key may have been
    /// revoked), a passed check is reset at once (its result and Connect disappear) and the list
    /// is reloaded. Returns whether that happened. connect() also re-compares the stamps.
    private func reloadKnownHostsIfChanged() async -> Bool {
        guard knownHostsStamps != knownHostsLoadedStamps else { return false }
        resetCheck()
        await loadKnownHosts()
        return true
    }

    /// A picker Add. The list is only loaded on refresh, so if any file behind it changed since,
    /// the check is reset, the list reloaded and the Add refused.
    func addKnownHost(_ entry: KnownHostEntry) async {
        let changed = await reloadKnownHostsIfChanged()
        guard !changed, knownHosts.contains(entry) else {
            knownHostsError = "known_hosts changed. The list was reloaded; pick again."
            return
        }
        knownHostsError = nil
        addDestination(Destination(name: entry.name ?? entry.fingerprint.short, hostKeys: [entry.fingerprint]))
    }

    // MARK: Gate bookkeeping

    private var rootConfigExists: Bool { FileManager.default.fileExists(atPath: rootConfig.path) }

    /// True when a file the last check depended on changed size or time, or
    /// the root config appeared or disappeared since (ruling 2).
    private func sshConfigChanged() -> Bool {
        guard let c = checked else { return false }
        let stamps = c.inputs.configStamps
        return SSHConfigAliases.currentStamps(for: stamps) != stamps || rootConfigExists != c.rootExisted
    }

    /// Any input change returns the check to idle; the old result and the
    /// copyable command are no longer shown.
    private func inputsChanged(agentMayDiffer: Bool = false) {
        if checkState != .idle, currentInputs != checked?.inputs || sshConfigChanged() {
            resetCheck()
        }
        if agentMayDiffer { Task { await refreshAgent() } }
    }

    private func resetCheck() {
        checkTask?.cancel()
        checkTask = nil
        waitingTask?.cancel()
        waitingTask = nil
        checkState = .idle
        checkFinishedAt = nil
        checkedKeyPresence = nil
        gate = CheckGate()
    }

    // MARK: Check and connect

    func runCheck() async {
        connectError = nil
        verifyTmpdir()  // ruling 6: re-verified before each check
        rediscover()
        inputsChanged()
        guard let inputs = currentInputs else { checkState = .idle; checkFinishedAt = nil; return }
        resetCheck()
        checked = (inputs, rootConfigExists)
        checkedKeyPresence = ForwardedKeys.present(forwarded: inputs.profile.forwardedKeys, agentKeys: agentKeys)
        checkState = .running(.checking)
        let runner = self.runner
        waitingTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(2))
            guard !Task.isCancelled, let self, self.checkState == .running(.checking) else { return }
            self.checkState = .running(.waitingForAgent)
        }
        let task = Task { [weak self] in
            let result = await ConnectionCheck.run(inputs, runner: runner)
            guard let self, !Task.isCancelled else { return }
            self.waitingTask?.cancel()
            self.waitingTask = nil
            self.gate.record(result, for: inputs)
            // A result for inputs that are no longer current is never shown.
            if self.currentInputs == inputs, !self.sshConfigChanged() {
                self.checkState = .finished(result)
                self.checkFinishedAt = Date()
            } else {
                self.checkState = .idle
                self.checkFinishedAt = nil
            }
            self.checkTask = nil
        }
        checkTask = task
        await task.value
    }

    /// Ruling 7: re-read the current inputs; launch only when the gate is open for them.
    func connect() async {
        connectError = nil
        verifyTmpdir()
        await refreshAgent()
        if sshConfigChanged() {
            rediscover()
            resetCheck()
            connectError = "SSH configuration changed since the check. Check again."
            return
        }
        inputsChanged()
        guard canConnect, var inputs = currentInputs, var tmp = verifiedTmp else {
            resetCheck()
            return
        }
        if discovery.untracked {
            // Some file ssh may read has no stamp, so a change there would not have closed the
            // gate: run the whole check again for these inputs and launch only if that passes.
            checkState = .running(.checking)
            var recheckGate = gate
            let passed = await ConnectionCheck.recheckBeforeConnect(inputs, runner: runner, gate: &recheckGate)
            verifyTmpdir()
            guard let now = currentInputs, now == inputs, !sshConfigChanged(), let nowTmp = verifiedTmp else {
                // A check the user started meanwhile is left alone; this stale re-check only stops.
                if checkTask == nil {
                    resetCheck()
                    connectError = "The inputs changed during the check before connecting. Check again."
                }
                return
            }
            gate = recheckGate
            if let result = recheckGate.result { checkState = .finished(result); checkFinishedAt = Date() }
            guard passed else { return }
            inputs = now
            tmp = nowTmp
        }
        do {
            let script = try Launcher.write(inputs, under: tmp.path)
            try await Launcher.open(script)
        } catch {
            connectError = "\(error)"
        }
    }

    // MARK: Profile edits (saved immediately)

    func toggleKey(_ fp: Fingerprint) {
        edit { p in
            if let i = p.forwardedKeys.firstIndex(of: fp) { p.forwardedKeys.remove(at: i) } else { p.forwardedKeys.append(fp) }
        }
    }

    func setMode(_ mode: ProtectionMode) { edit { $0.mode = mode } }

    /// The forwarded-key rows for the selected server: agent keys, then saved keys the agent lacks.
    var forwardedRows: [ForwardedKeyRow] {
        ForwardedKeys.rows(forwarded: selectedProfile?.forwardedKeys ?? [], agentKeys: agentKeys)
    }

    /// A draft started for one server is never applied to another.
    @discardableResult
    func setForwardedKeys(selection: Set<Fingerprint>, for server: HostInput) -> Bool {
        guard selectedServer == server else { return false }
        edit { $0.forwardedKeys = ForwardedKeys.applying(selection: selection, to: $0.forwardedKeys, agentKeys: agentKeys) }
        return true
    }

    @discardableResult
    func setMode(_ mode: ProtectionMode, for server: HostInput) -> Bool {
        guard selectedServer == server else { return false }
        setMode(mode)
        return true
    }

    func setAgent(_ agent: AgentChoice) {
        edit { $0.agent = agent }
        Task { await refreshAgent() }
    }

    func addDestination(_ d: Destination) {
        edit { p in
            if let i = p.destinations.firstIndex(where: { $0.name == d.name }) {
                for k in d.hostKeys where !p.destinations[i].hostKeys.contains(k) { p.destinations[i].hostKeys.append(k) }
            } else {
                p.destinations.append(d)
            }
        }
    }

    func removeDestination(_ d: Destination) { edit { $0.destinations.removeAll { $0 == d } } }

    func removeHostKey(_ fp: Fingerprint) {
        edit { p in
            for i in p.destinations.indices { p.destinations[i].hostKeys.removeAll { $0 == fp } }
            p.destinations.removeAll { $0.hostKeys.isEmpty }
        }
    }

    /// Adds a server discovery did not find, as an empty profile (no key forwarded), and selects it.
    func addServer(_ text: String) -> Bool {
        guard storeError == nil, let host = HostInput(text) else { return false }
        if !profiles.contains(where: { $0.server == host }) {
            guard save(profiles + [.empty(for: host, agent: defaultAgent)]) else { return false }
        }
        selectedServer = host
        return true
    }

    private func edit(_ change: (inout Profile) -> Void) {
        guard canEdit, var p = selectedProfile else { return }
        change(&p)
        var next = profiles
        if let i = next.firstIndex(where: { $0.server == p.server }) { next[i] = p } else { next.append(p) }
        _ = save(next)
    }

    /// On failure the in-memory list stays as last saved and edits are disabled.
    private func save(_ next: [Profile]) -> Bool {
        do {
            try store.save(next)
            profiles = next
            inputsChanged()
            return true
        } catch {
            storeError = Self.storeError(error)
            inputsChanged()
            return false
        }
    }

    // MARK: Settings

    /// false (and nothing changes) for an OpenSSH socket that is empty or not absolute.
    @discardableResult
    func setDefaultAgent(_ agent: AgentChoice) -> Bool {
        if case .openssh(let s) = agent, !Self.isUsableSocket(s) { return false }
        defaultAgent = agent
        if let data = try? JSONEncoder().encode(agent) { defaults.set(data, forKey: Self.agentKey) }
        inputsChanged(agentMayDiffer: true)
        return true
    }

    /// Ruling 1: only an absolute path is accepted; empty means "not set".
    /// A refused entry is shown as an error and the stored setting is kept.
    @discardableResult
    func setCLIPath(_ path: String) async -> Bool {
        if let problem = Self.cliPathProblem(path) {
            cliPathError = problem
            return false
        }
        cliPathError = nil
        cliPathSetting = path
        defaults.set(path, forKey: Self.cliPathKey)
        // The old CLI must not stay usable while the new setting is resolved.
        cli = nil
        resetCheck()
        verifyTmpdir()
        await locateCLI()
        inputsChanged()
        return true
    }

    static func cliPathProblem(_ path: String) -> String? {
        if path.isEmpty { return nil }
        guard path.hasPrefix("/") else { return "The CLI path must be absolute (start with /)." }
        guard !path.unicodeScalars.contains(where: {
            $0.properties.generalCategory == .control || $0.properties.generalCategory == .format
        }) else { return "The CLI path contains control characters." }
        return nil
    }

    static func isUsableSocket(_ s: String) -> Bool {
        s.count > 1 && s.hasPrefix("/") && !s.unicodeScalars.contains {
            $0.properties.generalCategory == .control || $0.properties.generalCategory == .format
        }
    }

    // MARK: Helpers

    private static func directory(of cli: CLIInfo) -> String {
        (cli.path.path(percentEncoded: false) as NSString).deletingLastPathComponent
    }

    private static func storeError(_ error: Error) -> ProfileStoreError {
        error as? ProfileStoreError ?? .writeFailed("\(error)")
    }
}
