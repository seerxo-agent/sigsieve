# SigSieve for macOS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

Status: in review (2026-11-09). No code is written until the owner approves
this plan.

**Goal:** A SwiftUI menu bar app that builds, checks and launches
`sigsieve connect` for a per-server key profile, without typing a command.

**Architecture:** One Swift package in `macos-app/` with two targets. All
logic (validation, profiles, environment, process running, command building,
check gate) lives in the `SigSieveKit` library and is unit tested. The
`SigSieveApp` executable holds only SwiftUI views and one observable model.
Every check and every connection is the Rust CLI; the app never runs `ssh`.

**Tech Stack:** Swift 6, SwiftUI `MenuBarExtra` (`.window` style), AppKit
`NSWorkspace`, Foundation `Process`, Swift Testing (`import Testing`). No
third-party dependencies. SwiftPM only: this machine has the Command Line
Tools, not Xcode, so there is no `.xcodeproj` and no XCTest/XCUITest.

**Spec:** [`macos-app/DESIGN.md`](DESIGN.md). Read it first; this plan does
not repeat its reasoning.

## Global Constraints

- Nothing outside `macos-app/` changes, except one new file
  `.github/workflows/macos-app.yml`. `src/`, `Cargo.toml`, the release
  workflows and v1.0.0 are untouched.
- No push, PR, signing, notarization or distribution. Local commits on
  `feat/macos-app-design`, authored as the branch's existing bot identity.
- macOS 13 or newer (`platforms: [.macOS(.v13)]`), Apple Silicon first.
- Supported CLI: `sigsieve --version` prints `sigsieve 1.<minor>.<patch>`.
  Anything else blocks checks and connections.
- The app starts only these programs through `Process`: the resolved CLI,
  `/usr/bin/ssh-add`, `/usr/bin/ssh-keygen`. Never `ssh`, never a shell.
- Child environment, exactly: `HOME`, `PATH`
  (`/usr/bin:/bin:/usr/sbin:/sbin:<cli directory>`), `LANG`, `TMPDIR`
  (verified), `SSH_AUTH_SOCK` (the profile's agent socket). The launcher and
  the copyable command add `TERM="$TERM"` and nothing else.
- Fingerprints match `^SHA256:[A-Za-z0-9+/]{43}$`. Host input: not empty, no
  leading `-`, no whitespace, no control characters.
- `-- -o StrictHostKeyChecking=yes` is always appended to `connect`.
- UI wording: never "the server sees a key". The key list is headed "Keys
  sessions on this server may use (forwarded agent)". Known-hosts picker
  entries are labelled "from your known_hosts". The result screen ends with
  "SigSieve checks again when it connects".
- A server without a profile forwards no key. There is no "select all".
- Tests never use a real user key, host, agent or `~/.ssh`. Every test takes
  its paths from a temporary directory.
- Timeouts: `--version` 5 s; `ssh-add`, `ssh-keygen` 10 s; `doctor` and
  `--dry-run` 150 s (above the CLI's 120 s `--upstream-timeout`).

## Review Focus

Inputs the design does not spell out but a user will hit. Each has a test in
the task named.

1. The agent is not running, or runs with zero keys: the key list shows an
   empty state with the reason, not an error dialog or a crash (Task 6).
2. Key comments that are empty, contain spaces or parentheses, or are
   identical for two keys: every key is listed once and told apart by
   fingerprint (Task 6).
3. `profiles.json` is truncated, not JSON, or has a newer `schemaVersion`:
   the file is left byte-for-byte unchanged and saving is refused (Task 2).
4. `HOME`, the CLI path or a socket path contains a space or a single quote:
   the launcher and the copyable command still run the intended program with
   the intended arguments (Task 9).
5. `~/.ssh/config` is missing, has `Host a b c` on one line, uses `Host=x`,
   has CRLF line endings, or an `Include` that includes itself: discovery
   returns what it can and never hangs (Task 7).

## File Structure

```text
macos-app/
  Package.swift
  README.md                      build, run, test; what the app does not do
  scripts/build-app.sh           swift build -c release → build/SigSieve.app
  Sources/SigSieveKit/
    Validation.swift             Fingerprint, HostInput
    Profile.swift                Profile model, ProfileStore (load/save)
    ChildEnvironment.swift       environment + TMPDIR verification
    ProcessRunner.swift          the only file that uses Process
    CLILocator.swift             find the CLI, read its version
    AgentKeys.swift              ssh-add output → [AgentKey], KeyFilter
    SSHConfigAliases.swift       Host aliases + file stamps
    KnownHosts.swift             destination picker source
    CommandBuilder.swift         CLI arguments, ShellQuote, launcher text
    ConnectionCheck.swift        doctor + dry-run, CheckInputs, CheckGate
    Launcher.swift               write launcher, open in Terminal, cleanup
  Sources/SigSieveApp/
    SigSieveApp.swift            @main, MenuBarExtra
    AppModel.swift               @MainActor ObservableObject, all state
    Views/StatusRow.swift
    Views/ServerPicker.swift
    Views/KeyList.swift
    Views/AdvancedSection.swift
    Views/CheckSection.swift
    Views/SettingsView.swift
  Tests/SigSieveKitTests/        one test file per Kit source file
    IntegrationTests.swift       throwaway ssh-agent + built CLI
    SourceRulesTests.swift       source scan (no ssh, one Process user)
```

`SigSieveApp` has no tests of its own: views read `AppModel`, and `AppModel`
only calls `SigSieveKit`. Anything worth testing belongs in the Kit.

---

### Task 1: Package and input validation

**Files:**
- Create: `macos-app/Package.swift`, `Sources/SigSieveKit/Validation.swift`,
  `Sources/SigSieveApp/SigSieveApp.swift` (an empty `MenuBarExtra`),
  `Tests/SigSieveKitTests/ValidationTests.swift`, `macos-app/.gitignore`
  (`.build/`, `build/`)

**Interfaces:**
- Produces:
  - `struct Fingerprint: Hashable, Codable, Sendable { init?(_ s: String); let value: String; var short: String }` (`short` is `SHA256:` plus the first 8 characters and `…`)
  - `struct HostInput: Hashable, Codable, Sendable { init?(_ s: String); let value: String }`

- [ ] **Step 1: Write `Package.swift`**: tools version 6.0, platform
  `.macOS(.v13)`, library target `SigSieveKit`, executable target
  `SigSieveApp` depending on it, test target `SigSieveKitTests`.
- [ ] **Step 2: Write the failing tests**

```swift
@Test func fingerprintAcceptsExactly43Base64Characters() {
    #expect(Fingerprint("SHA256:" + String(repeating: "A", count: 43)) != nil)
    #expect(Fingerprint("SHA256:" + String(repeating: "A", count: 42)) == nil)
    #expect(Fingerprint("SHA256:" + String(repeating: "A", count: 44)) == nil)
    #expect(Fingerprint("MD5:" + String(repeating: "A", count: 43)) == nil)
    #expect(Fingerprint("SHA256:" + String(repeating: "A", count: 42) + "'") == nil)
    #expect(Fingerprint("SHA256:" + String(repeating: "A", count: 43) + "\n") == nil)
}

@Test(arguments: ["", "-oProxyCommand=x", "a b", "a\tb", "a\nb", "a\u{0}b", "a\u{7f}"])
func hostInputRejects(_ s: String) { #expect(HostInput(s) == nil) }

@Test(arguments: ["build-host", "deploy@10.0.0.5", "user@host.example", "[::1]"])
func hostInputAccepts(_ s: String) { #expect(HostInput(s)?.value == s) }
```

- [ ] **Step 3: Run** `cd macos-app && swift test --filter ValidationTests`.
  Expected: fails to compile (types missing).
- [ ] **Step 4: Implement `Validation.swift`.** Check characters by scalar,
  not with `NSRegularExpression` (`$` there matches before a final newline).
- [ ] **Step 5: Run** the same command. Expected: all pass. Then `swift build`.
- [ ] **Step 6: Commit** `macos-app: package scaffold and input validation`.

### Task 2: Profiles and their file

**Files:**
- Create: `Sources/SigSieveKit/Profile.swift`,
  `Tests/SigSieveKitTests/ProfileTests.swift`

**Interfaces:**
- Consumes: `Fingerprint`, `HostInput`
- Produces:
  - `enum AgentChoice: Hashable, Codable, Sendable { case secretive; case openssh(socket: String) }`
  - `enum ProtectionMode: String, Codable, Sendable { case filtering, binding }`
  - `struct Destination: Hashable, Codable, Sendable { var name: String; var hostKeys: [Fingerprint] }`
  - `struct Profile: Hashable, Codable, Sendable { var server: HostInput; var agent: AgentChoice; var forwardedKeys: [Fingerprint]; var mode: ProtectionMode; var destinations: [Destination] }`
  - `struct ProfileStore { init(directory: URL); func load() throws -> [Profile]; func save(_ profiles: [Profile]) throws }`
  - `enum ProfileStoreError: Error, Equatable { case unsupportedVersion(Int); case unreadable(String) }`
  - `ProfileStore.defaultDirectory` = `~/Library/Application Support/SigSieve`

File format (the documented format a later CLI `--profile` may read):

```json
{
  "schemaVersion": 1,
  "profiles": [
    {
      "server": "build-host",
      "agent": { "kind": "secretive" },
      "forwardedKeys": ["SHA256:…"],
      "mode": "filtering",
      "destinations": [{ "name": "github.com", "hostKeys": ["SHA256:…"] }]
    }
  ]
}
```

`agent` is `{ "kind": "openssh", "socket": "/path" }` for the OpenSSH agent.
Write custom `Codable` for `AgentChoice`, `Fingerprint` and `HostInput` so
the file has these plain shapes and decoding re-validates every value.

- [ ] **Step 1: Write the failing tests**

```swift
@Test func saveCreatesPrivateDirectoryAndFile() throws {
    let dir = tmp().appending(path: "SigSieve")
    try ProfileStore(directory: dir).save([sample])
    #expect(mode(dir) == 0o700)
    #expect(mode(dir.appending(path: "profiles.json")) == 0o600)
    #expect(try ProfileStore(directory: dir).load() == [sample])
}
@Test func missingFileLoadsAsEmpty() throws {
    #expect(try ProfileStore(directory: tmp()).load() == [])
}
@Test func saveLeavesNoTemporaryFileBehind() throws {
    // after save, the directory contains exactly ["profiles.json"]
}
@Test(arguments: ["", "{", "{\"schemaVersion\":1,\"profiles\":[{\"server\":\"-x\"}]}"])
func unreadableFileIsNeverOverwritten(_ body: String) throws {
    // write body; load() throws .unreadable; save() throws .unreadable;
    // the file's bytes are unchanged
}
@Test func newerSchemaVersionIsNeverOverwritten() throws {
    // {"schemaVersion":2,"profiles":[]} → load() and save() both throw
    // .unsupportedVersion(2); bytes unchanged
}
@Test func aServerWithoutProfileForwardsNothing() {
    #expect(Profile.empty(for: HostInput("h")!, agent: .secretive).forwardedKeys.isEmpty)
}
```

- [ ] **Step 2: Run** `swift test --filter ProfileTests`. Expected: compile failure.
- [ ] **Step 3: Implement `Profile.swift`.** `save` writes a temporary file
  in the same directory with `open(O_CREAT|O_EXCL, 0o600)`, `fsync`, then
  `rename`; it calls `load()` first and rethrows, so an unreadable or newer
  file blocks saving. Add `static func empty(for:agent:) -> Profile`.
- [ ] **Step 4: Run** the tests. Expected: all pass.
- [ ] **Step 5: Commit** `macos-app: profile model and atomic private store`.

### Task 3: Child environment and TMPDIR verification

**Files:**
- Create: `Sources/SigSieveKit/ChildEnvironment.swift`,
  `Tests/SigSieveKitTests/ChildEnvironmentTests.swift`

**Interfaces:**
- Consumes: `AgentChoice`
- Produces:
  - `enum TempDirError: Error, Equatable { case notAbsolute, notADirectory, wrongOwner, notPrivate, unsupportedCharacters }` (each carries the path in its description)
  - `enum TempDir { static func system() -> String; static func verified(_ path: String, uid: uid_t = getuid()) throws -> String }`
  - `struct EnvVar: Hashable, Sendable { let name: String; let value: String }`
  - `struct ChildEnvironment: Hashable, Sendable { let variables: [EnvVar]; var dictionary: [String: String] }` (`variables` keeps the documented order)
  - `ChildEnvironment.make(home: String, cliDirectory: String, tmpdir: String, agent: AgentChoice) -> ChildEnvironment`
  - `AgentChoice.socketPath(home: String) -> String` (Secretive:
    `<home>/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh`)

- [ ] **Step 1: Write the failing tests**

```swift
@Test func environmentHasExactlyTheDocumentedVariables() {
    let env = ChildEnvironment.make(home: "/Users/t", cliDirectory: "/opt/homebrew/bin",
                                    tmpdir: "/private/var/folders/ab/T", agent: .openssh(socket: "/s"))
    #expect(env.variables.map(\.name) == ["HOME", "PATH", "LANG", "TMPDIR", "SSH_AUTH_SOCK"])
    #expect(env.dictionary["PATH"] == "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin")
    #expect(env.dictionary["LANG"] == "en_US.UTF-8")
    #expect(env.dictionary["SSH_AUTH_SOCK"] == "/s")
}
@Test func tmpdirRefusals() throws {
    // relative path → .notAbsolute; a file → .notADirectory;
    // mode 0755 dir → .notPrivate; mode 0770 → .notPrivate;
    // 0700 dir with uid: getuid()+1 passed in → .wrongOwner;
    // 0700 dir named "a b" → .unsupportedCharacters;
    // symlink to a 0755 dir → .notPrivate (checked after resolving)
}
@Test func tmpdirAcceptsAPrivateDirectoryAndReturnsTheResolvedPath() throws {}
@Test func systemTempDirPassesVerificationOnThisMachine() throws {
    _ = try TempDir.verified(TempDir.system())
}
```

- [ ] **Step 2: Run** `swift test --filter ChildEnvironmentTests`. Expected: compile failure.
- [ ] **Step 3: Implement.** `TempDir.system()` uses
  `confstr(_CS_DARWIN_USER_TEMP_DIR, …)`, never `ProcessInfo.environment`.
  `verified` resolves symlinks with `realpath`, then `lstat`: `S_ISDIR`,
  `st_uid == uid`, `st_mode & 0o077 == 0`, and every character is an ASCII
  letter, digit or one of `/._-`. `LANG` is fixed to `en_US.UTF-8` so CLI
  and OpenSSH output is parsed in one language.
- [ ] **Step 4: Run** the tests. Expected: all pass.
- [ ] **Step 5: Commit** `macos-app: child environment and TMPDIR verification`.

### Task 4: Process runner

**Files:**
- Create: `Sources/SigSieveKit/ProcessRunner.swift`,
  `Tests/SigSieveKitTests/ProcessRunnerTests.swift`,
  `Tests/SigSieveKitTests/SourceRulesTests.swift`

**Interfaces:**
- Consumes: `ChildEnvironment`
- Produces:
  - `enum Tool: Sendable { case cli(URL); case sshAdd; case sshKeygen }` with `var url: URL` (`/usr/bin/ssh-add`, `/usr/bin/ssh-keygen`)
  - `struct RunResult: Sendable { let exitCode: Int32; let stdout: String; let stderr: String }`
  - `enum RunError: Error, Equatable { case timedOut; case cannotStart(String) }`
  - `protocol Running: Sendable { func run(_ tool: Tool, _ arguments: [String], environment: ChildEnvironment, stdin: Data?, timeout: Duration) async throws -> RunResult }`
  - `struct ProcessRunner: Running`

`Tool` has no case that takes an arbitrary program other than the CLI URL;
that is how "never runs ssh" is enforced in the type.

- [ ] **Step 1: Write the failing tests** (use `/usr/bin/ssh-keygen` as a
  harmless real program, and a script in a temp dir as a fake CLI)

```swift
@Test func returnsExitCodeAndOutput() async throws {
    let cli = try script("#!/bin/sh\necho out; echo err >&2; exit 2\n")
    let r = try await ProcessRunner().run(.cli(cli), [], environment: env, stdin: nil, timeout: .seconds(5))
    #expect(r.exitCode == 2); #expect(r.stdout == "out\n"); #expect(r.stderr == "err\n")
}
@Test func childSeesOnlyTheGivenEnvironment() async throws {
    setenv("SIGSIEVE_ALLOW", "SHA256:leak", 1); setenv("SIGSIEVE_UPSTREAM", "/leak", 1)
    let cli = try script("#!/bin/sh\n/usr/bin/env\n")
    let r = try await ProcessRunner().run(.cli(cli), [], environment: env, stdin: nil, timeout: .seconds(5))
    #expect(!r.stdout.contains("SIGSIEVE_"))
    #expect(Set(names(r.stdout)).subtracting(["HOME","PATH","LANG","TMPDIR","SSH_AUTH_SOCK","PWD","_","SHLVL"]).isEmpty)
}
@Test func argumentsAreNotInterpretedByAShell() async throws {
    let cli = try script("#!/bin/sh\nprintf '%s\\n' \"$@\"\n")
    let r = try await ProcessRunner().run(.cli(cli), ["$(id)", "a b", "`x`"], environment: env, stdin: nil, timeout: .seconds(5))
    #expect(r.stdout == "$(id)\na b\n`x`\n")
}
@Test func timeoutKillsTheChild() async throws {
    let cli = try script("#!/bin/sh\nsleep 30\n")
    await #expect(throws: RunError.timedOut) {
        try await ProcessRunner().run(.cli(cli), [], environment: env, stdin: nil, timeout: .milliseconds(300))
    }
}
@Test func stdinIsDelivered() async throws {}     // script `cat`; stdin "abc" → stdout "abc"
@Test func largeOutputDoesNotDeadlock() async throws {} // script prints 1 MB; completes

// SourceRulesTests.swift
@Test func onlyProcessRunnerUsesProcess() throws {
    // every *.swift under Sources/: "Process()" appears only in ProcessRunner.swift
}
@Test func noSourceNamesTheSshBinary() throws {
    // no file under Sources/ contains "/usr/bin/ssh\"" or "\"ssh\"" or "-G"
}
```

- [ ] **Step 2: Run** `swift test --filter "ProcessRunnerTests|SourceRulesTests"`. Expected: compile failure.
- [ ] **Step 3: Implement `ProcessRunner`.** Set `process.environment` to
  `environment.dictionary`; read both pipes concurrently; on timeout send
  `SIGTERM`, then `SIGKILL` after 2 s; run off the main actor.
- [ ] **Step 4: Run** the tests. Expected: all pass.
- [ ] **Step 5: Commit** `macos-app: process runner limited to the CLI, ssh-add and ssh-keygen`.

### Task 5: CLI discovery

**Files:**
- Create: `Sources/SigSieveKit/CLILocator.swift`,
  `Tests/SigSieveKitTests/CLILocatorTests.swift`

**Interfaces:**
- Consumes: `Running`, `Tool`, `ChildEnvironment`
- Produces:
  - `struct CLIInfo: Hashable, Sendable { let path: URL; let version: String }` (`path` is symlink-resolved)
  - `enum CLIError: Error, Equatable { case notFound(searched: [String]); case notExecutable(String); case unsupportedVersion(path: String, output: String) }`
  - `struct CLILocator { init(runner: Running, userPath: String?, appPATH: String?, fixed: [String] = ["/opt/homebrew/bin/sigsieve", "/usr/local/bin/sigsieve"]); func locate(environment: (URL) -> ChildEnvironment) async throws -> CLIInfo }`

- [ ] **Step 1: Write the failing tests** with a fake `Running`

```swift
@Test func userPathWinsOverFixedLocations() async throws {}
@Test func searchOrderIsUserThenFixedThenAppPATH() async throws {}
@Test func symlinkIsResolvedInTheReportedPath() async throws {}
@Test func nonExecutableFileIsReported() async throws {}       // mode 0644 → .notExecutable
@Test(arguments: ["sigsieve 1.0.0\n", "sigsieve 1.12.3\n"])
func acceptsVersion1(_ out: String) async throws {}
@Test(arguments: ["sigsieve 2.0.0\n", "sigsieve 0.9.0\n", "sigsieve 1.0.0-alpha.2\n", "other 1.0.0\n", ""])
func refusesOtherVersions(_ out: String) async throws {}       // .unsupportedVersion
@Test func nonZeroExitFromVersionIsUnsupported() async throws {}
@Test func nothingFoundListsWhatWasSearched() async throws {}
```

- [ ] **Step 2: Run** `swift test --filter CLILocatorTests`. Expected: compile failure.
- [ ] **Step 3: Implement.** The login shell is never started and no shell
  file is read. Version output must match `sigsieve 1.<digits>.<digits>`
  followed by a newline, nothing else.
- [ ] **Step 4: Run** the tests. Expected: all pass.
- [ ] **Step 5: Commit** `macos-app: CLI discovery and version gate`.

### Task 6: Agent keys

**Files:**
- Create: `Sources/SigSieveKit/AgentKeys.swift`,
  `Tests/SigSieveKitTests/AgentKeysTests.swift`

**Interfaces:**
- Consumes: `Running`, `Fingerprint`, `ChildEnvironment`
- Produces:
  - `struct AgentKey: Hashable, Identifiable, Sendable { let fingerprint: Fingerprint; let bits: Int; let type: String; let comment: String; var id: Fingerprint }`
  - `enum AgentState: Equatable, Sendable { case keys([AgentKey]); case empty; case unreachable(String) }`
  - `enum AgentKeys { static func parse(_ output: String) -> [AgentKey]; static func list(runner: Running, environment: ChildEnvironment) async -> AgentState }`
  - `enum KeyFilter { static func filter(_ keys: [AgentKey], query: String) -> [AgentKey] }` (case-insensitive substring over comment, type and fingerprint; empty query returns all)

`ssh-add -l -E sha256` prints `<bits> SHA256:<43> <comment> (<TYPE>)` per
key. Exit 0: keys. Exit 1: agent reachable, no keys. Exit 2: cannot reach
the agent.

- [ ] **Step 1: Write the failing tests**

```swift
@Test func parsesOrdinaryLine() {
    let k = AgentKeys.parse("256 SHA256:\(a43) work laptop (ED25519)\n")[0]
    #expect(k.bits == 256); #expect(k.type == "ED25519"); #expect(k.comment == "work laptop")
}
@Test func commentMayBeEmptyOrContainParentheses() {
    #expect(AgentKeys.parse("256 SHA256:\(a43)  (ECDSA)\n")[0].comment == "")
    #expect(AgentKeys.parse("256 SHA256:\(a43) key (old) (ECDSA)\n")[0].comment == "key (old)")
}
@Test func identicalCommentsStaySeparateKeys() {}       // two lines, same comment → 2 keys, distinct ids
@Test func duplicateFingerprintIsListedOnce() {}
@Test func malformedLinesAreSkipped() {}                // "garbage", "256 MD5:aa x (RSA)" → []
@Test func exit1IsEmptyNotAnError() async {}            // fake runner exit 1 → .empty
@Test func exit2IsUnreachableWithStderr() async {}      // → .unreachable("…")
@Test func timeoutIsUnreachable() async {}
@Test func filterMatchesCommentTypeAndFingerprint() {}
@Test func filtering500KeysIsFast() {
    let keys = synthetic(500)
    let t = ContinuousClock().measure { for _ in 0..<100 { _ = KeyFilter.filter(keys, query: "key-49") } }
    #expect(t < .milliseconds(500))                     // under 5 ms per keystroke
}
```

- [ ] **Step 2: Run** `swift test --filter AgentKeysTests`. Expected: compile failure.
- [ ] **Step 3: Implement.** Parse from both ends: bits and fingerprint from
  the left, `(<TYPE>)` from the right, the comment is what remains. `list`
  runs `.sshAdd` with `["-l", "-E", "sha256"]`, timeout 10 s.
- [ ] **Step 4: Run** the tests. Expected: all pass.
- [ ] **Step 5: Commit** `macos-app: agent key listing and search`.

### Task 7: Server aliases from SSH configuration

**Files:**
- Create: `Sources/SigSieveKit/SSHConfigAliases.swift`,
  `Tests/SigSieveKitTests/SSHConfigAliasesTests.swift`

**Interfaces:**
- Consumes: `HostInput`
- Produces:
  - `struct FileStamp: Hashable, Sendable { let path: String; let size: Int64; let modified: Date }`
  - `struct AliasDiscovery: Equatable, Sendable { let aliases: [HostInput]; let stamps: [FileStamp]; let skippedIncludes: [String] }`
  - `enum SSHConfigAliases { static func discover(config: URL, home: URL) -> AliasDiscovery; static func currentStamps(for stamps: [FileStamp]) -> [FileStamp] }`

Display only: this decides nothing about safety and must not grow into a
copy of `src/sshconfig.rs`. It reads files; it runs nothing.

- [ ] **Step 1: Write the failing tests**

```swift
@Test func listsHostAliasesInFileOrderWithoutDuplicates() {}
@Test func oneLineMayNameSeveralAliases() {}          // "Host a b c" → a, b, c
@Test func wildcardAndNegatedPatternsAreNotListed() {} // "Host * web-? !bad prod" → prod
@Test func keywordIsCaseInsensitiveAndAllowsEquals() {} // "host=a", "HOST b" → a, b
@Test func crlfLineEndingsAreAccepted() {}
@Test func commentsAndMatchBlocksAreIgnored() {}      // "# Host x", "Match host y" → []
@Test func invalidAliasesAreDropped() {}              // "Host -oX" → []
@Test func includeIsFollowedRelativeToDotSsh() {}     // "Include conf.d/*" → aliases from both files
@Test func includeWithTildeIsFollowed() {}
@Test func unresolvableIncludeIsSkippedAndNamed() {}  // "Include ${X}/y" → skippedIncludes == ["${X}/y"]
@Test func selfIncludeTerminates() {}                 // config includes itself → returns; depth cap 16
@Test func missingConfigGivesNothing() {}             // aliases == [], stamps == []
@Test func stampsCoverEveryFileRead() {}
@Test func stampChangesWhenAFileIsRewritten() {}      // currentStamps(for:) != stamps after a write
@Test func stampNotesADeletedFile() {}                // deleted file → stamp with size -1
```

- [ ] **Step 2: Run** `swift test --filter SSHConfigAliasesTests`. Expected: compile failure.
- [ ] **Step 3: Implement.** Glob only the last path component of an
  `Include` (`*` and `?`); anything containing `$`, `%`, `[`, `{`, quotes, a
  backslash or `~user` goes to `skippedIncludes`. Depth cap 16, and a file
  already visited is not read again.
- [ ] **Step 4: Run** the tests. Expected: all pass.
- [ ] **Step 5: Commit** `macos-app: read server aliases from ssh_config (display only)`.

### Task 8: Destination picker source

**Files:**
- Create: `Sources/SigSieveKit/KnownHosts.swift`,
  `Tests/SigSieveKitTests/KnownHostsTests.swift`

**Interfaces:**
- Consumes: `Running`, `Tool.sshKeygen`, `Fingerprint`, `ChildEnvironment`
- Produces:
  - `struct KnownHostEntry: Hashable, Sendable { let name: String?; let fingerprint: Fingerprint; let type: String }` (`name` is `nil` for a hashed entry)
  - `enum KnownHosts { static func selectableLines(_ text: String) -> String; static func entries(file: URL, runner: Running, environment: ChildEnvironment) async -> [KnownHostEntry] }`

- [ ] **Step 1: Write the failing tests**

```swift
@Test func markedLinesAreRemovedBeforeFingerprinting() {
    let text = """
    # comment
    host-a ssh-ed25519 AAAAC3Nza...A
    @revoked host-b ssh-ed25519 AAAAC3Nza...B
    @cert-authority *.example ssh-ed25519 AAAAC3Nza...C
      @REVOKED host-d ssh-ed25519 AAAAC3Nza...D
    |1|c2FsdA==|aGFzaA== ssh-ed25519 AAAAC3Nza...E
    """
    let kept = KnownHosts.selectableLines(text)
    #expect(kept.contains("...A")); #expect(kept.contains("...E"))
    #expect(!kept.contains("...B")); #expect(!kept.contains("...C")); #expect(!kept.contains("...D"))
    #expect(!kept.contains("#"))
}
@Test func aKeyRevokedAnywhereIsNotOfferedFromAnUnmarkedLine() {
    // host-a KEYX and "@revoked * KEYX" → selectableLines has no KEYX
}
@Test func hashedHostNamesBecomeNamelessEntries() async {}
@Test func rsaEntriesAreMarkedByType() async {}       // type == "RSA", so the UI can say it cannot bind
@Test func missingFileGivesNoEntries() async {}
@Test func realSshKeygenNeverReturnsAMarkedKey() async throws {
    // generate 3 keys with ssh-keygen in a temp dir, write a known_hosts with
    // one plain, one @revoked, one @cert-authority; entries(...) has exactly
    // the plain key's fingerprint
}
```

- [ ] **Step 2: Run** `swift test --filter KnownHostsTests`. Expected: compile failure.
- [ ] **Step 3: Implement.** A line is marked when its first field,
  compared case-insensitively, starts with `@`; any `@` marker is dropped,
  not only the two known ones. Collect the key blobs of `@revoked` lines and
  drop unmarked lines carrying the same blob. Run `.sshKeygen` with
  `["-l", "-E", "sha256", "-f", "-"]` and the kept lines on stdin. The file
  is read once by the app; `ssh-keygen` never opens `known_hosts` itself.
- [ ] **Step 4: Run** the tests. Expected: all pass.
- [ ] **Step 5: Commit** `macos-app: known_hosts picker source without revoked or CA keys`.

### Task 9: Command building and quoting

**Files:**
- Create: `Sources/SigSieveKit/CommandBuilder.swift`,
  `Tests/SigSieveKitTests/CommandBuilderTests.swift`

**Interfaces:**
- Consumes: `Profile`, `ChildEnvironment`, `CLIInfo`
- Produces:
  - `enum CommandBuilder { static func doctorArguments(_ p: Profile) -> [String]; static func connectArguments(_ p: Profile, dryRun: Bool) -> [String]; static func copyableCommand(_ p: Profile, cli: CLIInfo, environment: ChildEnvironment) -> String; static func launcherScript(_ p: Profile, cli: CLIInfo, environment: ChildEnvironment, selfDirectory: String) -> String }`
  - `enum ShellQuote { static func quote(_ s: String) -> String }` (always single-quoted; `'` becomes `'\''`)

Exact shapes:

```text
doctor  --secretive | --upstream <socket>
        --allow-fingerprint <FP> …  [--allow-destination <HK> …]
connect <host> --secretive | --upstream <socket>
        --allow-fingerprint <FP> …  [--allow-destination <HK> …]
        [--dry-run] -- -o StrictHostKeyChecking=yes
```

`--allow-destination` appears only when `mode == .binding`; it lists every
host key of every destination, in order, without duplicates. Launcher:

```sh
#!/bin/sh
/bin/rm -rf -- '<selfDirectory>'
exec /usr/bin/env -i HOME='…' PATH='…' LANG='…' TMPDIR='…' SSH_AUTH_SOCK='…' TERM="$TERM" '<cli>' 'connect' '<host>' …
```

The copyable command is the `exec` line without `exec`.

- [ ] **Step 1: Write the failing tests**

```swift
@Test func doctorArgumentsForSecretiveFiltering() {
    #expect(CommandBuilder.doctorArguments(p) == ["--secretive", "--allow-fingerprint", fp1, "--allow-fingerprint", fp2])
}
@Test func connectArgumentsForOpensshBindingDryRun() {
    #expect(CommandBuilder.connectArguments(q, dryRun: true) ==
        ["build-host", "--upstream", "/s", "--allow-fingerprint", fp1,
         "--allow-destination", hk1, "--allow-destination", hk2,
         "--dry-run", "--", "-o", "StrictHostKeyChecking=yes"])
}
@Test func filteringModeNeverPassesDestinationsEvenIfStored() {}
@Test func strictHostKeyCheckingIsAlwaysLast() {}
@Test(arguments: ["a b", "it's", "$(id)", "`id`", "a\nb", "-x", "", "\\", "!", "*"])
func quotedWordRoundTripsThroughSh(_ s: String) async throws {
    // run /bin/sh -c "printf %s <quote(s)>" via Foundation in the test only; stdout == s
}
@Test func launcherRunsTheIntendedArgvWithHostileValues() async throws {
    // home "/tmp/x y/it's", cli path with a space and a quote (a script that
    // prints "$0" and each "$@" on its own line), openssh socket "/tmp/a b";
    // write launcherScript to a temp file, run it with /bin/sh and TERM=xterm;
    // output == expected argv, line by line
}
@Test func launcherEnvironmentIsTheCheckEnvironmentPlusTERM() async throws {
    // cli = script running /usr/bin/env; names == HOME, PATH, LANG, TMPDIR, SSH_AUTH_SOCK, TERM
}
@Test func launcherDeletesItsOwnDirectoryBeforeExec() async throws {}
@Test func copyableCommandEqualsTheLauncherExecLine() {}
```

- [ ] **Step 2: Run** `swift test --filter CommandBuilderTests`. Expected: compile failure.
- [ ] **Step 3: Implement.** Only `TERM="$TERM"` is unquoted text; every
  other word, including the environment values, goes through `ShellQuote`.
- [ ] **Step 4: Run** the tests. Expected: all pass.
- [ ] **Step 5: Commit** `macos-app: CLI arguments, launcher script and copyable command`.

### Task 10: Check Connection and the check gate

**Files:**
- Create: `Sources/SigSieveKit/ConnectionCheck.swift`,
  `Tests/SigSieveKitTests/ConnectionCheckTests.swift`

**Interfaces:**
- Consumes: `Running`, `CommandBuilder`, `Profile`, `CLIInfo`, `ChildEnvironment`, `FileStamp`
- Produces:
  - `struct CheckInputs: Hashable, Sendable { let profile: Profile; let cli: CLIInfo; let environment: ChildEnvironment; let configStamps: [FileStamp] }`
  - `struct ResultLine: Hashable, Sendable { let label: String; let value: String }`
  - `enum StepOutcome: Equatable, Sendable { case passed; case failed; case invalidConfiguration; case timedOut }`
  - `struct StepResult: Equatable, Sendable { let outcome: StepOutcome; let lines: [ResultLine]; let hint: String?; let raw: String }`
  - `struct CheckResult: Equatable, Sendable { let doctor: StepResult; let dryRun: StepResult?; var passed: Bool }`
  - `enum ConnectionCheck { static func run(_ inputs: CheckInputs, runner: Running) async -> CheckResult; static func lines(from output: String) -> [ResultLine] }`
  - `struct CheckGate: Sendable { mutating func record(_ r: CheckResult, for i: CheckInputs); func canConnect(_ current: CheckInputs) -> Bool; var result: CheckResult? }`

Exit codes decide the outcome: `0` passed, `1` failed, `2` invalid
configuration. `lines(from:)` splits `Label:   value` lines for display and
is never consulted for pass or fail. `dryRun` is `nil` when `doctor` did not
pass (it is not run). Because `environment` is part of `CheckInputs`, a
change of agent, `HOME`, CLI directory or `TMPDIR` invalidates the result
without separate bookkeeping.

- [ ] **Step 1: Write the failing tests** with a fake `Running`

```swift
@Test func bothStepsPassing() async {}             // exit 0, 0 → passed == true; runner saw doctor then connect --dry-run
@Test func doctorFailureSkipsDryRun() async {}     // exit 1 → dryRun == nil, passed == false, one call only
@Test func exit2IsInvalidConfiguration() async {}
@Test func textSayingPassedWithExit1IsStillAFailure() async {
    // stdout "Result: all checks passed", exit 1 → outcome == .failed
}
@Test func hintLineIsExtracted() async {}          // "  hint: start Secretive" → hint == "start Secretive"
@Test func timeoutIsReportedAndUses150Seconds() async {}   // fake records timeout == .seconds(150)
@Test func rawOutputKeepsStdoutAndStderr() async {}
@Test func linesAreSplitOnTheFirstColon() {
    #expect(ConnectionCheck.lines(from: "Login agent:         your SSH_AUTH_SOCK agent, passed as IdentityAgent\n")
            == [ResultLine(label: "Login agent", value: "your SSH_AUTH_SOCK agent, passed as IdentityAgent")])
}
@Test func gateOpensOnlyForTheCheckedInputs() {
    var g = CheckGate(); g.record(passing, for: inputs)
    #expect(g.canConnect(inputs))
}
@Test(arguments: Change.allCases)   // forwardedKeys, mode, destinations, server, agent, cliPath, cliVersion, tmpdir, configStampSize, configStampDate
func anyChangeClosesTheGate(_ c: Change) {
    var g = CheckGate(); g.record(passing, for: inputs)
    #expect(!g.canConnect(c.apply(to: inputs)))
}
@Test func aFailedCheckNeverOpensTheGate() {}
```

- [ ] **Step 2: Run** `swift test --filter ConnectionCheckTests`. Expected: compile failure.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the tests. Expected: all pass.
- [ ] **Step 5: Commit** `macos-app: Check Connection and the check-to-connect gate`.

### Task 11: Terminal launcher

**Files:**
- Create: `Sources/SigSieveKit/Launcher.swift`,
  `Tests/SigSieveKitTests/LauncherTests.swift`

**Interfaces:**
- Consumes: `CommandBuilder.launcherScript`, `CheckInputs`
- Produces:
  - `enum Launcher { static func write(_ inputs: CheckInputs, under tmpdir: String) throws -> URL; static func open(_ script: URL) async throws; static func removeStale(under tmpdir: String, olderThan: TimeInterval = 3600, now: Date = .now) }`

The directory is `mkdtemp("<tmpdir>/sigsieve-launch-XXXXXX")`, mode `0700`;
the file is `connect.command`, mode `0700`. `open` calls
`NSWorkspace.shared.open([script], withApplicationAt:
/System/Applications/Utilities/Terminal.app, configuration:)`. No
AppleScript, no `osascript`, no `Process`.

- [ ] **Step 1: Write the failing tests**

```swift
@Test func writesAPrivateDirectoryAndExecutableScript() throws {
    // dir mode 0700, name has prefix "sigsieve-launch-"; file mode 0700, named connect.command
}
@Test func scriptContentIsTheBuilderOutputForThatDirectory() throws {}
@Test func twoWritesUseDifferentDirectories() throws {}
@Test func removeStaleDeletesOnlyOldLauncherDirectories() throws {
    // old "sigsieve-launch-a" (2 h) removed; new "sigsieve-launch-b" kept;
    // old "sigsieve-0123456789ab" (the CLI's socket dir) kept; old "other" kept
}
@Test func removeStaleIgnoresASymlinkNamedLikeALauncher() throws {}  // symlink is not followed, target survives
```

- [ ] **Step 2: Run** `swift test --filter LauncherTests`. Expected: compile failure.
- [ ] **Step 3: Implement.** `open` has no unit test (it would open
  Terminal); Task 13's checklist covers it.
- [ ] **Step 4: Run** the tests. Expected: all pass.
- [ ] **Step 5: Commit** `macos-app: Terminal launcher without AppleScript`.

### Task 12: Window and model

**Files:**
- Create: `Sources/SigSieveApp/AppModel.swift`, the six files in
  `Sources/SigSieveApp/Views/`, `scripts/build-app.sh`
- Modify: `Sources/SigSieveApp/SigSieveApp.swift`

**Interfaces:**
- Consumes: everything in `SigSieveKit`
- Produces: `@MainActor final class AppModel: ObservableObject` with
  `@Published` state: `cli: Result<CLIInfo, CLIError>?`, `tmpdir:
  Result<String, TempDirError>`, `agentState: AgentState`, `discovery:
  AliasDiscovery`, `profiles: [Profile]`, `selectedServer: HostInput?`,
  `keyQuery`, `serverQuery`, `checkState: enum { idle, running(step),
  finished(CheckResult) }`, `storeError: ProfileStoreError?`; and methods
  `refresh() async`, `toggleKey(_:)`, `setMode(_:)`, `addServer(_:) -> Bool`,
  `addDestination(_:)`, `runCheck() async`, `connect() async`,
  `var currentInputs: CheckInputs?`, `var canConnect: Bool`,
  `var copyableCommand: String?`.

Rules that are not obvious from the design:

- `canConnect` is `gate.canConnect(currentInputs)`. `currentInputs` is
  `nil`, and Check is disabled, when the CLI or `TMPDIR` is in error, no
  server is selected, or no key is forwarded.
- `connect()` re-reads `SSHConfigAliases.currentStamps` first; if they
  differ from the checked ones it clears the result and does not launch.
  `refresh()` (window opens) does the same comparison.
- Settings holds the default agent (Secretive or an OpenSSH socket, prefilled
  from the app's own `SSH_AUTH_SOCK`), an optional CLI path, and shows the
  resolved CLI path, its version and the profiles file location. A new
  profile takes the default agent; each profile can change its own. These
  two settings live in `UserDefaults`.
- At launch the model calls `Launcher.removeStale(under:)` once.
- Every profile edit saves through `ProfileStore` immediately. If
  `storeError` is set, edits are disabled and the status row shows the error
  with the file path.
- The copyable command is shown only while `canConnect` is true.
- Key and server lists are `List` with a fixed height (keys 180 pt, servers
  120 pt) so 500 rows are created lazily. Search fields bind to the queries.
- Window width 380 pt. One window: status row, server picker, key list,
  Advanced (disclosure), Check section, footer (Settings, Quit).
- Advanced shows the binding limits as plain rows: needs OpenSSH hostbound
  authentication on the onward server; RSA host keys cannot bind; with
  Secretive a cancelled Touch ID prompt means reconnecting. RSA picker
  entries are shown disabled with "RSA host keys cannot bind".
- Under the key list, one line: "Login uses <agent name>, unfiltered." In
  filtering mode the result screen includes the row "Forwarded key can sign
  for any server while connected".
- For a failed check: the CLI's `hint` if any, then "Show output" with the
  raw text. While running: "Waiting for agent…" after 2 s.
- Menu bar icon: SF Symbol `key.horizontal` as template; `key.horizontal.fill`
  with a badge only when the CLI or `TMPDIR` is in error.
- `scripts/build-app.sh`: `swift build -c release`, then assemble
  `build/SigSieve.app/Contents/{MacOS/SigSieve,Info.plist}` with
  `LSUIElement = true`, `CFBundleIdentifier = dev.sigsieve.macos`,
  `LSMinimumSystemVersion = 13.0`. No signing step.

- [ ] **Step 1: Implement `AppModel`** against the Kit interfaces.
- [ ] **Step 2: Implement the views**, one file per window section.
- [ ] **Step 3: Write `scripts/build-app.sh`.**
- [ ] **Step 4: Run** `swift build && swift test`. Expected: builds, all
  earlier tests pass, `SourceRulesTests` still pass with the app sources.
- [ ] **Step 5: Run** `scripts/build-app.sh && open build/SigSieve.app`.
  Expected: a key icon in the menu bar, no Dock icon, the window opens.
- [ ] **Step 6: Commit** `macos-app: menu bar window`.

### Task 13: Integration tests, 500 keys, manual checklist

**Files:**
- Create: `Tests/SigSieveKitTests/IntegrationTests.swift`,
  `Tests/SigSieveKitTests/Support/ThrowawayAgent.swift`
- Modify: `macos-app/README.md` (manual checklist)

**Interfaces:**
- Consumes: the whole Kit
- Produces: `final class ThrowawayAgent { init(keys: Int) throws; let socket: String; let fingerprints: [Fingerprint]; deinit kills the agent and removes its directory }`. It starts `/usr/bin/ssh-agent -a <socket>` in a temp dir and adds freshly generated Ed25519 keys with `ssh-add`.

Integration tests need the built CLI. They read its path from the
`SIGSIEVE_TEST_CLI` environment variable and are skipped
(`.enabled(if:)`) when it is unset, so `swift test` alone still passes.
Locally: `cargo build --release && SIGSIEVE_TEST_CLI=$PWD/target/release/sigsieve swift test --package-path macos-app`.

- [ ] **Step 1: Write the tests**

```swift
@Test func listsTheThrowawayAgentsKeys() async throws {}       // 3 keys → 3 AgentKeys, same fingerprints
@Test func emptyAgentIsTheEmptyState() async throws {}         // 0 keys → .empty
@Test func stoppedAgentIsUnreachable() async throws {}
@Test func doctorPassesForAnAllowedKey() async throws {}       // real CLI, exit 0, lines contain "Filtering"
@Test func doctorFailsForAMissingKey() async throws {}         // fingerprint not in agent → .failed
@Test func dryRunPassesAgainstAnIsolatedConfig() async throws {
    // HOME = temp dir with .ssh/config "Host t\n  HostName 127.0.0.1\n";
    // CheckResult.passed == true; no ssh session is opened by --dry-run
}
@Test func matchExecConfigIsRefusedByTheCLIAndNothingRuns() async throws {
    // config: "Match exec \"touch <marker>\"\nHost t\n"; dry run → .failed;
    // raw contains "Match exec"; <marker> does not exist;
    // SSHConfigAliases.discover on the same file also leaves no marker
}
@Test func sigsieveVariablesInTheTestEnvironmentAreIgnored() async throws {
    // setenv SIGSIEVE_ALLOW=<other fp>; doctor output reports 1 allowlisted fingerprint, ours
}
@Test func wrongVersionBinaryBlocks() async throws {}          // fake script printing "sigsieve 2.0.0"
@Test func fiveHundredKeysListAndFilterWithinBudget() async throws {
    let agent = try ThrowawayAgent(keys: 500)
    let t = await clock.measure { state = await AgentKeys.list(runner: ProcessRunner(), environment: env(agent)) }
    #expect(count(state) == 500)
    #expect(t < .seconds(2))
}
```

- [ ] **Step 2: Run** with `SIGSIEVE_TEST_CLI` set. Expected: all pass.
  Run without it. Expected: integration tests reported as skipped, the rest pass.
- [ ] **Step 3: Write the manual checklist in `README.md`** (things no
  automated test here can see):
  1. With 500 keys in a throwaway agent selected in Settings, scrolling and
     typing in the key search show no visible stall.
  2. Light and Dark Mode both readable.
  3. Check with Secretive: the Touch ID wait shows "Waiting for agent…".
  4. Connect opens Terminal with the session; no Automation prompt appears;
     the launcher directory is gone afterwards.
  5. Pasting the copyable command into another terminal connects the same way.
  6. Editing the profile while a session is open does not affect it; the
     window says "applies to new connections".
  7. Editing `~/.ssh/config` after a passed check disables Connect on the
     next window open.
- [ ] **Step 4: Commit** `macos-app: integration tests, 500-key budget, manual checklist`.

### Task 14: CI job and README

**Files:**
- Create: `.github/workflows/macos-app.yml`
- Modify: `macos-app/README.md`

- [ ] **Step 1: Write the workflow.** Triggers: `pull_request` and `push`
  with `paths: ['macos-app/**', '.github/workflows/macos-app.yml']`.
  `permissions: contents: read`. One job on `macos-15`: checkout (the same
  pinned commit `ci.yml` uses, `3d3c42e5aac5ba805825da76410c181273ba90b1`),
  `cargo build --release --locked`, then
  `SIGSIEVE_TEST_CLI=$PWD/target/release/sigsieve swift test --package-path macos-app`,
  then `macos-app/scripts/build-app.sh`. It uploads nothing, publishes
  nothing and shares no job with the release workflows.
- [ ] **Step 2: Finish `README.md`**: what the app is (a convenience layer;
  the CLI enforces), requirements, build, run, test, the manual checklist,
  and "not signed or notarized; local builds only".
- [ ] **Step 3: Run** `git diff --check` and
  `git diff --stat main -- . ':!macos-app' ':!.github/workflows/macos-app.yml'`.
  Expected: no whitespace errors; the second command prints nothing.
- [ ] **Step 4: Commit** `macos-app: CI job and README`. The workflow runs
  for the first time when the owner decides to push; that run is part of
  the completion criteria, not of this task.

---

## Completion criteria

The first version is done when all of these hold, each with its evidence:

1. `swift test` passes with `SIGSIEVE_TEST_CLI` set, with zero skipped
   tests, on this machine.
2. `scripts/build-app.sh` produces `build/SigSieve.app` and it launches as a
   menu bar item.
3. The seven manual checklist items are done and recorded with date and
   macOS version in `README.md`. Item 3 and a real Secretive connection
   need the owner's device; until then they are recorded as "not run".
4. `git diff main` touches only `macos-app/` and
   `.github/workflows/macos-app.yml`.
5. `SourceRulesTests` pass: no `ssh` invocation, one `Process` user.
6. A fresh-context review of the whole branch against `DESIGN.md` finds no
   unaddressed anti-goal.
7. After the owner authorizes a push: the `macos-app` workflow is green.

## Not in this plan

Disconnect and session management, the CLI `--profile` option, effective
hostname display, signing, notarization, distribution and Intel builds. See
"Open for later phases" in `DESIGN.md`.
