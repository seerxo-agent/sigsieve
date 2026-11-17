import Foundation
import Testing
@testable import SigSieveKit

private func fp(_ c: Character) -> Fingerprint { Fingerprint("SHA256:" + String(repeating: c, count: 42) + "A")! }
private let fp1 = fp("a"), fp2 = fp("b"), hk1 = fp("c"), hk2 = fp("d"), hk3 = fp("e")

private let p = Profile(server: HostInput("web")!, agent: .secretive, forwardedKeys: [fp1, fp2],
                        mode: .filtering, destinations: [])
private let q = Profile(server: HostInput("build-host")!, agent: .openssh(socket: "/s"), forwardedKeys: [fp1],
                        mode: .binding,
                        destinations: [Destination(name: "a", hostKeys: [hk1, hk2]),
                                       Destination(name: "b", hostKeys: [hk2, hk1])])

private let tail = ["--", "-o", "StrictHostKeyChecking=yes"]

/// Runs `/bin/sh` with exactly `environment` (test only; Sources never start processes this way).
private func sh(_ arguments: [String], environment: [String: String] = [:]) throws -> (status: Int32, out: String) {
    let proc = Process()
    proc.executableURL = URL(filePath: "/bin/sh")
    proc.arguments = arguments
    proc.environment = environment
    let pipe = Pipe()
    proc.standardOutput = pipe
    try proc.run()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    proc.waitUntilExit()
    return (proc.terminationStatus, String(decoding: data, as: UTF8.self))
}

private func writeExecutable(_ url: URL, _ text: String) throws {
    try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
    try text.write(to: url, atomically: false, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path(percentEncoded: false))
}

/// A fake CLI in a directory whose name has a space and a single quote.
private func hostileCLI(_ body: String) throws -> CLIInfo {
    let url = TestDirectory.make().appending(path: "c d'e/sigsieve")
    try writeExecutable(url, body)
    return CLIInfo(path: url, version: "sigsieve 1.0.0")
}

private func hostileEnvironment(cli: CLIInfo, agent: AgentChoice) throws -> ChildEnvironment {
    try ChildEnvironment.make(home: "/tmp/x y/it's",
                              cliDirectory: cli.path.deletingLastPathComponent().path(percentEncoded: false),
                              tmpdir: TempDir.verified(TempDir.system()), agent: agent)
}

@Test func doctorArgumentsForSecretiveFiltering() {
    #expect(CommandBuilder.doctorArguments(p) == ["--secretive", "--allow-fingerprint", fp1.value,
                                                  "--allow-fingerprint", fp2.value])
}

@Test func doctorArgumentsForOpensshBinding() {
    #expect(CommandBuilder.doctorArguments(q) ==
        ["--upstream", "/s", "--allow-fingerprint", fp1.value,
         "--allow-destination", hk1.value, "--allow-destination", hk2.value])
}

@Test func connectArgumentsForOpensshBindingDryRun() {
    // hk1 and hk2 appear in both destinations: listed once each, first occurrence order.
    #expect(CommandBuilder.connectArguments(q, dryRun: true) ==
        ["build-host", "--upstream", "/s", "--allow-fingerprint", fp1.value,
         "--allow-destination", hk1.value, "--allow-destination", hk2.value,
         "--dry-run"] + tail)
}

@Test func connectArgumentsForSecretiveFiltering() {
    #expect(CommandBuilder.connectArguments(p, dryRun: false) ==
        ["web", "--secretive", "--allow-fingerprint", fp1.value, "--allow-fingerprint", fp2.value] + tail)
}

@Test func filteringModeNeverPassesDestinationsEvenIfStored() {
    var f = q
    f.mode = .filtering
    f.destinations.append(Destination(name: "c", hostKeys: [hk3]))
    for args in [CommandBuilder.doctorArguments(f), CommandBuilder.connectArguments(f, dryRun: true),
                 CommandBuilder.connectArguments(f, dryRun: false)] {
        #expect(!args.contains("--allow-destination"))
        #expect(!args.contains(hk1.value))
    }
}

@Test func strictHostKeyCheckingIsAlwaysLast() {
    for profile in [p, q] {
        for dryRun in [true, false] {
            let args = CommandBuilder.connectArguments(profile, dryRun: dryRun)
            #expect(Array(args.suffix(3)) == tail)
            #expect(args.filter { $0 == "--" }.count == 1)
            #expect(!args.contains("-F"))
        }
        #expect(!CommandBuilder.doctorArguments(profile).contains("-F"))
    }
}

@Test func quoteAlwaysSingleQuotes() {
    #expect(ShellQuote.quote("") == "''")
    #expect(ShellQuote.quote("plain") == "'plain'")
    #expect(ShellQuote.quote("it's") == "'it'\\''s'")
}

@Test(arguments: ["a b", "it's", "$(id)", "`id`", "a\nb", "-x", "", "\\", "!", "*", "''", "'", "a'\"b\"$HOME"])
func quotedWordRoundTripsThroughSh(_ s: String) throws {
    let r = try sh(["-c", "printf %s " + ShellQuote.quote(s)])
    #expect(r.status == 0)
    #expect(r.out == s)
}

@Test func launcherRunsTheIntendedArgvWithHostileValues() throws {
    let cli = try hostileCLI("#!/bin/sh\nprintf '%s\\n' \"$0\" \"$@\"\n")
    var profile = q
    profile.server = HostInput("h'$(id)`id`")!
    profile.agent = .openssh(socket: "/tmp/a b")
    let env = try hostileEnvironment(cli: cli, agent: profile.agent)
    let dir = TestDirectory.make().appending(path: "l m'n")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false)
    let script = TestDirectory.make().appending(path: "run.command")
    try CommandBuilder.launcherScript(profile, cli: cli, environment: env,
                                      selfDirectory: dir.path(percentEncoded: false))
        .write(to: script, atomically: false, encoding: .utf8)

    let r = try sh([script.path(percentEncoded: false)], environment: ["TERM": "xterm"])
    #expect(r.status == 0)
    let expected = [cli.path.path(percentEncoded: false), "connect"]
        + CommandBuilder.connectArguments(profile, dryRun: false)
    #expect(r.out == expected.map { $0 + "\n" }.joined())
    #expect(expected.contains("h'$(id)`id`") && expected.contains("/tmp/a b"))
}

@Test func copyableCommandRunsTheIntendedArgvWithHostileValues() throws {
    let cli = try hostileCLI("#!/bin/sh\nprintf '%s\\n' \"$0\" \"$@\"\n")
    let env = try hostileEnvironment(cli: cli, agent: .secretive)
    let r = try sh(["-c", CommandBuilder.copyableCommand(p, cli: cli, environment: env)], environment: ["TERM": "xterm"])
    #expect(r.status == 0)
    let expected = [cli.path.path(percentEncoded: false), "connect"] + CommandBuilder.connectArguments(p, dryRun: false)
    #expect(r.out == expected.map { $0 + "\n" }.joined())
}

@Test func launcherEnvironmentIsTheCheckEnvironmentPlusTERM() throws {
    // awk adds no variables of its own (a shell would add PWD, SHLVL, ...).
    let cli = try hostileCLI("#!/usr/bin/awk -f\nBEGIN { for (k in ENVIRON) printf \"%s=%s\\n\", k, ENVIRON[k] }\n")
    let env = try hostileEnvironment(cli: cli, agent: .secretive)
    let dir = TestDirectory.make()
    let script = TestDirectory.make().appending(path: "run.command")
    try CommandBuilder.launcherScript(p, cli: cli, environment: env, selfDirectory: dir.path(percentEncoded: false))
        .write(to: script, atomically: false, encoding: .utf8)

    let r = try sh([script.path(percentEncoded: false)], environment: ["TERM": "xterm", "LEAK": "1"])
    #expect(r.status == 0)
    var got: [String: String] = [:]
    for line in r.out.split(separator: "\n") {
        let parts = line.split(separator: "=", maxSplits: 1)
        got[String(parts[0])] = String(parts[1])
    }
    var want = env.dictionary
    want["TERM"] = "xterm"
    #expect(got == want)
    #expect(Set(got.keys) == ["HOME", "PATH", "LANG", "TMPDIR", "SSH_AUTH_SOCK", "TERM"])
}

@Test func launcherDeletesItsOwnDirectoryBeforeExec() throws {
    // The CLI checks that the launcher directory is already gone when it starts.
    let dir = TestDirectory.make().appending(path: "s d'x")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false)
    let dirPath = dir.path(percentEncoded: false)
    let cli = try hostileCLI("#!/bin/sh\nif [ -e \(ShellQuote.quote(dirPath)) ]; then echo present; else echo gone; fi\n")
    let env = try hostileEnvironment(cli: cli, agent: .secretive)
    let script = dir.appending(path: "run.command")
    try CommandBuilder.launcherScript(p, cli: cli, environment: env, selfDirectory: dirPath)
        .write(to: script, atomically: false, encoding: .utf8)

    let r = try sh([script.path(percentEncoded: false)], environment: ["TERM": "xterm"])
    #expect(r.status == 0)
    #expect(r.out == "gone\n")
    #expect(!FileManager.default.fileExists(atPath: dirPath))
}

@Test func launcherShape() throws {
    let cli = CLIInfo(path: URL(filePath: "/opt/homebrew/bin/sigsieve"), version: "sigsieve 1.0.0")
    let env = try ChildEnvironment.make(home: "/Users/t", cliDirectory: "/opt/homebrew/bin",
                                        tmpdir: TempDir.verified(TempDir.system()), agent: .secretive)
    let lines = CommandBuilder.launcherScript(p, cli: cli, environment: env, selfDirectory: "/d/x").split(separator: "\n")
    #expect(lines.count == 3)
    #expect(lines[0] == "#!/bin/sh")
    #expect(lines[1] == "/bin/rm -rf -- '/d/x'")
    #expect(lines[2].hasPrefix("exec /usr/bin/env -i HOME='/Users/t' PATH='/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin' LANG='en_US.UTF-8' TMPDIR='"))
    #expect(lines[2].contains("' SSH_AUTH_SOCK='/Users/t/Library/") )
    #expect(lines[2].hasSuffix(" TERM=\"$TERM\" '/opt/homebrew/bin/sigsieve' 'connect' 'web' '--secretive' '--allow-fingerprint' '\(fp1.value)' '--allow-fingerprint' '\(fp2.value)' '--' '-o' 'StrictHostKeyChecking=yes'"))
}

@Test func copyableCommandEqualsTheLauncherExecLine() throws {
    let cli = try hostileCLI("")
    let env = try hostileEnvironment(cli: cli, agent: .openssh(socket: "/tmp/a b"))
    let script = CommandBuilder.launcherScript(q, cli: cli, environment: env, selfDirectory: "/d")
    let lines = script.split(separator: "\n", omittingEmptySubsequences: false)
    #expect(lines.last == "")
    #expect(lines.dropLast().last.map(String.init) == "exec " + CommandBuilder.copyableCommand(q, cli: cli, environment: env))
}
