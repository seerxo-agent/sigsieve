import Foundation

public enum ShellQuote {
    /// One POSIX shell word that expands to exactly `s`: always single-quoted,
    /// even when empty or plain, with each `'` written as `'\''`.
    ///
    /// Shell text cannot hold a NUL byte, so a string containing one stops the
    /// app (precondition). Upstream validation (`HostInput`, `Fingerprint`,
    /// `ChildEnvironment.make`, the socket decoder) already refuses control
    /// characters, so no valid value reaches that.
    public static func quote(_ s: String) -> String {
        precondition(!s.utf8.contains(0), "a NUL byte cannot be represented in shell text")
        return "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}

/// The CLI arguments for `sigsieve doctor` and `sigsieve connect`, and the
/// shell text that runs `connect` in Terminal. The app only renders text here;
/// it never starts OpenSSH itself.
public enum CommandBuilder {
    public static func doctorArguments(_ p: Profile) -> [String] {
        policyArguments(p)
    }

    public static func connectArguments(_ p: Profile, dryRun: Bool) -> [String] {
        [p.server.value] + policyArguments(p) + (dryRun ? ["--dry-run"] : [])
            + ["--", "-o", "StrictHostKeyChecking=yes"]
    }

    /// The launcher's `exec` line without `exec`, for the user to paste.
    public static func copyableCommand(_ p: Profile, cli: CLIInfo, environment: ChildEnvironment) -> String {
        let cliPath = cli.path.path(percentEncoded: false)
        // env(1) takes every word containing `=` before the program as an
        // assignment (`--` does not stop that), so such a path would run
        // `connect` through PATH instead of the CLI. CLILocator and
        // ChildEnvironment.make refuse `=` upstream; this is only a backstop.
        precondition(!cliPath.contains("="),
                     "bug: CLILocator and ChildEnvironment refuse '=' in the CLI path, yet it reached CommandBuilder: \(cliPath)")
        let arguments = [cliPath, "connect"] + connectArguments(p, dryRun: false)
        // fish reads `\` inside single quotes as an escape, so one there could end a quoted word.
        // HostInput, ChildEnvironment.make and CLILocator refuse `\` upstream (finding F1); this
        // is only a backstop. The command is for POSIX shells either way.
        for value in arguments + environment.variables.map(\.value) {
            precondition(!value.contains("\\"),
                         "bug: HostInput, ChildEnvironment.make and CLILocator refuse '\\', yet it reached CommandBuilder: \(value)")
        }
        let assignments = environment.variables.map { "\($0.name)=\(ShellQuote.quote($0.value))" }
        // TERM="$TERM" is the only unquoted text: Terminal's own value.
        let words = ["/usr/bin/env", "-i"] + assignments + ["TERM=\"$TERM\""] + arguments.map(ShellQuote.quote)
        return words.joined(separator: " ")
    }

    /// The `.command` file Terminal runs. It removes its own directory
    /// (`selfDirectory`, created by the caller) and then replaces itself with
    /// the CLI, with an environment of exactly `environment` plus TERM.
    ///
    /// The `rm` line is a recursive delete, so `selfDirectory` must be absolute,
    /// name at least one component, and hold no `.` or `..` component; anything
    /// else is a caller bug and stops the app.
    public static func launcherScript(_ p: Profile, cli: CLIInfo, environment: ChildEnvironment,
                                      selfDirectory: String) -> String {
        let components = selfDirectory.split(separator: "/")
        precondition(selfDirectory.hasPrefix("/") && !components.isEmpty
                     && !components.contains(".") && !components.contains(".."),
                     "launcher directory must be an absolute path below / without . or ..: \(selfDirectory)")
        // Under the verified TMPDIR (ASCII letters, digits and /._-), so never `\` (finding F1 backstop).
        precondition(!selfDirectory.contains("\\"), "bug: launcher directory contains '\\': \(selfDirectory)")
        return """
        #!/bin/sh
        /bin/rm -rf -- \(ShellQuote.quote(selfDirectory))
        exec \(copyableCommand(p, cli: cli, environment: environment))

        """
    }

    private static func policyArguments(_ p: Profile) -> [String] {
        // Binding without a host key would build filtering arguments for a profile that says binding.
        precondition(p.policyProblem == nil,
                     "bug: a .binding profile without a host key reached CommandBuilder; Profile.policyProblem, ConnectionCheck.run and Launcher.write refuse it first")
        let agent: [String] = switch p.agent {
        case .secretive: ["--secretive"]
        case .openssh(let socket): ["--upstream", socket]
        }
        var args = agent + p.forwardedKeys.flatMap { ["--allow-fingerprint", $0.value] }
        if p.mode == .binding {
            var seen = Set<Fingerprint>()
            for key in p.destinations.flatMap(\.hostKeys) where seen.insert(key).inserted {
                args += ["--allow-destination", key.value]
            }
        }
        return args
    }
}
