import Foundation

/// Everything a check result depends on. A result is valid only for exactly
/// these inputs: the profile, the CLI (path and version), the child
/// environment (HOME, PATH, TMPDIR, agent socket) and the SSH config files.
public struct CheckInputs: Hashable, Sendable {
    public let profile: Profile
    public let cli: CLIInfo
    public let environment: ChildEnvironment
    public let configStamps: [FileStamp]

    public init(profile: Profile, cli: CLIInfo, environment: ChildEnvironment, configStamps: [FileStamp]) {
        self.profile = profile
        self.cli = cli
        self.environment = environment
        self.configStamps = configStamps
    }
}

/// One `Label:   value` line of CLI output, for display only.
public struct ResultLine: Hashable, Sendable {
    public let label: String
    public let value: String

    public init(label: String, value: String) {
        self.label = label
        self.value = value
    }
}

/// Decided by the exit code alone.
public enum StepOutcome: Equatable, Sendable {
    case passed, failed, invalidConfiguration, timedOut
}

public struct StepResult: Equatable, Sendable {
    public let outcome: StepOutcome
    public let lines: [ResultLine]
    public let hint: String?
    /// stdout, then stderr.
    public let raw: String

    public init(outcome: StepOutcome, lines: [ResultLine], hint: String?, raw: String) {
        self.outcome = outcome
        self.lines = lines
        self.hint = hint
        self.raw = raw
    }
}

public struct CheckResult: Equatable, Sendable {
    public let doctor: StepResult
    /// `nil` when doctor did not pass: the dry run is not started then.
    public let dryRun: StepResult?

    public init(doctor: StepResult, dryRun: StepResult?) {
        self.doctor = doctor
        self.dryRun = dryRun
    }

    public var passed: Bool { doctor.outcome == .passed && dryRun?.outcome == .passed }
}

public enum ConnectionCheck {
    static let timeout: Duration = .seconds(150)

    /// `sigsieve doctor`, then (only if it passed) `sigsieve connect --dry-run`.
    /// A profile with a `policyProblem` is refused as invalid configuration
    /// without starting anything.
    public static func run(_ inputs: CheckInputs, runner: Running) async -> CheckResult {
        if let problem = inputs.profile.policyProblem {
            return CheckResult(doctor: StepResult(outcome: .invalidConfiguration, lines: [], hint: problem, raw: problem),
                               dryRun: nil)
        }
        let doctor = await step(["doctor"] + CommandBuilder.doctorArguments(inputs.profile), inputs, runner)
        guard doctor.outcome == .passed else { return CheckResult(doctor: doctor, dryRun: nil) }
        let dry = await step(["connect"] + CommandBuilder.connectArguments(inputs.profile, dryRun: true), inputs, runner)
        return CheckResult(doctor: doctor, dryRun: dry)
    }

    private static func step(_ arguments: [String], _ inputs: CheckInputs, _ runner: Running) async -> StepResult {
        do {
            let r = try await runner.run(.cli(inputs.cli.path), arguments, environment: inputs.environment,
                                         stdin: nil, timeout: timeout)
            let raw = [r.stdout, r.stderr].filter { !$0.isEmpty }.joined(separator: "\n")
            let outcome: StepOutcome = switch r.exitCode {
            case 0: .passed
            case 2: .invalidConfiguration
            default: .failed // 1, and anything unexpected (a signal, a shell's 126/127)
            }
            return StepResult(outcome: outcome, lines: lines(from: raw), hint: hint(in: raw), raw: raw)
        } catch RunError.timedOut {
            return StepResult(outcome: .timedOut, lines: [], hint: nil, raw: "")
        } catch {
            // Could not start, or not allowed: never a pass.
            return StepResult(outcome: .failed, lines: [], hint: nil, raw: String(describing: error))
        }
    }

    /// Display only; never consulted for pass or fail. Each line is split on
    /// its first `:`; a line without one, or with an empty label, is skipped.
    public static func lines(from output: String) -> [ResultLine] {
        output.split(whereSeparator: \.isNewline).compactMap { line in
            guard let colon = line.firstIndex(of: ":") else { return nil }
            let label = line[..<colon].trimmingCharacters(in: .whitespaces)
            guard !label.isEmpty else { return nil }
            return ResultLine(label: label, value: line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces))
        }
    }

    static func hint(in output: String) -> String? {
        for line in output.split(whereSeparator: \.isNewline) {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("hint:") { return t.dropFirst("hint:".count).trimmingCharacters(in: .whitespaces) }
        }
        return nil
    }
}

/// Connect is allowed only for a passing check made for exactly the current
/// inputs. The result is stored together with its inputs, so a change of any
/// input closes the gate without separate bookkeeping.
public struct CheckGate: Sendable {
    private var recorded: (result: CheckResult, inputs: CheckInputs)?

    public init() {}

    public var result: CheckResult? { recorded?.result }

    /// The latest check replaces the previous one, so a failed re-check closes the gate.
    public mutating func record(_ r: CheckResult, for i: CheckInputs) {
        recorded = (r, i)
    }

    public func canConnect(_ current: CheckInputs) -> Bool {
        guard let recorded else { return false }
        return recorded.result.passed && recorded.inputs == current
    }
}
