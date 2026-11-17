import Foundation

public struct CLIInfo: Hashable, Sendable {
    /// Symlinks resolved.
    public let path: URL
    /// The trimmed `--version` line, for example `sigsieve 1.2.3`.
    public let version: String
}

public enum CLIError: Error, Equatable {
    /// Every path that was tried, in order.
    case notFound(searched: [String])
    case notExecutable(String)
    /// `--version` failed, was not answered in time, or printed something other than `sigsieve 1.x.y`.
    case unsupportedVersion(path: String, output: String)
}

/// Finds the CLI and checks that its major version is 1. No shell is started
/// and no shell file is read: the candidates are the user's setting, fixed
/// install locations and the app's own PATH.
public struct CLILocator: Sendable {
    let runner: Running
    let userPath: String?
    let appPATH: String?
    let fixed: [String]

    public init(runner: Running, userPath: String?, appPATH: String?,
                fixed: [String] = ["/opt/homebrew/bin/sigsieve", "/usr/local/bin/sigsieve"]) {
        self.runner = runner
        self.userPath = userPath
        self.appPATH = appPATH
        self.fixed = fixed
    }

    /// The first candidate that exists decides: a broken one is reported, not skipped.
    public func locate(environment: (URL) -> ChildEnvironment) async throws -> CLIInfo {
        let candidates = self.candidates()
        for candidate in candidates {
            guard let resolved = Self.resolve(candidate) else { continue }
            var st = stat()
            guard stat(resolved, &st) == 0, st.st_mode & S_IFMT == S_IFREG, access(resolved, X_OK) == 0
            else { throw CLIError.notExecutable(resolved) }
            let url = URL(filePath: resolved)
            let output: String
            do {
                let r = try await runner.run(.cli(url), ["--version"], environment: environment(url),
                                             stdin: nil, timeout: .seconds(5))
                guard r.exitCode == 0, Self.isSupported(r.stdout) else {
                    throw CLIError.unsupportedVersion(path: resolved, output: r.stdout)
                }
                output = r.stdout
            } catch let error as RunError {
                throw CLIError.unsupportedVersion(path: resolved, output: String(describing: error))
            }
            return CLIInfo(path: url, version: String(output.dropLast()))
        }
        throw CLIError.notFound(searched: candidates)
    }

    private func candidates() -> [String] {
        let fromPATH = (appPATH ?? "").split(separator: ":", omittingEmptySubsequences: true)
            .filter { $0.hasPrefix("/") }.map { String($0).trimmingSlash + "/sigsieve" }
        var seen = Set<String>(), result: [String] = []
        for p in (userPath.map { [$0] } ?? []) + fixed + fromPATH where seen.insert(p).inserted {
            result.append(p)
        }
        return result
    }

    private static func resolve(_ path: String) -> String? {
        guard let r = realpath(path, nil) else { return nil }
        defer { free(r) }
        return String(cString: r)
    }

    /// `sigsieve 1.<digits>.<digits>` and one newline, nothing else.
    private static func isSupported(_ output: String) -> Bool {
        output.wholeMatch(of: /sigsieve 1\.[0-9]+\.[0-9]+\n/) != nil
    }
}

private extension String {
    var trimmingSlash: String { hasSuffix("/") && count > 1 ? String(dropLast()) : self }
}
