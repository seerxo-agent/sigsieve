import Foundation

/// A fresh directory for one test, under one root that this test process
/// creates and removes again at exit. Nothing outside that root is touched;
/// a crashed run leaves its root behind.
enum TestDirectory {
    // Short names: TempDir paths must stay within 70 bytes, and the per-user
    // temporary directory itself takes 54 ("/private/var/folders/xx/<28>/T").
    private static let root: URL = {
        let fm = FileManager.default
        let base = fm.temporaryDirectory
        var r: URL
        repeat {
            r = base.appending(path: "k_" + String(UUID().uuidString.prefix(4)))
        } while fm.fileExists(atPath: r.path)
        try! fm.createDirectory(at: r, withIntermediateDirectories: false)
        chmod(r.path, 0o700)
        rootPath = r.path
        atexit { if let p = TestDirectory.rootPath { TestDirectory.removeTree(p) } }
        return r
    }()

    nonisolated(unsafe) private static var rootPath: String?

    static func make() -> URL {
        let u = root.appending(path: String(UUID().uuidString.prefix(4)))
        try! FileManager.default.createDirectory(at: u, withIntermediateDirectories: false)
        chmod(u.path, 0o700)
        return u
    }

    /// Tests leave restrictive modes and flags behind; restore them inside the
    /// root so removal works. Symbolic links are not followed.
    private static func removeTree(_ root: String) {
        if let e = FileManager.default.enumerator(atPath: root) {
            for case let rel as String in e {
                let p = root + "/" + rel
                var st = stat()
                guard lstat(p, &st) == 0, st.st_mode & S_IFMT != S_IFLNK else { continue }
                chflags(p, 0)
                if st.st_mode & S_IFMT == S_IFDIR { chmod(p, 0o700) }
            }
        }
        chflags(root, 0)
        chmod(root, 0o700)
        try? FileManager.default.removeItem(atPath: root)
    }
}
