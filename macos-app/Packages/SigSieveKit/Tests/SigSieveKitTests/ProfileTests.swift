import Foundation
import Testing
@testable import SigSieveKit

private func tmp() -> URL {
    TestDirectory.make()
}

private func mode(_ u: URL) -> mode_t {
    var st = stat()
    precondition(lstat(u.path, &st) == 0)
    return st.st_mode & 0o7777
}

private func fp(_ c: Character) -> Fingerprint { Fingerprint("SHA256:" + String(repeating: c, count: 42) + "A")! }

private let sample = Profile(server: HostInput("build-host")!, agent: .secretive,
                             forwardedKeys: [fp("a")], mode: .filtering, destinations: [])

private let binding = Profile(server: HostInput("deploy@10.0.0.5")!, agent: .openssh(socket: "/tmp/a b/agent.sock"),
                              forwardedKeys: [fp("b"), fp("c")], mode: .binding,
                              destinations: [Destination(name: "github.com", hostKeys: [fp("d"), fp("e")])])

private func isUnreadable(_ e: any Error) -> Bool {
    if case .unreadable = e as? ProfileStoreError { return true }
    return false
}

private func isWriteFailed(_ e: any Error) -> Bool {
    if case .writeFailed = e as? ProfileStoreError { return true }
    return false
}

private func isInvalidProfiles(_ e: any Error) -> Bool {
    if case .invalidProfiles = e as? ProfileStoreError { return true }
    return false
}

private func file(_ dir: URL) -> URL { dir.appending(path: "profiles.json") }

/// Writes `body`, then checks that load and save both refuse with `check` and the bytes stay the same.
private func expectRefusedAndUntouched(_ body: String, _ check: (any Error) -> Bool) throws {
    let dir = tmp()
    try Data(body.utf8).write(to: file(dir))
    let store = ProfileStore(directory: dir)
    #expect(performing: { try store.load() }, throws: check)
    #expect(performing: { try store.save([sample]) }, throws: check)
    #expect(try Data(contentsOf: file(dir)) == Data(body.utf8))
    #expect(try FileManager.default.contentsOfDirectory(atPath: dir.path) == ["profiles.json"])
}

// MARK: - Plan tests

@Test func saveCreatesPrivateDirectoryAndFile() throws {
    let dir = tmp().appending(path: "SigSieve")
    try ProfileStore(directory: dir).save([sample])
    #expect(mode(dir) == 0o700)
    #expect(mode(file(dir)) == 0o600)
    #expect(try ProfileStore(directory: dir).load() == [sample])
}

@Test func missingFileLoadsAsEmpty() throws {
    #expect(try ProfileStore(directory: tmp()).load() == [])
    #expect(try ProfileStore(directory: tmp().appending(path: "absent")).load() == [])
}

@Test func saveLeavesNoTemporaryFileBehind() throws {
    let dir = tmp()
    let store = ProfileStore(directory: dir)
    try store.save([sample])
    try store.save([sample, binding])
    #expect(try FileManager.default.contentsOfDirectory(atPath: dir.path) == ["profiles.json"])
}

@Test(arguments: [
    "",
    "{",
    "not json",
    "[]",
    "{\"profiles\":[]}",                                                    // no schemaVersion
    "{\"schemaVersion\":\"1\",\"profiles\":[]}",                            // version not a number
    "{\"schemaVersion\":1}",                                                // no profiles
    "{\"schemaVersion\":1,\"profiles\":[{\"server\":\"-x\"}]}",
    "{\"schemaVersion\":1,\"profiles\":[{\"server\":\"h\",\"agent\":{\"kind\":\"secretive\"},\"forwardedKeys\":[\"SHA256:x\"],\"mode\":\"filtering\",\"destinations\":[]}]}",
    "{\"schemaVersion\":1,\"profiles\":[{\"server\":\"h\",\"agent\":{\"kind\":\"gpg\"},\"forwardedKeys\":[],\"mode\":\"filtering\",\"destinations\":[]}]}",
    "{\"schemaVersion\":1,\"profiles\":[{\"server\":\"h\",\"agent\":{\"kind\":\"openssh\",\"socket\":\"rel/s\"},\"forwardedKeys\":[],\"mode\":\"filtering\",\"destinations\":[]}]}",
    "{\"schemaVersion\":1,\"profiles\":[{\"server\":\"h\",\"agent\":{\"kind\":\"openssh\"},\"forwardedKeys\":[],\"mode\":\"filtering\",\"destinations\":[]}]}",
    "{\"schemaVersion\":1,\"profiles\":[{\"server\":\"h\",\"agent\":{\"kind\":\"secretive\"},\"forwardedKeys\":[],\"mode\":\"open\",\"destinations\":[]}]}",
])
func unreadableFileIsNeverOverwritten(_ body: String) throws {
    try expectRefusedAndUntouched(body, isUnreadable)
}

@Test func truncatedValidFileIsNeverOverwritten() throws {
    let dir = tmp()
    try ProfileStore(directory: dir).save([sample, binding])
    let full = try Data(contentsOf: file(dir))
    try expectRefusedAndUntouched(String(decoding: full.prefix(full.count / 2), as: UTF8.self), isUnreadable)
}

@Test(arguments: [2, 99, 0, -1])
func otherSchemaVersionIsNeverOverwritten(_ v: Int) throws {
    try expectRefusedAndUntouched("{\"schemaVersion\":\(v),\"profiles\":[]}") {
        ($0 as? ProfileStoreError) == .unsupportedVersion(v)
    }
}

@Test func newerSchemaWithUnknownShapeIsReportedAsVersionNotUnreadable() throws {
    // A future file may change everything but schemaVersion; the user should
    // be told it is newer, not that it is broken.
    try expectRefusedAndUntouched("{\"schemaVersion\":2,\"profiles\":{\"x\":1}}") {
        ($0 as? ProfileStoreError) == .unsupportedVersion(2)
    }
}

@Test func aServerWithoutProfileForwardsNothing() {
    let p = Profile.empty(for: HostInput("h")!, agent: .secretive)
    #expect(p.forwardedKeys.isEmpty)
    #expect(p.mode == .filtering)
    #expect(p.destinations.isEmpty)
}

// MARK: - File format and permissions

@Test func fileHasTheDocumentedPlainShape() throws {
    let dir = tmp()
    try ProfileStore(directory: dir).save([sample, binding])
    let json = try JSONSerialization.jsonObject(with: Data(contentsOf: file(dir))) as! [String: Any]
    #expect(json["schemaVersion"] as? Int == 1)
    let profiles = json["profiles"] as! [[String: Any]]
    #expect(profiles[0]["server"] as? String == "build-host")
    #expect(profiles[0]["agent"] as? [String: String] == ["kind": "secretive"])
    #expect(profiles[0]["forwardedKeys"] as? [String] == [fp("a").value])
    #expect(profiles[0]["mode"] as? String == "filtering")
    #expect(profiles[1]["agent"] as? [String: String] == ["kind": "openssh", "socket": "/tmp/a b/agent.sock"])
    #expect(profiles[1]["mode"] as? String == "binding")
    let dest = (profiles[1]["destinations"] as! [[String: Any]])[0]
    #expect(dest["name"] as? String == "github.com")
    #expect(dest["hostKeys"] as? [String] == [fp("d").value, fp("e").value])
}

@Test func roundTripKeepsOrderAndEveryField() throws {
    let dir = tmp()
    try ProfileStore(directory: dir).save([binding, sample])
    #expect(try ProfileStore(directory: dir).load() == [binding, sample])
}

@Test func existingLoosePermissionsAreTightened() throws {
    let dir = tmp()
    chmod(dir.path, 0o755)
    try Data("{\"schemaVersion\":1,\"profiles\":[]}".utf8).write(to: file(dir))
    chmod(file(dir).path, 0o644)
    try ProfileStore(directory: dir).save([sample])
    #expect(mode(dir) == 0o700)
    #expect(mode(file(dir)) == 0o600)
}

@Test func saveReplacesTheFileRatherThanWritingIntoIt() throws {
    // A hard link to the old file keeps the old bytes: the new content went to
    // a new inode that was renamed into place.
    let dir = tmp()
    let store = ProfileStore(directory: dir)
    try store.save([sample])
    let before = try Data(contentsOf: file(dir))
    let alias = dir.appending(path: "old-link")
    #expect(Darwin.link(file(dir).path, alias.path) == 0)
    try store.save([binding])
    #expect(try Data(contentsOf: alias) == before)
    #expect(try store.load() == [binding])
}

@Test func emptyListSavesAndLoads() throws {
    let dir = tmp()
    try ProfileStore(directory: dir).save([sample])
    try ProfileStore(directory: dir).save([])
    #expect(try ProfileStore(directory: dir).load() == [])
}

// MARK: - Duplicates

@Test func duplicateServerInFileIsUnreadable() throws {
    let p = "{\"server\":\"h\",\"agent\":{\"kind\":\"secretive\"},\"forwardedKeys\":[],\"mode\":\"filtering\",\"destinations\":[]}"
    try expectRefusedAndUntouched("{\"schemaVersion\":1,\"profiles\":[\(p),\(p)]}", isUnreadable)
}

@Test func savingDuplicateServersIsRefusedAndWritesNothing() throws {
    let dir = tmp()
    let store = ProfileStore(directory: dir)
    try store.save([sample])
    let before = try Data(contentsOf: file(dir))
    #expect(performing: { try store.save([sample, sample]) }, throws: isInvalidProfiles)
    #expect(try Data(contentsOf: file(dir)) == before)
    #expect(try FileManager.default.contentsOfDirectory(atPath: dir.path) == ["profiles.json"])
}

@Test func canonicallyEquivalentServersAreNotDuplicates() throws {
    let dir = tmp()
    let a = Profile.empty(for: HostInput("h\u{E9}")!, agent: .secretive)
    let b = Profile.empty(for: HostInput("he\u{301}")!, agent: .secretive)
    try ProfileStore(directory: dir).save([a, b])
    #expect(try ProfileStore(directory: dir).load().map(\.server.value) == [a.server.value, b.server.value])
}

@Test func defaultDirectoryIsApplicationSupportSigSieve() {
    #expect(ProfileStore.defaultDirectory.path.hasSuffix("/Library/Application Support/SigSieve"))
}

// MARK: - Review regressions

private func message(_ e: any Error) -> String? {
    if case .unreadable(let m) = e as? ProfileStoreError { return m }
    return nil
}

@Test func symlinkedFileIsRefusedAndBothEndsAreUntouched() throws {
    // load() would follow the link but save()'s rename would replace it,
    // splitting the two files; refuse instead.
    let dir = tmp()
    let target = dir.appending(path: "target.json")
    let body = Data("{\"schemaVersion\":1,\"profiles\":[]}".utf8)
    try body.write(to: target)
    try FileManager.default.createSymbolicLink(at: file(dir), withDestinationURL: target)
    let store = ProfileStore(directory: dir)
    #expect(performing: { try store.load() }, throws: { message($0)?.contains("not a regular file") == true })
    #expect(performing: { try store.save([sample]) }, throws: isUnreadable)
    #expect(try FileManager.default.destinationOfSymbolicLink(atPath: file(dir).path) == target.path)
    #expect(try Data(contentsOf: target) == body)
}

@Test func danglingSymlinkIsRefusedNotTreatedAsMissing() throws {
    let dir = tmp()
    try FileManager.default.createSymbolicLink(at: file(dir), withDestinationURL: dir.appending(path: "gone"))
    let store = ProfileStore(directory: dir)
    #expect(performing: { try store.load() }, throws: isUnreadable)
    #expect(performing: { try store.save([sample]) }, throws: isUnreadable)
    #expect(try FileManager.default.destinationOfSymbolicLink(atPath: file(dir).path) == dir.appending(path: "gone").path)
}

@Test func directoryOrFifoAtTheFilePathIsRefused() throws {
    let a = tmp()
    try FileManager.default.createDirectory(at: file(a), withIntermediateDirectories: false)
    #expect(performing: { try ProfileStore(directory: a).save([sample]) }, throws: isUnreadable)
    var isDir: ObjCBool = false
    #expect(FileManager.default.fileExists(atPath: file(a).path, isDirectory: &isDir) && isDir.boolValue)

    let b = tmp()
    #expect(mkfifo(file(b).path, 0o600) == 0)
    #expect(performing: { try ProfileStore(directory: b).load() }, throws: isUnreadable) // refused, does not block
}

@Test func unreadablePermissionsAreRefusedAndBytesKept() throws {
    let dir = tmp()
    let body = Data("{\"schemaVersion\":1,\"profiles\":[]}".utf8)
    try body.write(to: file(dir))
    chmod(file(dir).path, 0o000)
    defer { chmod(file(dir).path, 0o600) }
    let store = ProfileStore(directory: dir)
    #expect(performing: { try store.load() }, throws: { message($0)?.contains("ermission denied") == true })
    #expect(performing: { try store.save([sample]) }, throws: isUnreadable)
    chmod(file(dir).path, 0o600)
    #expect(try Data(contentsOf: file(dir)) == body)
}

@Test func oversizedFileIsRefusedAndKept() throws {
    let dir = tmp()
    let body = Data(repeating: 0x20, count: Int(ProfileStore.maxFileSize) + 1)
    try body.write(to: file(dir))
    #expect(performing: { try ProfileStore(directory: dir).save([sample]) }, throws: isUnreadable)
    #expect(try Data(contentsOf: file(dir)) == body)
}

@Test func badInMemoryListBlamesTheListNotTheFile() throws {
    let dir = tmp()
    #expect(performing: { try ProfileStore(directory: dir).save([sample, sample]) },
            throws: { $0 as? ProfileStoreError == .invalidProfiles("profiles to save: more than one profile for build-host") })
}

@Test(arguments: ["/tmp/\u{202E}kcos", "/tmp/a\u{200B}b", "/tmp/a\nb", "relative", "/"])
func socketPathMustBeAbsoluteAndVisible(_ socket: String) throws {
    let dir = tmp()
    let p = Profile.empty(for: HostInput("h")!, agent: .openssh(socket: socket))
    #expect(performing: { try ProfileStore(directory: dir).save([p]) }, throws: isInvalidProfiles)
    #expect(!FileManager.default.fileExists(atPath: file(dir).path))
}

// MARK: - writeFailed and the profile directory

@Test func unwritableParentIsAWriteFailureNotAnUnreadableFile() throws {
    let parent = tmp()
    chmod(parent.path, 0o500)
    defer { chmod(parent.path, 0o700) }
    let dir = parent.appending(path: "SigSieve")
    #expect(try ProfileStore(directory: dir).load() == [])
    #expect(performing: { try ProfileStore(directory: dir).save([sample]) },
            throws: { e in isWriteFailed(e) && "\(e)".contains("ermission denied") })
    #expect(!FileManager.default.fileExists(atPath: dir.path))
}

@Test func failedTemporaryFileCreationKeepsTheExistingFile() throws {
    // An immutable 0700 directory: the existing file reads fine and the mode
    // needs no change, but the temporary file cannot be created.
    let dir = tmp()
    let store = ProfileStore(directory: dir)
    try store.save([sample])
    let before = try Data(contentsOf: file(dir))
    #expect(chflags(dir.path, UInt32(UF_IMMUTABLE)) == 0)
    defer { chflags(dir.path, 0) }
    #expect(performing: { try store.save([binding]) },
            throws: { e in isWriteFailed(e) && "\(e)".contains(".tmp: open failed") })
    chflags(dir.path, 0)
    #expect(try Data(contentsOf: file(dir)) == before)
    #expect(try FileManager.default.contentsOfDirectory(atPath: dir.path) == ["profiles.json"])
}

@Test func symlinkedDirectoryIsRefusedAndItsTargetIsUntouched() throws {
    let root = tmp()
    let target = root.appending(path: "elsewhere")
    try FileManager.default.createDirectory(at: target, withIntermediateDirectories: false)
    let body = Data("{\"schemaVersion\":1,\"profiles\":[]}".utf8)
    try body.write(to: file(target))
    chmod(target.path, 0o755)
    chmod(file(target).path, 0o644)
    let link = root.appending(path: "SigSieve")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)

    let store = ProfileStore(directory: link)
    #expect(performing: { try store.load() }, throws: { message($0)?.contains("not a directory") == true })
    #expect(performing: { try store.save([sample]) }, throws: isUnreadable)

    #expect(mode(target) == 0o755)
    #expect(mode(file(target)) == 0o644)
    #expect(try Data(contentsOf: file(target)) == body)
    #expect(try FileManager.default.contentsOfDirectory(atPath: target.path) == ["profiles.json"])
    #expect(try FileManager.default.destinationOfSymbolicLink(atPath: link.path) == target.path)
}

@Test func danglingDirectorySymlinkIsRefusedAndNothingIsCreated() throws {
    let root = tmp()
    let missing = root.appending(path: "not-yet")
    let link = root.appending(path: "SigSieve")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: missing)
    #expect(performing: { try ProfileStore(directory: link).save([sample]) }, throws: isUnreadable)
    #expect(!FileManager.default.fileExists(atPath: missing.path))
}

@Test func directoryThatIsAFileIsRefused() throws {
    let root = tmp()
    let notDir = root.appending(path: "SigSieve")
    try Data("x".utf8).write(to: notDir)
    #expect(performing: { try ProfileStore(directory: notDir).save([sample]) }, throws: isUnreadable)
    #expect(try Data(contentsOf: notDir) == Data("x".utf8))
}

@Test func failedRenameIsAWriteFailureAndRemovesTheTemporaryFile() throws {
    // An immutable profiles.json reads fine and the temp file is written, but
    // the rename over it fails: the late error path and its cleanup.
    let dir = tmp()
    let store = ProfileStore(directory: dir)
    try store.save([sample])
    let before = try Data(contentsOf: file(dir))
    #expect(chflags(file(dir).path, UInt32(UF_IMMUTABLE)) == 0)
    defer { chflags(file(dir).path, 0) }
    #expect(performing: { try store.save([binding]) },
            throws: { e in isWriteFailed(e) && "\(e)".contains("rename failed") })
    #expect(try Data(contentsOf: file(dir)) == before)
    #expect(try FileManager.default.contentsOfDirectory(atPath: dir.path) == ["profiles.json"])
}

@Test func searchOnlyDirectoryStillSavesAndIsTightened() throws {
    // Mode 0100: no read permission. The directory is opened for search only,
    // so loading and saving work and the mode is repaired to 0700.
    let dir = tmp()
    let store = ProfileStore(directory: dir)
    try store.save([sample])
    chmod(dir.path, 0o100)
    defer { chmod(dir.path, 0o700) }
    #expect(try store.load() == [sample])
    try store.save([binding])
    #expect(mode(dir) == 0o700)
    #expect(try store.load() == [binding])
}

@Test func invalidListIsInvalidProfilesNotAWriteOrReadError() throws {
    // Owner rule: a list that fails validation is neither a disk write failure
    // nor an unreadable file, even when the directory does not exist yet.
    for dir in [tmp(), tmp().appending(path: "absent")] {
        let store = ProfileStore(directory: dir)
        let dup = Profile.empty(for: HostInput("h")!, agent: .secretive)
        let e = #expect(throws: ProfileStoreError.self) { try store.save([dup, dup]) }
        #expect(e == .invalidProfiles("profiles to save: more than one profile for h"))
        #expect(!FileManager.default.fileExists(atPath: store.file.path))
    }
}

@Test(arguments: [".", ".."])
func dotComponentCannotBypassTheSymlinkRule(_ dot: String) throws {
    // "link/." would resolve through the link even with O_NOFOLLOW.
    let root = tmp()
    let target = root.appending(path: "elsewhere")
    try FileManager.default.createDirectory(at: target.appending(path: "inner"), withIntermediateDirectories: true)
    chmod(target.path, 0o755)
    let link = root.appending(path: "SigSieve")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
    let dir = URL(filePath: link.path + "/" + (dot == "." ? "." : "inner/.."))
    let store = ProfileStore(directory: dir)
    #expect(performing: { try store.load() }, throws: isUnreadable)
    #expect(performing: { try store.save([sample]) }, throws: isUnreadable)
    #expect(mode(target) == 0o755)
    #expect(try FileManager.default.contentsOfDirectory(atPath: target.path) == ["inner"])
}
