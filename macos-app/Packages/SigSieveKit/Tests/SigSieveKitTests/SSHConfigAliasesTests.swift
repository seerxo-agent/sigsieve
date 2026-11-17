import Foundation
import Testing
@testable import SigSieveKit

private struct Fixture {
    let home = TestDirectory.make()
    var config: URL { home.appending(path: ".ssh/config") }

    @discardableResult
    func write(_ rel: String, _ text: String) -> URL {
        let u = home.appending(path: rel)
        try! FileManager.default.createDirectory(at: u.deletingLastPathComponent(), withIntermediateDirectories: true)
        try! text.write(to: u, atomically: true, encoding: .utf8)
        return u
    }

    func aliases(_ text: String) -> [String] {
        write(".ssh/config", text)
        return SSHConfigAliases.discover(config: config, home: home).aliases.map(\.value)
    }
}

@Test func listsHostAliasesInFileOrderWithoutDuplicates() {
    #expect(Fixture().aliases("Host zeta\nHost alpha\nHost zeta\n  Host beta\n") == ["zeta", "alpha", "beta"])
}

@Test func oneLineMayNameSeveralAliases() {
    #expect(Fixture().aliases("Host a b c\n") == ["a", "b", "c"])
}

@Test func wildcardAndNegatedPatternsAreNotListed() {
    #expect(Fixture().aliases("Host * web-? !bad prod\n") == ["prod"])
}

@Test func keywordIsCaseInsensitiveAndAllowsEquals() {
    #expect(Fixture().aliases("host=a\nHOST b\nHost = c\nhOsT\t=\td\nHost \"e\"\n") == ["a", "b", "c", "d", "e"])
}

@Test func crlfLineEndingsAreAccepted() {
    #expect(Fixture().aliases("Host a\r\nHost b c\r\n") == ["a", "b", "c"])
}

@Test func commentsAndMatchBlocksAreIgnored() {
    #expect(Fixture().aliases("# Host x\nMatch host y\n  Host z\n") == ["z"])
    #expect(Fixture().aliases("# Host x\nMatch host y\n  User u\n") == [])
}

@Test func invalidAliasesAreDropped() {
    #expect(Fixture().aliases("Host -oX\nHost ok\n") == ["ok"])
}

@Test func includeIsFollowedRelativeToDotSsh() {
    let f = Fixture()
    f.write(".ssh/conf.d/b", "Host b\n")
    f.write(".ssh/conf.d/a", "Host a\n")
    f.write(".ssh/conf.d/.hidden", "Host hidden\n")
    #expect(f.aliases("Host first\nInclude conf.d/*\nHost last\n") == ["first", "a", "b", "last"])
}

@Test func includeWithTildeIsFollowed() {
    let f = Fixture()
    f.write("other/extra", "Host extra\n")
    #expect(f.aliases("Include ~/other/extra\n") == ["extra"])
}

@Test func includeInsideHostBlockIsFollowedButNotInsideMatch() {
    let f = Fixture()
    f.write(".ssh/in-host", "Host fromhost\n")
    f.write(".ssh/in-match", "Host frommatch\n")
    #expect(f.aliases("Host h\nInclude in-host\nMatch all\nInclude in-match\n") == ["h", "fromhost"])
}

@Test func unresolvableIncludeIsSkippedAndNamed() {
    let f = Fixture()
    f.write(".ssh/config", "Include ${X}/y\nInclude ~root/z\nHost a\n")
    let d = SSHConfigAliases.discover(config: f.config, home: f.home)
    #expect(d.skippedIncludes == ["${X}/y", "~root/z"])
    #expect(d.aliases.map(\.value) == ["a"])
}

@Test func selfIncludeTerminates() {
    let f = Fixture()
    #expect(f.aliases("Host a\nInclude config\nInclude ~/.ssh/config\nInclude /nonexistent/x\n") == ["a"])
}

@Test func includeChainIsDepthCapped() {
    let f = Fixture()
    for i in 1...20 { f.write(".ssh/f\(i)", "Host h\(i)\nInclude f\(i + 1)\n") }
    let names = f.aliases("Include f1\n")
    #expect(names.contains("h1"))
    #expect(!names.contains("h20"))
}

@Test func missingConfigGivesNothing() {
    let f = Fixture()
    let d = SSHConfigAliases.discover(config: f.config, home: f.home)
    #expect(d.aliases == [] && d.stamps == [] && d.skippedIncludes == [])
}

@Test func oversizedFileIsSkipped() {
    let f = Fixture()
    f.write(".ssh/config", "Host a\n" + String(repeating: "# pad\n", count: 200_000))
    let d = SSHConfigAliases.discover(config: f.config, home: f.home)
    #expect(d.aliases == [])
    #expect(d.stamps.map { URL(fileURLWithPath: $0.path).lastPathComponent } == ["config"])
}

@Test func stampsCoverEveryFileRead() {
    let f = Fixture()
    f.write(".ssh/inc", "Host b\n")
    f.write(".ssh/config", "Include inc\nInclude nothere\nHost a\n")
    let d = SSHConfigAliases.discover(config: f.config, home: f.home)
    // The missing include target is stamped too (size -1), so creating it is noticed.
    #expect(d.stamps.map { URL(fileURLWithPath: $0.path).lastPathComponent }.sorted() == ["config", "inc", "nothere"])
    #expect(d.stamps.first { $0.path.hasSuffix("nothere") }?.size == -1)
    #expect(SSHConfigAliases.currentStamps(for: d.stamps) == d.stamps)
}

@Test func stampChangesWhenAFileIsRewritten() {
    let f = Fixture()
    f.write(".ssh/config", "Host a\n")
    let d = SSHConfigAliases.discover(config: f.config, home: f.home)
    f.write(".ssh/config", "Host a\nHost bb\n")
    #expect(SSHConfigAliases.currentStamps(for: d.stamps) != d.stamps)
}

@Test func stampNotesADeletedFile() throws {
    let f = Fixture()
    f.write(".ssh/config", "Host a\n")
    let d = SSHConfigAliases.discover(config: f.config, home: f.home)
    try FileManager.default.removeItem(at: f.config)
    let now = SSHConfigAliases.currentStamps(for: d.stamps)
    #expect(now.map(\.size) == [-1])
    #expect(now.map(\.modified) == [.distantPast])
}

@Test func addingAFileToAGlobbedDirectoryChangesStamps() {
    let f = Fixture()
    f.write(".ssh/conf.d/a", "Host a\n")
    f.write(".ssh/config", "Include conf.d/*\n")
    let d = SSHConfigAliases.discover(config: f.config, home: f.home)
    #expect(SSHConfigAliases.currentStamps(for: d.stamps) == d.stamps)
    f.write(".ssh/conf.d/new", "Host n\n")
    #expect(SSHConfigAliases.currentStamps(for: d.stamps) != d.stamps)
}

@Test func creatingAMissingIncludeTargetChangesStamps() {
    let f = Fixture()
    f.write(".ssh/config", "Include later\n")
    let d = SSHConfigAliases.discover(config: f.config, home: f.home)
    #expect(SSHConfigAliases.currentStamps(for: d.stamps) == d.stamps)
    f.write(".ssh/later", "Host l\n")
    #expect(SSHConfigAliases.currentStamps(for: d.stamps) != d.stamps)
}

@Test func retargetedSymlinkIncludeIsNoticed() throws {
    let f = Fixture()
    f.write(".ssh/real1", "Host r1\n")
    f.write(".ssh/real2", "Host r2 more names here\n")
    let link = f.home.appending(path: ".ssh/link").path
    try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: f.home.appending(path: ".ssh/real1").path)
    f.write(".ssh/config", "Include real1\nInclude link\n")
    let d = SSHConfigAliases.discover(config: f.config, home: f.home)
    #expect(d.stamps.contains { $0.path.hasSuffix("/link") })
    try FileManager.default.removeItem(atPath: link)
    try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: f.home.appending(path: ".ssh/real2").path)
    #expect(SSHConfigAliases.currentStamps(for: d.stamps) != d.stamps)
}

@Test func globOverManyFilesStopsAtTheFileCap() {
    let f = Fixture()
    for i in 0..<300 { f.write(".ssh/conf.d/h\(String(format: "%03d", i))", "Host h\(String(format: "%03d", i))\n") }
    f.write(".ssh/config", "Host first\nInclude conf.d/*\n")
    let d = SSHConfigAliases.discover(config: f.config, home: f.home)
    #expect(d.aliases.count == 256) // config + 255 included files
    #expect(d.aliases.first?.value == "first" && d.aliases[1].value == "h000")
    #expect(d.skippedIncludes == ["conf.d/* (limit reached)"])
}

@Test func manyIncludeDirectivesAreCapped() {
    let f = Fixture()
    f.write(".ssh/conf.d/a", "Host a\n")
    f.write(".ssh/config", String(repeating: "Include conf.d/*\n", count: 2000))
    let d = SSHConfigAliases.discover(config: f.config, home: f.home)
    #expect(d.aliases.map(\.value) == ["a"])
    #expect(d.skippedIncludes == ["conf.d/* (limit reached)"])
    let g = Fixture()
    g.write(".ssh/config", (0..<2000).map { "Include missing\($0)\n" }.joined())
    let e = SSHConfigAliases.discover(config: g.config, home: g.home)
    #expect(e.stamps.count <= 1025)
    #expect(e.skippedIncludes.count == 1)
}

@Test func trailingCommentEndsTheArguments() {
    #expect(Fixture().aliases("Host a # note b\nHost c #d\nHost \"#e\"\n") == ["a", "c", "#e"])
}

@Test func leadingBOMIsStripped() {
    let f = Fixture()
    f.write(".ssh/config", "\u{FEFF}Host bom\n")
    #expect(SSHConfigAliases.discover(config: f.config, home: f.home).aliases.map(\.value) == ["bom"])
}

@Test func undecodableFilesStillCountAgainstTheFileCap() throws {
    let f = Fixture()
    for i in 0..<300 {
        let u = f.home.appending(path: ".ssh/conf.d/b\(String(format: "%03d", i))")
        try FileManager.default.createDirectory(at: u.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data([0xFF, 0xFE, 0xFF, 0xFE]).write(to: u)
    }
    f.write(".ssh/conf.d/z-valid", "Host late\n")
    f.write(".ssh/config", "Include conf.d/*\n")
    let d = SSHConfigAliases.discover(config: f.config, home: f.home)
    #expect(d.aliases.isEmpty)
    #expect(d.skippedIncludes == ["conf.d/* (limit reached)"])
}

@Test func includeNamingADirectoryDoesNotSpendTheBudget() {
    let f = Fixture()
    f.write(".ssh/dir/x", "Host x\n")
    f.write(".ssh/config", "Include dir\nHost a\n")
    let d = SSHConfigAliases.discover(config: f.config, home: f.home)
    #expect(d.aliases.map(\.value) == ["a"] && d.skippedIncludes == [])
    #expect(d.stamps.contains { $0.path.hasSuffix("/dir") })
}
