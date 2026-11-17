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
    #expect(d.aliases == [] && d.stamps == [])
}

@Test func stampsCoverEveryFileRead() {
    let f = Fixture()
    f.write(".ssh/inc", "Host b\n")
    f.write(".ssh/config", "Include inc\nInclude nothere\nHost a\n")
    let d = SSHConfigAliases.discover(config: f.config, home: f.home)
    #expect(d.stamps.count == 2)
    #expect(d.stamps.map { URL(fileURLWithPath: $0.path).lastPathComponent }.sorted() == ["config", "inc"])
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
