import XCTest
@testable import SluiceApp

final class SubscriptionRenameTests: XCTestCase {
    func testRenameMovesOnlySourceReferencesAndKeepsOtherContent() throws {
        let text = """
        # @A/HK must remain a comment
        [Subscription]
        A = policy-path="https://example.test/@A/HK", import-groups=false, future="keep,me"
        B = policy-path="file:///tmp/b"
        [Proxy Group]
        Main = select, @A/HK, @A/group/Auto, @B/HK, use=A|B
        Same = select, DIRECT
        [Rule]
        DOMAIN,old.example,@A/HK,no-resolve
        FINAL,Main
        """
        let renamed = try SubscriptionChanges.rename("A", to: "工作 A", in: text)
        let doc = StructuredConfig(renamed)
        XCTAssertEqual(doc.subscriptionNames, ["工作 A", "B"])
        XCTAssertEqual(doc.groups[0].value.sources, ["工作 A", "B"])
        XCTAssertEqual(doc.groups[0].value.members, ["@工作%20A/HK", "@工作%20A/group/Auto", "@B/HK"])
        XCTAssertEqual(doc.rules[0].value.policy, "@工作%20A/HK")
        XCTAssertEqual(doc.rules[0].value.options, "no-resolve")
        XCTAssertTrue(renamed.contains("https://example.test/@A/HK"))
        XCTAssertTrue(renamed.contains("# @A/HK must remain a comment"))
        XCTAssertTrue(renamed.contains("future=\"keep,me\""))
        XCTAssertThrowsError(try SubscriptionChanges.rename("A", to: "Same", in: text))
        for name in ["A|B", "DIRECT", "#hidden", "@reserved", "A,B"] {
            XCTAssertThrowsError(try SubscriptionChanges.rename("A", to: name, in: text))
        }
    }

    func testLegacySourceRenamingIncludesTheGroupIdentity() throws {
        let text = "[Proxy Group]\nOld = select, policy-path=nodes.txt, future=yes\nMain = select, Old, @Old/HK, use=Old\n[Rule]\nFINAL,Old\n"
        let changed = try SubscriptionChanges.rename("Old", to: "New", in: text)
        let doc = StructuredConfig(changed)
        XCTAssertEqual(doc.groups[0].value.name, "New")
        XCTAssertEqual(doc.groups[0].value.parameter("policy-path"), "nodes.txt")
        XCTAssertEqual(doc.groups[0].value.parameter("future"), "yes")
        XCTAssertEqual(doc.groups[1].value.members, ["New", "@New/HK"])
        XCTAssertEqual(doc.groups[1].value.sources, ["New"])
        XCTAssertEqual(doc.rules[0].value.policy, "New")
    }

    @MainActor func testStoppedRenamePreservesSelectionsAndUnknownSourceSettings() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let nodes = root.appendingPathComponent("nodes.txt")
        try "HK = trojan, hk.example, 443, password=fixture\n".write(to: nodes, atomically: true, encoding: .utf8)
        let config = root.appendingPathComponent("base.conf")
        let text = "[General]\napi-listen=127.0.0.1:0\n[Subscription]\nA = policy-path=\"\(nodes.absoluteString)\", import-groups=false, future=yes\n[Proxy Group]\nMain = select, DIRECT, @A/HK, use=A\n[Rule]\nFINAL,Main\n"
        try text.write(to: config, atomically: true, encoding: .utf8)
        let suite = "SubscriptionRename.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(config.path, forKey: "configPath")
        let core = Core(defaults: defaults, profilesDirectory: root.appendingPathComponent("profiles"), discoverExisting: false)
        let selections = URL(fileURLWithPath: core.configPath).appendingPathExtension("selections.json")
        try JSONEncoder().encode(["Main": "@A/HK"]).write(to: selections)
        let source = try XCTUnwrap(SubscriptionSource.all(in: core.readConfig(), statuses: []).first)
        let error = await core.renameSubscription(source, to: "工作")
        XCTAssertNil(error)
        XCTAssertEqual(StructuredConfig(core.readConfig()).groups[0].value.sources, ["工作"])
        XCTAssertTrue(core.readConfig().contains("import-groups=false, future=yes"))
        XCTAssertEqual(try JSONDecoder().decode([String: String].self, from: Data(contentsOf: selections)), ["Main": "@工作/HK"])
        XCTAssertEqual(core.catalogNodes.first?.id, "@工作/HK")
        XCTAssertEqual(core.state, .stopped)
    }
}
