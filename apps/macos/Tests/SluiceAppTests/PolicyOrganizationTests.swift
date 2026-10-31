import XCTest
@testable import SluiceApp

final class PolicyOrganizationTests: XCTestCase {
    private let text = """
    # preserve comments
    [Subscription]
    A = policy-path="file:///tmp/a"
    [Proxy Group]
    Proxy = select, Auto, DIRECT
    Auto = url-test, use=A, node-filter=HK, interval=123, tolerance=17
    Legacy = select, policy-path=legacy.txt
    [Rule]
    DOMAIN-SUFFIX,work.test,Auto
    FINAL,Proxy
    """
    private var groups: [PolicyGroup] {
        [PolicyGroup(group: "Proxy", type: "select", selected: "Auto", options: [.init(name: "Auto", latencyMs: nil), .init(name: "DIRECT", latencyMs: nil)]),
         PolicyGroup(group: "Auto", type: "url-test", selected: "@A/HK", options: [.init(name: "@A/HK", latencyMs: nil)], url: "https://example.test/", interval: 123, tolerance: 17),
         PolicyGroup(group: "Legacy", type: "select", selected: "HK", options: [.init(name: "HK", latencyMs: nil)]),
         PolicyGroup(group: "@A/group/Main", type: "select", selected: "@A/HK", options: [.init(name: "@A/HK", latencyMs: nil)]),
         PolicyGroup(group: "Unused", type: "select", selected: "DIRECT", options: [.init(name: "DIRECT", latencyMs: nil)])]
    }

    func testSectionsSeparateLocalGroupsFromEachSourceAndSearchDoesNotChangeOwnership() {
        let model = PolicyOrganization(document: StructuredConfig(text), groups: groups, nodes: [])
        XCTAssertEqual(model.sections().map(\.id), ["mine", "source:A", "source:Legacy"])
        XCTAssertEqual(model.sections().first?.groups.map(\.group), ["Proxy", "Auto", "Unused"])
        XCTAssertEqual(model.sections(filter: "A / Main").first?.id, "source:A")
        XCTAssertEqual(model.usage(of: "Proxy"), "默认出口")
        XCTAssertEqual(model.usage(of: "Auto"), "规则引用 1 · 组引用 1")
        XCTAssertEqual(model.usage(of: "Unused"), "未引用")
        XCTAssertEqual(model.chain(from: "Proxy"), ["Proxy", "Auto", "@A/HK"])
    }

    func testCopyKeepsDynamicSourcesAndProbeParametersWithoutCopyingSourceSecrets() throws {
        let model = PolicyOrganization(document: StructuredConfig(text), groups: groups, nodes: [])
        let auto = model.ownedCopy(of: groups[1], named: "MyAuto")
        XCTAssertEqual(auto.sources, ["A"])
        XCTAssertEqual(auto.nodeFilter, "HK")
        XCTAssertEqual(auto.parameter("tolerance"), "17")
        XCTAssertTrue(auto.members.isEmpty)
        let legacy = model.ownedCopy(of: groups[2], named: "MyLegacy")
        XCTAssertEqual(legacy.sources, ["Legacy"])
        XCTAssertNil(legacy.parameter("policy-path"))
        let imported = model.ownedCopy(of: groups[3], named: "MyMain")
        XCTAssertEqual(imported.members, ["@A/HK"])
    }

    func testRenamePreservesRuleOrderAndUpdatesEveryLocalReference() throws {
        var auto = try XCTUnwrap(StructuredConfig(text).groups.first { $0.value.name == "Auto" }?.value)
        auto.name = "Fast"
        let output = try PolicyChanges.upsert(auto, originalName: "Auto", usage: .init(), in: text, knownGroups: groups)
        let doc = StructuredConfig(output)
        XCTAssertEqual(doc.groups.first?.value.members, ["Fast", "DIRECT"])
        XCTAssertEqual(doc.rules.first?.value.policy, "Fast")
        XCTAssertEqual(doc.rules.last?.value.policy, "Proxy")
        XCTAssertTrue(output.hasPrefix("# preserve comments"))
    }

    func testNewGroupCanBecomeDefaultOrAddAReachableRuleAndRejectsCyclesAndDuplicates() throws {
        var group = StructuredConfig.Group(); group.name = "Work"; group.members = ["DIRECT"]
        var usage = PolicyGroupUse(); usage.mode = .defaultExit
        let madeDefault = try PolicyChanges.upsert(group, originalName: nil, usage: usage, in: text, knownGroups: groups)
        XCTAssertEqual(StructuredConfig(madeDefault).rules.last?.value.policy, "Work")
        usage.mode = .rule; usage.value = "office.test"
        let linked = try PolicyChanges.upsert(group, originalName: nil, usage: usage, in: text, knownGroups: groups)
        let rules = StructuredConfig(linked).rules.map(\.value)
        XCTAssertEqual(rules.map(\.policy), ["Auto", "Work", "Proxy"])
        var proxy = try XCTUnwrap(StructuredConfig(text).groups.first?.value)
        proxy.members = ["Proxy"]
        XCTAssertThrowsError(try PolicyChanges.upsert(proxy, originalName: "Proxy", usage: .init(), in: text, knownGroups: groups))
        group.name = "Auto"
        XCTAssertThrowsError(try PolicyChanges.upsert(group, originalName: nil, usage: .init(), in: text, knownGroups: groups))
    }

    func testSettingDefaultUpdatesMultipleFinalEntriesConsistently() {
        let output = PolicyChanges.setDefault("Work", in: "[Rule]\nFINAL,DIRECT\nFINAL,REJECT\n")
        XCTAssertEqual(StructuredConfig(output).rules.map { $0.value.policy }, ["Work", "Work"])
    }
}
