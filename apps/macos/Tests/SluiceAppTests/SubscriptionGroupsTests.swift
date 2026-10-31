import XCTest
@testable import SluiceApp

final class SubscriptionGroupsTests: XCTestCase {
    private let text = """
    # keep this comment
    [Subscription]
    A = policy-path="file:///tmp/a.txt"
    B = policy-path="https://example.test/b?token=private"
    [Proxy Group]
    Proxy = select, DIRECT, use=A|B
    Pinned = select, @A/HK, @B/HK
    OnlyA = select, @A/HK
    Legacy = select, policy-path=legacy.txt
    [Rule]
    FINAL,Proxy
    """

    func testCatalogNodesKeepTheirReferenceMetadataAndCannotBeDeletedIndividually() throws {
        let json = #"{"id":"@A/HK%2001","source":"A","name":"HK 01","kind":"trojan","server":"::1","port":443}"#
        let item = try JSONDecoder().decode(SubscriptionNode.self, from: Data(json.utf8))
        let node = NodeRecord(subscription: item)
        XCTAssertEqual(node.reference, "@A/HK%2001")
        XCTAssertEqual(node.displayName, "HK 01")
        XCTAssertEqual(node.endpoint, "[::1]:443")
        XCTAssertEqual(node.kind, "TROJAN")
        XCTAssertFalse(node.canDelete)
        XCTAssertTrue(node.matches("A / HK"))
        XCTAssertEqual(subscriptionNodeLabel("@A/group/Auto%20Test"), "A / Auto Test · 策略组")
    }

    func testLegacyAndIndependentSourcesCanEnableOrDisableGroupImport() throws {
        let updated = ConfigText.setImportGroups(true, source: "Legacy", section: "Proxy Group", in: text)
        XCTAssertEqual(StructuredConfig(updated).groups.last?.value.importsGroups, true)
        let off = ConfigText.setImportGroups(false, source: "A", section: "Subscription", in: updated)
        let line = try XCTUnwrap(ConfigText.lines(of: "Subscription", in: off).first)
        let record = NodeRecord(line: line, id: "A", section: "Subscription")
        XCTAssertFalse(record.importsGroups)
        XCTAssertTrue(off.contains("# keep this comment"))
        XCTAssertEqual(StructuredConfig(off).groups.first?.value.sources, ["A", "B"])
    }

    func testIndependentSourcesAreNotPoliciesAndLegacySourcesRemainAvailable() {
        let document = StructuredConfig(text)
        XCTAssertEqual(document.subscriptionNames, ["A", "B", "Legacy"])
        XCTAssertFalse(document.policies.contains("A"))
        XCTAssertFalse(document.policies.contains("B"))
        XCTAssertTrue(document.policies.contains("Legacy"))
        XCTAssertEqual(ConfigSummary(text: text).subscriptionCount, 3)
    }

    func testSourceAndFilterEditsRoundtripWithoutChangingUnrelatedContent() throws {
        var document = StructuredConfig(text)
        let entry = try XCTUnwrap(document.groups.first { $0.value.name == "Proxy" })
        var group = entry.value
        group.sources = ["B", "Legacy"]
        group.nodeFilter = "^(香港|JP),01$"
        document.setGroup(group, at: entry.id)
        let saved = document.serialise()
        let parsed = try XCTUnwrap(StructuredConfig(saved).groups.first { $0.value.name == "Proxy" }?.value)
        XCTAssertEqual(parsed.sources, ["B", "Legacy"])
        XCTAssertEqual(parsed.nodeFilter, "^(香港|JP),01$")
        XCTAssertEqual(saved, text.replacingOccurrences(of: "Proxy = select, DIRECT, use=A|B", with: group.serialised))
    }

    func testDeletingSourcePrunesDynamicAndPinnedReferencesAndLeavesOtherSourcesUntouched() throws {
        let saved = ConfigText.remove("A", from: "Subscription", of: text)
        let document = StructuredConfig(saved)
        XCTAssertEqual(document.subscriptionNames, ["B", "Legacy"])
        XCTAssertEqual(document.groups.first { $0.value.name == "Proxy" }?.value.sources, ["B"])
        XCTAssertEqual(document.groups.first { $0.value.name == "Pinned" }?.value.members, ["@B/HK"])
        XCTAssertEqual(document.groups.first { $0.value.name == "OnlyA" }?.value.members, ["REJECT"])
        XCTAssertTrue(saved.contains("token=private"))
        XCTAssertTrue(saved.contains("FINAL,Proxy"))
    }

    func testAddingSourceToFinalGroupDoesNotDuplicateItOrRewriteSources() {
        let saved = ConfigText.addSourceToFinalGroup("Legacy", in: text)
        XCTAssertEqual(StructuredConfig(saved).groups.first?.value.sources, ["A", "B", "Legacy"])
        XCTAssertEqual(ConfigText.addSourceToFinalGroup("Legacy", in: saved), saved)
        XCTAssertTrue(saved.contains("# keep this comment"))
        XCTAssertEqual(ConfigText.addSourceToFinalGroup("A", in: "[Rule]\nFINAL,DIRECT\n"), "[Rule]\nFINAL,DIRECT\n")
        XCTAssertTrue(ConfigText.names(in: text).contains("A"))
    }

    func testSourceMetadataDoesNotExposeURLsAndQuotedCommasArePreserved() {
        let node = NodeRecord(line: "A = policy-path=\"https://user:secret@example.test/a,b?token=private\", policy-regex-filter=\"HK,01\"", id: "A", section: "Subscription")
        XCTAssertTrue(node.isSubscription)
        XCTAssertEqual(node.section, "Subscription")
        XCTAssertEqual(node.endpoint, "example.test")
        XCTAssertEqual(node.filter, "HK,01")
        XCTAssertNil(node.copyableEndpoint)
        XCTAssertFalse(node.matches("private"))
    }

    func testReferencesKeepTheSourceIdentityAndDisplayReadableNames() {
        let reference = subscriptionNodeReference(source: "机场 A", name: "香港/01,=|%@\n")
        XCTAssertEqual(reference, "@机场%20A/香港%2F01%2C%3D%7C%25%40%0A")
        XCTAssertEqual(subscriptionNodeLabel(reference), "机场 A / 香港/01,=|%@\n")
        XCTAssertNotEqual(subscriptionNodeReference(source: "A/B", name: "C"), subscriptionNodeReference(source: "A", name: "B/C"))
        XCTAssertEqual(subscriptionNodeLabel("DIRECT"), "DIRECT")
    }
}
