import XCTest
@testable import SluiceApp

final class InterfaceStateTests: XCTestCase {
    @MainActor
    func testSubscriptionValidatorAcceptsLocalFileURLs() {
        for url in ["https://example.test/sub", "http://127.0.0.1/sub", "file:///tmp/local%20nodes.txt"] {
            XCTAssertTrue(Core.isSubscriptionURL(url), url)
        }
        for url in ["/tmp/nodes.txt", "ftp://example.test/sub", ""] {
            XCTAssertFalse(Core.isSubscriptionURL(url), url)
        }
    }

    func testMenuBarSpeedUsesPaddedFixedDecimalPrecision() {
        XCTAssertEqual(menuBarSpeed(0), "  0.0 B/s")
        XCTAssertEqual(menuBarSpeed(999), "999.0 B/s")
        XCTAssertEqual(menuBarSpeed(1_000_000), "  1.0 MB/s")
        XCTAssertEqual(menuBarSpeed(12_340_000), " 12.3 MB/s")
        XCTAssertEqual(menuBarSpeed(123_000_000), "123.0 MB/s")
        XCTAssertEqual(menuBarSpeed(1_000_000_000), "  1.0 GB/s")
    }

    @MainActor
    func testDraftSurvivesNavigationAndDetectsExternalChanges() {
        let draft = ConfigDraft()
        draft.refresh(path: "a.conf", disk: "original")
        draft.text = "my edit"
        draft.refresh(path: "a.conf", disk: "original")
        XCTAssertEqual(draft.text, "my edit")
        XCTAssertFalse(draft.changedOnDisk)
        draft.refresh(path: "a.conf", disk: "external edit")
        XCTAssertEqual(draft.text, "my edit")
        XCTAssertEqual(draft.saved, "original")
        XCTAssertTrue(draft.changedOnDisk)
        draft.restore("external edit")
        XCTAssertFalse(draft.hasChanges)
        XCTAssertFalse(draft.changedOnDisk)
    }

    @MainActor
    func testUneditedDraftRefreshesAndNewFileStartsClean() {
        let draft = ConfigDraft()
        draft.refresh(path: "a.conf", disk: "old")
        draft.refresh(path: "a.conf", disk: "new")
        XCTAssertEqual(draft.text, "new")
        draft.text = "draft"
        draft.refresh(path: "b.conf", disk: "second file")
        XCTAssertEqual(draft.text, "second file")
        XCTAssertFalse(draft.hasChanges)
    }

    func testSubscriptionDisplayDoesNotExposeCredentialsOrToken() {
        let node = NodeRecord(line: "Airport = select, policy-path = https://user:secret@example.com/private?token=hidden, policy-regex-filter = HK", id: "1")
        XCTAssertTrue(node.isSubscription)
        XCTAssertEqual(node.endpoint, "example.com")
        XCTAssertEqual(node.filter, "HK")
        XCTAssertFalse(node.matches("secret"))
        XCTAssertFalse(node.matches("hidden"))
    }

    func testNodeMetadataSupportsIPv6AndTransports() {
        let node = NodeRecord(line: "HK = vless, 2001:db8::1, 443, uuid=test, tls=true, ws=true", id: "1")
        XCTAssertEqual(node.endpoint, "[2001:db8::1]:443")
        XCTAssertEqual(node.transport, "WebSocket / TLS")
        XCTAssertTrue(node.matches("vLeSs"))
        let hy2 = NodeRecord(line: "HY = hysteria2, example.com, 443, password=private", id: "2")
        XCTAssertEqual(hy2.transport, "QUIC / TLS")
    }

    func testOfflineRulesRejectMalformedIPv4AndNormalizeDomains() {
        let rules = [
            RuleRow(id: 1, type: "IP-CIDR", value: "1.2.3.0/24", policy: "DIRECT", options: ""),
            RuleRow(id: 2, type: "DOMAIN-SUFFIX", value: "example.com", policy: "Proxy", options: ""),
            RuleRow(id: 3, type: "FINAL", value: "", policy: "REJECT", options: ""),
        ]
        XCTAssertEqual(RuleMatcher.match("1.bad.2.3.4", in: rules)?.policy, "REJECT")
        XCTAssertEqual(RuleMatcher.match("1..2.3.4", in: rules)?.policy, "REJECT")
        XCTAssertEqual(RuleMatcher.match("1.2.3.4:80", in: rules)?.policy, "DIRECT")
        XCTAssertEqual(RuleMatcher.match("WWW.Example.com.:443", in: rules)?.policy, "Proxy")
    }
}
