import XCTest
@testable import SluiceApp

final class ConfigTextRemoveTests: XCTestCase {
    private let text = """
        [Proxy]
        HK = ss, hk.example, 8388, encrypt-method=aes-256-gcm, password=x
        JP = ss, jp.example, 8388, encrypt-method=aes-256-gcm, password=x

        [Proxy Group]
        Proxy = select, DIRECT, Airport, HK, JP
        Airport = select, policy-path=https://sub.example/s?token=t
        Media = select, Proxy, Airport

        [Rule]
        FINAL,Proxy
        """

    func testRemovingASubscriptionDropsItsGroupAndEveryReference() {
        let out = ConfigText.remove("Airport", from: "Proxy Group", of: text)
        XCTAssertFalse(out.contains("policy-path"))
        XCTAssertTrue(out.contains("Proxy = select, DIRECT, HK, JP"))
        XCTAssertTrue(out.contains("Media = select, Proxy"))
        XCTAssertFalse(out.contains("Airport"))
        XCTAssertTrue(out.contains("HK = ss"), "nodes are untouched")
    }

    func testRemovingANodeKeepsSimilarNamesAndOtherSections() {
        let out = ConfigText.remove("HK", from: "Proxy", of: text + "\nHKG = ss, x, 1, encrypt-method=aes-256-gcm, password=x")
        XCTAssertFalse(out.contains("HK = ss"))
        XCTAssertTrue(out.contains("HKG = ss"), "only the exact name is removed")
        XCTAssertTrue(out.contains("Proxy = select, DIRECT, Airport, JP"))
        XCTAssertTrue(out.contains("FINAL,Proxy"))
    }

    func testUnknownNameLeavesTextUnchanged() {
        XCTAssertEqual(ConfigText.remove("Nope", from: "Proxy", of: text), text)
    }
}
