import XCTest
@testable import SluiceApp

final class StructuredConfigTests: XCTestCase {
    func testLosslessRoundTripIncludingUnicodeAndMixedLineEndings() {
        for text in ["", "\n", "\r\n", "\r", "# 注释\r\n[Rule]\n\tDOMAIN,例子.test,DIRECT\r; keep\nFINAL,Proxy", "[Unknown]\nx=y\n"] {
            XCTAssertEqual(StructuredConfig(text).serialise(), text)
        }
    }

    func testExampleConfigurationsRoundTripAndNoOpEditsAreLossless() throws {
        for name in ["sluice", "tun-test"] {
            let url = try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "conf", subdirectory: "Fixtures"))
            let text = try String(contentsOf: url, encoding: .utf8)
            var document = StructuredConfig(text)
            XCTAssertFalse(document.rules.isEmpty)
            XCTAssertEqual(document.unparsedCount(in: "Rule"), 0)
            XCTAssertEqual(document.unparsedCount(in: "Proxy Group"), 0)
            for entry in document.rules { document.setRule(entry.value, at: entry.id) }
            for entry in document.groups { document.setGroup(entry.value, at: entry.id) }
            XCTAssertEqual(document.serialise(), text)
            if name == "sluice" {
                XCTAssertEqual(document.groups.count, 4)
                XCTAssertEqual(document.rules.count, 10)
                XCTAssertEqual(document.groups[1].value.interval, "300")
                XCTAssertTrue(document.policies.contains("HK-SS"))
            }
        }
    }

    func testEveryCoreRuleTypeAndNestedConditions() throws {
        let values: [String: String] = [
            "DOMAIN": "example.com", "DOMAIN-SUFFIX": "example.com", "DOMAIN-KEYWORD": "ads",
            "IP-CIDR": "10.0.0.0/8", "IP-CIDR6": "2001:db8::/32", "GEOIP": "CN", "IP-ASN": "AS13335",
            "RULE-SET": "rules/local.list", "DOMAIN-SET": "https://example.com/domains.txt",
            "DST-PORT": "443", "DEST-PORT": "80-90", "IN-PORT": "6152", "SRC-IP": "192.168.1.2",
            "PROTOCOL": "TCP", "PROCESS-NAME": "Safari", "URL-REGEX": "^https://(a|b).example/(foo,bar)$",
            "AND": "((DOMAIN,example.com),(OR,((DST-PORT,443),(DST-PORT,80))))",
            "OR": "((DOMAIN,a.test),(DOMAIN,b.test))", "NOT": "((DOMAIN,ads.test))",
        ]
        XCTAssertEqual(Set(values.keys).union(["FINAL"]), Set(StructuredConfig.Rule.types))
        for (type, value) in values {
            let rule = try XCTUnwrap(StructuredConfig.Rule(line: "\(type),\(value),Proxy,no-resolve,future-option"))
            XCTAssertEqual(rule.type, type)
            XCTAssertEqual(rule.value, value)
            XCTAssertEqual(rule.policy, "Proxy")
            XCTAssertEqual(rule.options, "no-resolve,future-option")
            XCTAssertEqual(StructuredConfig.Rule(line: rule.serialised), rule)
        }
        let final = try XCTUnwrap(StructuredConfig.Rule(line: "final,Proxy,extra"))
        XCTAssertTrue(final.isFinal)
        XCTAssertEqual(final.value, "")
        XCTAssertEqual(final.options, "extra")
        XCTAssertEqual(final.serialised, "final,Proxy,extra")
    }

    func testUnsupportedAndIncompleteLinesStayInText() {
        let text = "[Rule]\n# comment\n; comment\n// comment\n\nUNKNOWN,a,b\nDOMAIN,,DIRECT\nFINAL,\nDOMAIN,ok.test,DIRECT\n[Proxy Group]\nFuture = new-type, DIRECT\nbroken\nEmpty =\nGood = select, DIRECT\n"
        let document = StructuredConfig(text)
        XCTAssertEqual(document.rules.count, 1)
        XCTAssertEqual(document.groups.count, 1)
        XCTAssertEqual(document.unparsedCount(in: "Rule"), 3)
        XCTAssertEqual(document.unparsedCount(in: "Proxy Group"), 3)
        XCTAssertEqual(document.serialise(), text)
    }

    func testRuleEditChangesOnlyItsLine() throws {
        let text = "# original\r\n[General]\r\nx = y\r\n[Rule]\r\n# before\r\n  DOMAIN,old.test,DIRECT\r\n; after\nFINAL,Proxy\r\n[Host]\r\nx=1.2.3.4"
        var document = StructuredConfig(text)
        let entry = try XCTUnwrap(document.rules.first)
        var rule = entry.value
        rule.type = "IP-CIDR6"
        rule.value = "2001:db8::/32"
        rule.policy = "Proxy"
        rule.options = "no-resolve"
        document.setRule(rule, at: entry.id)
        XCTAssertEqual(document.serialise(), text.replacingOccurrences(of: "DOMAIN,old.test,DIRECT", with: "IP-CIDR6,2001:db8::/32,Proxy,no-resolve"))
        XCTAssertEqual(StructuredConfig(document.serialise()).rules.first?.value, rule)
    }

    func testNoOpEditsPreserveSpacingAndCapitalization() throws {
        let text = "[Rule]\n domain , example.com , Proxy , no-resolve \n[Proxy Group]\n  Proxy  = SELECT , URL = \"https://example.test/?a=b\" , DIRECT , interval = 60 , future = yes \n"
        var document = StructuredConfig(text)
        let rule = try XCTUnwrap(document.rules.first)
        let group = try XCTUnwrap(document.groups.first)
        document.setRule(rule.value, at: rule.id)
        document.setGroup(group.value, at: group.id)
        XCTAssertEqual(document.serialise(), text)
    }

    func testSwitchingRuleToFinalClearsHiddenValueAndRoundTrips() throws {
        var rule = try XCTUnwrap(StructuredConfig.Rule(line: "DOMAIN,old.test,DIRECT,no-resolve"))
        rule.type = "FINAL"
        rule.policy = " Proxy "
        rule.normalise()
        XCTAssertEqual(rule.value, "")
        XCTAssertEqual(rule.serialised, "FINAL,Proxy,no-resolve")
        XCTAssertEqual(StructuredConfig.Rule(line: rule.serialised), rule)
        rule.type = "DOMAIN-SUFFIX"
        rule.value = " new.test "
        rule.normalise()
        XCTAssertEqual(StructuredConfig.Rule(line: rule.serialised), rule)
    }

    func testNewRulePrecedesFinalAcrossRepeatedSections() throws {
        let text = "[Rule]\n# final comment\nFINAL,DIRECT\n[Host]\nx=1.2.3.4\n[Rule]\n# another section\n"
        var document = StructuredConfig(text)
        let rule = try XCTUnwrap(StructuredConfig.Rule(line: "DOMAIN,new.test,REJECT"))
        document.setRule(rule)
        XCTAssertEqual(document.serialise(), text.replacingOccurrences(of: "FINAL,DIRECT", with: "DOMAIN,new.test,REJECT\nFINAL,DIRECT"))
    }

    func testAddingToExistingSectionPreservesFollowingSection() throws {
        var document = StructuredConfig("[Rule]\r\n# keep\r\n[Host]\r\nx=1.2.3.4")
        document.setRule(try XCTUnwrap(StructuredConfig.Rule(line: "FINAL,DIRECT")))
        XCTAssertEqual(document.serialise(), "[Rule]\r\n# keep\r\nFINAL,DIRECT\r\n[Host]\r\nx=1.2.3.4")
    }

    func testAddingMissingSectionsAndUnterminatedLastLine() throws {
        var document = StructuredConfig("[General]\r\nx=y")
        document.setRule(try XCTUnwrap(StructuredConfig.Rule(line: "FINAL,DIRECT")))
        XCTAssertEqual(document.serialise(), "[General]\r\nx=y\r\n[Rule]\r\nFINAL,DIRECT\r\n")
        var empty = StructuredConfig("")
        empty.setGroup(try XCTUnwrap(StructuredConfig.Group(line: "Proxy = select, DIRECT")))
        XCTAssertEqual(empty.serialise(), "[Proxy Group]\nProxy = select, DIRECT\n")
        var unterminated = StructuredConfig("[Rule]\nDOMAIN,a.test,DIRECT")
        unterminated.setRule(try XCTUnwrap(StructuredConfig.Rule(line: "FINAL,DIRECT")))
        XCTAssertEqual(unterminated.serialise(), "[Rule]\nDOMAIN,a.test,DIRECT\nFINAL,DIRECT\n")
    }

    func testRuleDeletePreservesCommentsBlankLinesAndOtherSections() throws {
        let text = "[Rule]\n# before\nDOMAIN,a.test,DIRECT\n\n; after\nFINAL,DIRECT\n[Host]\nx=1.2.3.4\n"
        var document = StructuredConfig(text)
        document.delete(try XCTUnwrap(document.rules.first).id, in: "Rule")
        XCTAssertEqual(document.serialise(), text.replacingOccurrences(of: "DOMAIN,a.test,DIRECT\n", with: ""))
    }

    func testRuleReorderKeepsCommentsAndLineEndingsInPlace() throws {
        let text = "[Rule]\r\nDOMAIN,a.test,DIRECT\r\n# between\n\nDOMAIN,b.test,REJECT\nFINAL,DIRECT"
        var document = StructuredConfig(text)
        document.move(try XCTUnwrap(document.rules.first).id, by: 1, in: "Rule")
        XCTAssertEqual(document.serialise(), "[Rule]\r\nDOMAIN,b.test,REJECT\r\n# between\n\nDOMAIN,a.test,DIRECT\nFINAL,DIRECT")
        document.move(document.rules[1].id, by: -1, in: "Rule")
        XCTAssertEqual(document.serialise(), text)
        document.move(document.rules[0].id, by: -1, in: "Rule")
        document.move(document.rules[2].id, by: 1, in: "Rule")
        document.move(999, by: 1, in: "Rule")
        XCTAssertEqual(document.serialise(), text)
    }

    func testGroupParsingMatchesCoreAndPreservesFutureParameters() throws {
        for type in StructuredConfig.Group.types {
            let group = try XCTUnwrap(StructuredConfig.Group(line: "机场 = \(type.uppercased()), DIRECT, Proxy, URL = \"https://example.test/check?a=b\", interval=300, tolerance=50, policy-path=./airport.txt, policy-regex-filter=香港|HK, update-interval=86400, future=yes"))
            XCTAssertEqual(group.name, "机场")
            XCTAssertEqual(group.members, ["DIRECT", "Proxy"])
            XCTAssertEqual(group.url, "https://example.test/check?a=b")
            XCTAssertEqual(group.interval, "300")
            XCTAssertEqual(group.parameter("policy-path"), "./airport.txt")
            XCTAssertEqual(group.parameters.count, 7)
            XCTAssertEqual(StructuredConfig.Group(line: group.serialised), group)
        }
        let subscription = try XCTUnwrap(StructuredConfig.Group(line: "Airport = url-test, policy-path=https://example.test/sub"))
        XCTAssertTrue(subscription.members.isEmpty)
        // The core unquotes double quotes only and uses the last duplicate key.
        var duplicate = try XCTUnwrap(StructuredConfig.Group(line: "Auto = url-test, DIRECT, interval=10, INTERVAL = \"20\", url='literal'"))
        XCTAssertEqual(duplicate.interval, "20")
        XCTAssertEqual(duplicate.url, "'literal'")
        duplicate.interval = "30"
        XCTAssertEqual(duplicate.interval, "30")
        duplicate.interval = ""
        XCTAssertNil(duplicate.parameter("interval"))
        XCTAssertFalse(duplicate.parameters.contains { $0.lowercased().hasPrefix("interval") })
    }

    func testGroupEditChangesOnlyItsLineAndRetainsSubscriptionParameters() throws {
        let original = "Auto = url-test, A, B, url=\"https://old.test\", interval=60, tolerance=50, policy-path=./airport.txt, policy-regex-filter=HK|JP, update-interval=900, future=yes"
        let text = "[Proxy]\nA=ss,h,1\n[Proxy Group]\n# keep\n\t\(original)\r\n; keep too\nOther = select, DIRECT\n[Rule]\nFINAL,Auto"
        var document = StructuredConfig(text)
        let entry = try XCTUnwrap(document.groups.first)
        var group = entry.value
        group.name = "Backup"
        group.type = "fallback"
        group.members = ["B", "DIRECT", "A"]
        group.url = "https://new.test/check"
        group.interval = "120"
        document.setGroup(group, at: entry.id)
        XCTAssertEqual(document.serialise(), text.replacingOccurrences(of: original, with: group.serialised))
        let reparsed = try XCTUnwrap(StructuredConfig(document.serialise()).groups.first).value
        XCTAssertEqual(reparsed, group)
        XCTAssertEqual(reparsed.parameter("policy-path"), "./airport.txt")
        XCTAssertEqual(reparsed.parameter("policy-regex-filter"), "HK|JP")
        XCTAssertEqual(reparsed.parameter("future"), "yes")
    }

    func testUnchangedGroupFieldsKeepOriginalParameterTokens() throws {
        var group = try XCTUnwrap(StructuredConfig.Group(line: "Auto = url-test, DIRECT, URL = \"https://test\", interval = \"60\", tolerance=50"))
        let original = group
        group.url = "https://test"
        group.interval = "60"
        XCTAssertEqual(group, original)
        group.url = ""
        XCTAssertNil(group.parameter("url"))
        group.url = "https://new.test"
        XCTAssertEqual(StructuredConfig.Group(line: group.serialised), group)
    }

    func testGroupAddDeleteAndReorderPreserveOtherText() throws {
        let text = "[Proxy Group]\nA = select, DIRECT\n# between\nB = fallback, DIRECT\n[Rule]\nFINAL,A\n"
        var document = StructuredConfig(text)
        document.move(try XCTUnwrap(document.groups.last).id, by: -1, in: "Proxy Group")
        XCTAssertEqual(document.serialise(), "[Proxy Group]\nB = fallback, DIRECT\n# between\nA = select, DIRECT\n[Rule]\nFINAL,A\n")
        document.delete(document.groups.first!.id, in: "Proxy Group")
        let group = try XCTUnwrap(StructuredConfig.Group(line: "C = load-balance, DIRECT"))
        document.setGroup(group)
        XCTAssertEqual(document.serialise(), "[Proxy Group]\n# between\nA = select, DIRECT\nC = load-balance, DIRECT\n[Rule]\nFINAL,A\n")
        XCTAssertEqual(StructuredConfig(document.serialise()).groups.last?.value, group)
    }

    func testPolicyChoicesIncludeBuiltinsGroupsAndProxiesWithoutCommentsOrDuplicates() {
        let document = StructuredConfig("[Proxy]\n# Secret = ss,h,1\nA = ss,h,1\nDIRECT = direct\n[Proxy Group]\nProxy = select, A, DIRECT\nAuto = url-test, A\n[Rule]\nFINAL,Proxy\n")
        XCTAssertEqual(document.policies, ["DIRECT", "REJECT", "Proxy", "Auto", "A"])
    }

    func testStaleOrWrongSectionIdentifiersCannotEditOtherSections() throws {
        let text = "[General]\nx=y\n[Rule]\nFINAL,DIRECT\n[Proxy Group]\nProxy = select, DIRECT\n"
        var document = StructuredConfig(text)
        document.setRule(try XCTUnwrap(StructuredConfig.Rule(line: "FINAL,REJECT")), at: document.groups[0].id)
        document.setGroup(try XCTUnwrap(StructuredConfig.Group(line: "Other = select, REJECT")), at: document.rules[0].id)
        document.delete(1, in: "Rule")
        document.delete(999, in: "Proxy Group")
        XCTAssertEqual(document.serialise(), text)
    }

    @MainActor
    func testStructuredEditsShareThePersistentTextDraft() throws {
        let draft = ConfigDraft()
        let original = "[Rule]\nFINAL,DIRECT\n"
        draft.refresh(path: "test.conf", disk: original)
        var document = StructuredConfig(draft.text)
        document.setRule(try XCTUnwrap(StructuredConfig.Rule(line: "DOMAIN,example.test,REJECT")))
        draft.text = document.serialise()
        XCTAssertTrue(draft.hasChanges)
        draft.refresh(path: "test.conf", disk: original)
        XCTAssertEqual(StructuredConfig(draft.text).rules.first?.value.policy, "REJECT")
        XCTAssertEqual(draft.saved, original)
        draft.restore(original)
        XCTAssertEqual(StructuredConfig(draft.text).rules.count, 1)
        XCTAssertFalse(draft.hasChanges)
    }
}
