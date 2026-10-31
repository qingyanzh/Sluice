import XCTest
@testable import SluiceApp

final class PolicyWorkflowTests: XCTestCase {
    @MainActor func testReadOnlyPreviewPolicySavingDefaultRuleLinkAndIndependentImport() async throws {
        let binary = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("target/release/sluice")
        guard FileManager.default.isExecutableFile(atPath: binary.path) else { throw XCTSkip("Build the release core first") }
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("base.conf")
        try "[General]\napi-listen=127.0.0.1:0\n[Proxy Group]\nProxy = select, DIRECT, REJECT\n[Rule]\nFINAL,Proxy\n".write(to: file, atomically: true, encoding: .utf8)
        let suite = "PolicyWorkflowTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(file.path, forKey: "configPath")
        let core = Core(defaults: defaults, profilesDirectory: root.appendingPathComponent("profiles"), discoverExisting: false)
        let path = core.configPath
        let other = "# Sluice config created by the app\n[General]\napi-listen=127.0.0.1:0\nhttp-listen=127.0.0.1:6152\nsocks5-listen=127.0.0.1:6153\n[Proxy Group]\nOther = select, DIRECT\n[Rule]\nFINAL,Other\n"
        try core.createProfile(name: "Other", contents: other)
        let preview = try await core.profilePolicySnapshot("Other")
        XCTAssertEqual(preview.text, other)
        XCTAssertEqual(preview.organization.defaultPolicy, "Other")
        XCTAssertEqual(try String(contentsOfFile: preview.path, encoding: .utf8), other, "Preview must never run the legacy file migration")
        XCTAssertEqual(core.configPath, path)
        XCTAssertEqual(core.activeProfileName, "Default")
        await core.loadNodeCatalog()
        let before = core.readConfig()
        var group = StructuredConfig.Group(); group.name = "Work"; group.members = ["DIRECT"]
        let usage = PolicyGroupUse(mode: .rule, ruleType: "DOMAIN-SUFFIX", value: "office.test")
        let error = await core.savePolicyGroup(group, originalName: nil, usage: usage, path: path, expected: before, knownGroups: core.policyGroups)
        XCTAssertNil(error)
        XCTAssertEqual(StructuredConfig(core.readConfig()).rules.map { $0.value.policy }, ["Work", "Proxy"])
        let defaultError = await core.makeDefaultPolicy("Work", path: path, expected: core.readConfig())
        XCTAssertNil(defaultError)
        XCTAssertEqual(StructuredConfig(core.readConfig()).rules.last?.value.policy, "Work")
        let snapshot = core.readConfig()
        try (snapshot + "# external change\n").write(toFile: path, atomically: true, encoding: .utf8)
        group.name = "Stale"
        let stale = await core.savePolicyGroup(group, originalName: nil, usage: .init(), path: path, expected: snapshot, knownGroups: core.policyGroups)
        XCTAssertNotNil(stale)
        XCTAssertTrue(core.readConfig().hasSuffix("# external change\n"))
        XCTAssertFalse(StructuredConfig(core.readConfig()).groups.contains { $0.value.name == "Stale" })
        let importFile = root.appendingPathComponent("native.conf")
        try "[General]\napi-listen=127.0.0.1:0\n[Proxy Group]\nImported = select, REJECT\n[Rule]\nFINAL,Imported\n".write(to: importFile, atomically: true, encoding: .utf8)
        let prepared = try await core.prepareProfileImport(importFile.absoluteString)
        XCTAssertEqual(prepared.groups, 1)
        XCTAssertEqual(prepared.rules, 1)
        try await core.importProfile(name: "Imported", text: prepared.text)
        XCTAssertTrue(core.profileNames.contains("Imported"))
        XCTAssertEqual(core.configPath, path)
        XCTAssertEqual(core.activeProfileName, "Default")
        XCTAssertEqual(core.state, .stopped)
        XCTAssertFalse(core.isActive)
        let upstream = root.appendingPathComponent("upstream.yaml")
        try "proxies:\n  - {name: HK, type: trojan, server: hk.example, port: 443, password: fixture}\nproxy-groups:\n  - {name: Main, type: select, proxies: [HK]}\nrules:\n  - MATCH,Main\n".write(to: upstream, atomically: true, encoding: .utf8)
        let named = try await core.prepareProfileImport(upstream.absoluteString, name: "旅行")
        XCTAssertEqual(StructuredConfig(named.text).subscriptionNames, ["旅行"])
        XCTAssertEqual(StructuredConfig(named.text).groups[0].value.members, ["@旅行/HK"])
        try await core.importProfile(name: "旅行", text: named.text)
        XCTAssertEqual(core.configPath, path)
    }
}
