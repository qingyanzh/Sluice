import XCTest
@testable import SluiceApp

final class GeoSiteImportTests: XCTestCase {
    @MainActor func testImportValidateAndSaveNativeGeoSiteWhileStopped() async throws {
        let binary = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("target/release/sluice")
        guard FileManager.default.isExecutableFile(atPath: binary.path) else { throw XCTSkip("Build the release core first") }
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        func field(_ number: UInt8, _ bytes: Data) -> Data {
            Data([number << 3 | 2, UInt8(bytes.count)]) + bytes
        }
        let domain = Data([8, 2]) + field(2, Data("ads.example".utf8))
        let site = field(1, Data("CATEGORY-ADS-ALL".utf8)) + field(2, domain)
        let database = root.appendingPathComponent("geosite.dat")
        try field(1, site).write(to: database)
        let base = root.appendingPathComponent("base.conf")
        try "[General]\napi-listen=127.0.0.1:0\ngeosite-db=\(database.path)\n[Rule]\nFINAL,DIRECT\n"
            .write(to: base, atomically: true, encoding: .utf8)
        let upstream = root.appendingPathComponent("upstream.yaml")
        try "proxies:\n  - {name: HK, type: trojan, server: hk.example, port: 443, password: fixture}\nproxy-groups:\n  - {name: Main, type: select, proxies: [HK]}\nrules:\n  - GEOSITE,category-ads-all,REJECT\n  - MATCH,Main\n"
            .write(to: upstream, atomically: true, encoding: .utf8)
        let suite = "GeoSiteImportTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(base.path, forKey: "configPath")
        let core = Core(defaults: defaults, profilesDirectory: root.appendingPathComponent("profiles"), discoverExisting: false)
        let originalPath = core.configPath
        let prepared = try await core.prepareProfileImport(upstream.absoluteString, name: "广告拦截")
        XCTAssertEqual(prepared.rules, 2)
        XCTAssertTrue(StructuredConfig.Rule.types.contains("GEOSITE"))
        let rule = try XCTUnwrap(StructuredConfig(prepared.text).rules.first?.value)
        XCTAssertEqual(rule.type, "GEOSITE")
        XCTAssertEqual(rule.value, "category-ads-all")
        XCTAssertEqual(rule.policy, "REJECT")
        try await core.importProfile(name: "广告拦截", text: prepared.text)
        let saved = try await core.profilePolicySnapshot("广告拦截")
        XCTAssertTrue(saved.text.contains("GEOSITE,category-ads-all,REJECT"))
        XCTAssertEqual(core.state, .stopped)
        XCTAssertEqual(core.configPath, originalPath)
    }
}
