import XCTest
@testable import SluiceApp

final class GeneratedConfigTests: XCTestCase {
    /// The local check runner asks the actual app generators for configs, rather
    /// than maintaining copies which can silently drift from the UI.
    @MainActor
    func testDumpGeneratedConfigs() throws {
        var configs = ["starter": Core.starterConfig]
        for kind in StructuredConfig.Group.types {
            var document = StructuredConfig(Core.starterConfig)
            var group = StructuredConfig.Group()
            group.name = "Generated"
            group.type = kind
            group.members = ["DIRECT", "REJECT"]
            if group.isAutomatic {
                group.url = "http://127.0.0.1:9/health"
                group.interval = "3600"
            }
            document.setGroup(group)
            var rule = StructuredConfig.Rule()
            rule.type = "DOMAIN"
            rule.value = "generated.test"
            rule.policy = group.name
            document.setRule(rule)
            let text = document.serialise()
            XCTAssertEqual(StructuredConfig(text).groups.last?.value, group)
            XCTAssertTrue(StructuredConfig(text).rules.contains { $0.value == rule })
            configs[kind] = text
        }
        if let path = ProcessInfo.processInfo.environment["SLUICE_GENERATED_CONFIG_DIR"] {
            let directory = URL(fileURLWithPath: path, isDirectory: true)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            for (name, text) in configs {
                try text.write(to: directory.appendingPathComponent(name + ".conf"), atomically: true, encoding: .utf8)
            }
        }
    }
}
