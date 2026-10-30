import XCTest
@testable import SluiceApp

final class E2ELaunchTests: XCTestCase {
    private let environment = ["GITHUB_ACTIONS": "true", "SLUICE_E2E": "1"]
    private func arguments(pane: String = "requests-active", address: String = "127.0.0.1:16270") -> [String] {
        ["Sluice", "-SluiceE2EAPI", address, "-SluiceE2EConfig", "/tmp/e2e/main.conf",
         "-SluiceE2EPane", pane, "-SluiceE2EReady", "/tmp/e2e/ready.json"]
    }

    func testNormalLaunchIgnoresAllScreenshotArguments() {
        for env in [[:], ["SLUICE_E2E": "1"], ["GITHUB_ACTIONS": "true"]] {
            XCTAssertNil(E2ELaunch.parse(arguments: arguments(), environment: env))
        }
    }

    func testPaneAndEndpointValidation() throws {
        let launch = try XCTUnwrap(E2ELaunch.parse(arguments: arguments(), environment: environment))
        XCTAssertEqual(launch.port, 16270)
        XCTAssertEqual(launch.pane, .requests)
        XCTAssertEqual(launch.destination, "requests-active")
        for address in ["example.com:16270", "127.0.0.1:0", "127.0.0.1:70000", "127.0.0.1:16270/path", "user@127.0.0.1:16270"] {
            XCTAssertNil(E2ELaunch.parse(arguments: arguments(address: address), environment: environment), address)
        }
        XCTAssertNil(E2ELaunch.parse(arguments: arguments(pane: "unknown"), environment: environment))
        XCTAssertNil(E2ELaunch.parse(arguments: ["Sluice", "-SluiceE2EAPI"], environment: environment))
        for destination in E2ELaunch.destinations.keys {
            XCTAssertNotNil(E2ELaunch.parse(arguments: arguments(pane: destination), environment: environment))
        }
    }

    @MainActor
    func testAttachmentUsesFixtureProfilesAndNeverOwnsAProcess() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let config = directory.appendingPathComponent("main.conf")
        try "[General]\napi-listen = 127.0.0.1:6170\nenhanced-mode = true\n".write(to: config, atomically: true, encoding: .utf8)
        try "[General]\n".write(to: directory.appendingPathComponent("alt.conf"), atomically: true, encoding: .utf8)
        let otherSuite = "E2EIsolationTests.\(UUID().uuidString)"
        let otherDefaults = UserDefaults(suiteName: otherSuite)!
        otherDefaults.set("Untouched", forKey: ProfileStore.activeNameKey)
        defer { otherDefaults.removePersistentDomain(forName: otherSuite) }
        let testResults = directory.appendingPathComponent("node-tests.json")
        try #"[{"node":"SS","ok":true,"latency_ms":7}]"#.write(to: testResults, atomically: true, encoding: .utf8)
        let launch = E2ELaunch(host: "127.0.0.1", port: 16270, config: config, destination: "nodes",
                               ready: directory.appendingPathComponent("ready.json"), nodeTests: testResults)
        let core = Core(attachment: launch)
        // The main actor is not yielded: cancel monitoring before it can do any I/O.
        defer { core.stopForQuit() }
        XCTAssertEqual(core.configPath, config.path)
        XCTAssertEqual(core.profileNames, ["alt", "main"])
        XCTAssertEqual(core.activeProfileName, "main")
        XCTAssertEqual(core.api?.port, 16270)
        XCTAssertEqual(core.requestedPane, .nodes)
        XCTAssertEqual(otherDefaults.string(forKey: ProfileStore.activeNameKey), "Untouched")
        XCTAssertEqual(core.nodeLatencies["SS"], 7)
        XCTAssertEqual(core.nodeTests["SS"]?.ok, true)
        XCTAssertFalse(core.autoStart)
        XCTAssertTrue(core.isActive)
        core.start() // Must not spawn a process, even for an enhanced-mode fixture.
        core.stop()
        core.restart()
        XCTAssertEqual(core.state, .starting)
        XCTAssertFalse(core.privileged)
    }
}
