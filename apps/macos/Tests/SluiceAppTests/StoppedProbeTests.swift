import XCTest
@testable import SluiceApp

final class StoppedProbeTests: XCTestCase {
    private var binary: URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("target/release/sluice")
    }

    @MainActor
    func testStoppedGroupAndAllButtonsExecuteAndShareResultsWithNodeAliases() async throws {
        guard FileManager.default.isExecutableFile(atPath: binary.path) else { throw XCTSkip("Build the release core first") }
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let server = Process()
        server.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        server.arguments = ["-u", "-c", """
        import http.server
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_HEAD(self):
                self.send_response(204)
                self.end_headers()
            def log_message(self, *args): pass
        server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        print(server.server_port, flush=True)
        server.serve_forever()
        """]
        let pipe = Pipe(); server.standardOutput = pipe; server.standardError = FileHandle.nullDevice
        try server.run()
        defer { server.terminate(); server.waitUntilExit() }
        var bytes = Data()
        while let byte = try pipe.fileHandleForReading.read(upToCount: 1), !byte.isEmpty {
            if byte == Data([10]) { break }; bytes.append(byte)
        }
        let port = try XCTUnwrap(Int(String(decoding: bytes, as: UTF8.self)))
        let source = root.appendingPathComponent("nodes")
        try "HK = ss, 127.0.0.1, 2, encrypt-method=aes-256-gcm, password=fixture\n".write(to: source, atomically: true, encoding: .utf8)
        let file = root.appendingPathComponent("fixture.conf")
        try """
        [General]
        api-listen = 127.0.0.1:0
        [Proxy Group]
        Proxy = select, DIRECT, REJECT, url=http://127.0.0.1:\(port)/check
        Legacy = select, policy-path=\(source.absoluteString), url=http://127.0.0.1:\(port)/check
        [Rule]
        FINAL,Proxy
        """.write(to: file, atomically: true, encoding: .utf8)
        let suite = "StoppedProbeTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(file.path, forKey: "configPath")
        let core = Core(defaults: defaults, profilesDirectory: root.appendingPathComponent("profiles"), discoverExisting: false)
        await core.loadNodeCatalog()
        XCTAssertNil(core.catalogError)
        XCTAssertEqual(core.state, .stopped)
        XCTAssertTrue(core.canTestNodes)
        XCTAssertEqual(core.policyGroups.count, 2)
        core.test(group: "Proxy")
        XCTAssertTrue(core.testingGroups.contains("Proxy"))
        try await wait { core.testingGroups.isEmpty }
        XCTAssertNil(core.lastActionError)
        let direct = try XCTUnwrap(core.policyGroups.first { $0.group == "Proxy" }?.options.first { $0.name == "DIRECT" })
        XCTAssertGreaterThanOrEqual(try XCTUnwrap(direct.latencyMs), 0)
        XCTAssertNil(direct.error)
        XCTAssertEqual(core.nodeLatencies["REJECT"], -1)
        XCTAssertFalse(core.isActive, "A test must never start the proxy service")
        XCTAssertEqual(core.state, .stopped)
        XCTAssertEqual(core.measurementKeys(for: "@Legacy/HK"), ["@Legacy/HK", "HK"])
        core.recordMeasurement(NodeTestResult(node: "@Legacy/HK", outbound: "@Legacy/HK", ok: true,
                                             connectMs: 1, latencyMs: 123, status: 204, error: nil), for: "@Legacy/HK")
        XCTAssertEqual(core.nodeLatencies["HK"], 123)
        XCTAssertEqual(core.nodeLatencies["@Legacy/HK"], 123)
        core.testAll()
        XCTAssertFalse(core.testingGroups.isEmpty)
        try await wait { core.testingGroups.isEmpty }
        XCTAssertEqual(core.state, .stopped)
        XCTAssertFalse(core.isActive)
    }

    @MainActor private func wait(_ condition: () -> Bool) async throws {
        let deadline = ContinuousClock.now + .seconds(20)
        while !condition(), ContinuousClock.now < deadline { try await Task.sleep(for: .milliseconds(20)) }
        XCTAssertTrue(condition(), "Probe did not finish within its deadline")
    }
}
