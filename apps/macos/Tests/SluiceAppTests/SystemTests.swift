import XCTest
@testable import SluiceApp

final class SystemTests: XCTestCase {
    private func proxy(_ kind: String, _ host: String, _ port: Int, enabled: Bool = true) -> String {
        "  \(kind)Enable : \(enabled ? 1 : 0)\n  \(kind)Proxy : \(host)\n  \(kind)Port : \(port)\n"
    }

    func testDefaultListenersMatchAllProxyProtocols() {
        for kind in ["HTTP", "HTTPS", "SOCKS"] {
            let output = proxy(kind, "127.0.0.1", kind == "SOCKS" ? 6253 : 6252)
            let status = SystemProxy.parseStatus(output, http: nil, socks: nil)
            XCTAssertTrue(status.isSluice, kind)
            XCTAssertNil(status.otherProxy)
        }
        XCTAssertFalse(SystemProxy.parseStatus("<dictionary> {\n}", http: nil, socks: nil).isSluice)
        XCTAssertFalse(SystemProxy.parseStatus(proxy("HTTP", "127.0.0.1", 6252, enabled: false), http: nil, socks: nil).isSluice)
    }

    func testSurgeAndSamePortOnAnotherHostAreOtherProxies() {
        let surge = proxy("HTTP", "127.0.0.1", 6152) + proxy("HTTPS", "127.0.0.1", 6152) + proxy("SOCKS", "127.0.0.1", 6153)
        let status = SystemProxy.parseStatus(surge, http: nil, socks: nil)
        XCTAssertFalse(status.isSluice)
        XCTAssertEqual(status.otherProxy, "其他代理 (127.0.0.1:6152, 127.0.0.1:6153)")

        let remote = SystemProxy.parseStatus(proxy("HTTP", "192.168.1.2", 6252), http: nil, socks: nil)
        XCTAssertFalse(remote.isSluice)
        XCTAssertEqual(remote.otherAddresses, ["192.168.1.2:6252"])
    }

    func testConfiguredListenersAndMixedProxies() {
        let config = ConfigSummary(text: "[General]\nhttp-listen = 127.0.0.2:8080\nsocks5-listen = [::1]:1080\n")
        let output = proxy("HTTP", "127.0.0.2", 8080) + proxy("HTTPS", "127.0.0.2", 8080) + proxy("SOCKS", "::1", 1080)
        XCTAssertTrue(SystemProxy.parseStatus(output, http: config.httpListen, socks: config.socksListen).isSluice)
        XCTAssertFalse(SystemProxy.parseStatus(output, http: nil, socks: nil).isSluice)
        let mixed = proxy("HTTP", "127.0.0.2", 8080) + proxy("HTTPS", "127.0.0.1", 6152)
        let status = SystemProxy.parseStatus(mixed, http: config.httpListen, socks: config.socksListen)
        XCTAssertFalse(status.isSluice)
        XCTAssertEqual(status.otherAddresses, ["127.0.0.1:6152"])
        XCTAssertTrue(SystemProxy.parseStatus(proxy("HTTP", "127.0.0.1", 8080), http: "8080", socks: nil).isSluice)
    }

    func testLsofParserDeduplicatesIPv4AndIPv6Owners() {
        let output = """
        COMMAND    PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
        Surge     1234 user   12u  IPv4 0x123       0t0  TCP 127.0.0.1:6252 (LISTEN)
        Surge     1234 user   13u  IPv6 0x456       0t0  TCP [::1]:6252 (LISTEN)
        sluice    5678 user   14u  IPv6 0x789       0t0  TCP *:6252 (LISTEN)
        curl      9012 user   15u  IPv4 0xabc       0t0  TCP 127.0.0.1:6252 (ESTABLISHED)
        malformed
        """
        XCTAssertEqual(ListenConflict.parseOwners(output), [
            .init(process: "Surge", pid: 1234), .init(process: "sluice", pid: 5678)
        ])
        XCTAssertEqual(ListenConflict.parseOwners(output).first?.message(port: 6252), "端口 6252 已被 Surge(1234) 占用")
        XCTAssertTrue(ListenConflict.parseOwners("").isEmpty)
        XCTAssertTrue(ListenConflict.parseOwners("lsof: permission denied").isEmpty)
    }

    func testStoppedCoreRecognizesAnotherOwnerOfConfiguredListener() {
        let proxies = proxy("HTTP", "127.0.0.1", 6152) + proxy("HTTPS", "127.0.0.1", 6152)
        let lsof = "Surge 1234 user 12u IPv4 0x123 0t0 TCP 127.0.0.1:6152 (LISTEN)\n"
        let status = SystemProxy.parseStatus(proxies, http: "127.0.0.1:6152", socks: nil,
                                            coreRunning: false, listenerOutput: [6152: lsof])
        XCTAssertFalse(status.isSluice)
        XCTAssertEqual(status.otherAddresses, ["127.0.0.1:6152"])
        XCTAssertEqual(status.otherProxy, "其他代理 (Surge, 127.0.0.1:6152)")

        let running = SystemProxy.parseStatus(proxies, http: "127.0.0.1:6152", socks: nil,
                                             coreRunning: true, listenerOutput: [6152: lsof])
        XCTAssertTrue(running.isSluice)
        XCTAssertNil(running.otherProxy)
    }

    func testStoppedCoreKeepsWarningForUnownedOrSluiceListeners() {
        let proxies = proxy("HTTP", "127.0.0.1", 6152)
        for output in ["", "lsof: permission denied",
                       "sluice 1234 user 12u IPv4 0x123 0t0 TCP 127.0.0.1:6152 (LISTEN)"] {
            let status = SystemProxy.parseStatus(proxies, http: "127.0.0.1:6152", socks: nil,
                                                coreRunning: false, listenerOutput: [6152: output])
            XCTAssertTrue(status.isSluice)
            XCTAssertNil(status.otherProxy)
        }
    }

    func testStoppedCoreChecksSOCKSAndPreservesMixedProxyStatus() {
        let lsof = "Surge 1234 user 12u IPv6 0x123 0t0 TCP [::1]:6153 (LISTEN)\n"
        let proxies = proxy("HTTP", "127.0.0.1", 6252) + proxy("SOCKS", "::1", 6153)
        let status = SystemProxy.parseStatus(proxies, http: nil, socks: "[::1]:6153",
                                            coreRunning: false, listenerOutput: [6153: lsof])
        XCTAssertFalse(status.isSluice)
        XCTAssertEqual(status.otherProxy, "其他代理 (Surge, [::1]:6153)")
        let unrelated = SystemProxy.parseStatus(proxy("HTTP", "127.0.0.1", 6252), http: nil, socks: nil,
                                               coreRunning: false, listenerOutput: [6153: lsof])
        XCTAssertTrue(unrelated.isSluice)
    }

    func testListenConflictExtractsOnlyTheFailedPort() {
        XCTAssertEqual(ListenConflict.port(in: "error: bind HTTP on 127.0.0.1:6252: AddrInUse: Address already in use (os error 48)"), 6252)
        XCTAssertEqual(ListenConflict.port(in: "error: bind SOCKS5 on [::1]:1080: AddrInUse: Address already in use"), 1080)
        XCTAssertEqual(ListenConflict.port(in: "error: bind api on 127.0.0.1:6170: AddrInUse: Address already in use"), 6170)
        XCTAssertNil(ListenConflict.port(in: "error: bind HTTP on 127.0.0.1:6252: PermissionDenied: Permission denied"))
        XCTAssertNil(ListenConflict.port(in: "error: connection failed"))
    }
}

extension SystemTests {
    func testConfigCheckUsesGivenBinaryAndPreservesItsError() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let binary = directory.appendingPathComponent("sluice")
        let script = """
        #!/bin/sh
        [ "$1" = check ] || exit 99
        printf 'error: line 4: invalid rule in %s\\n' "$2" >&2
        exit 2
        """
        try script.write(to: binary, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: binary.path)
        let message = await ConfigValidation.check(binary: binary, path: "/tmp/invalid config.conf")
        XCTAssertEqual(message, "error: line 4: invalid rule in /tmp/invalid config.conf")
        let missing = await ConfigValidation.check(binary: nil, path: "")
        XCTAssertNotNil(missing)
        let valid = await ConfigValidation.check(binary: URL(fileURLWithPath: "/usr/bin/true"), path: "")
        XCTAssertNil(valid)
    }

    func testToolDrainsOutputLargerThanPipeBeforeWaitingForExit() async {
        let (status, output) = await runTool("/usr/bin/head", ["-c", "262144", "/dev/zero"])
        XCTAssertEqual(status, 0)
        XCTAssertEqual(output.utf8.count, 262144)
    }
}
