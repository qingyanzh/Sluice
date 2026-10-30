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
        XCTAssertEqual(status.otherProxy, "another proxy (127.0.0.1:6152, 127.0.0.1:6153)")

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

    func testListenConflictExtractsOnlyTheFailedPort() {
        XCTAssertEqual(ListenConflict.port(in: "error: bind HTTP on 127.0.0.1:6252: AddrInUse: Address already in use (os error 48)"), 6252)
        XCTAssertEqual(ListenConflict.port(in: "error: bind SOCKS5 on [::1]:1080: AddrInUse: Address already in use"), 1080)
        XCTAssertEqual(ListenConflict.port(in: "error: bind api on 127.0.0.1:6170: AddrInUse: Address already in use"), 6170)
        XCTAssertNil(ListenConflict.port(in: "error: bind HTTP on 127.0.0.1:6252: PermissionDenied: Permission denied"))
        XCTAssertNil(ListenConflict.port(in: "error: connection failed"))
    }
}
