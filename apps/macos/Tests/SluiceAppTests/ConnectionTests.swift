import XCTest
@testable import SluiceApp

final class ConnectionTests: XCTestCase {
    /// The API returns a bare array in chronological order, with nullable source and process.
    private let fixture = """
        [
            {
                "id": 41, "time_ms": 1793286962123, "network": "tcp",
                "target": "example.com:443", "src": "127.0.0.1:53721",
                "rule": "DOMAIN-SUFFIX,example.com", "policy": "Proxy",
                "outbound": "HK", "process": "Safari"
            },
            {
                "id": 42, "time_ms": 1793286963456, "network": "udp",
                "target": "1.1.1.1:53", "src": null,
                "rule": "FINAL", "policy": "DIRECT",
                "outbound": "DIRECT", "process": null
            }
        ]
        """

    private func connections() throws -> [Connection] {
        try JSONDecoder().decode([Connection].self, from: Data(fixture.utf8))
    }

    func testDecodesRealConnectionArray() throws {
        let records = try connections()
        XCTAssertEqual(records.map(\.id), [41, 42])
        let tcp = records[0]
        XCTAssertEqual(tcp.proto, "TCP")
        XCTAssertEqual(tcp.target, "example.com:443")
        XCTAssertEqual(tcp.src, "127.0.0.1:53721")
        XCTAssertEqual(tcp.process, "Safari")
        XCTAssertEqual(tcp.rule, "DOMAIN-SUFFIX,example.com")
        XCTAssertEqual(tcp.policyChain, "Proxy → HK")

        let clock = DateFormatter()
        clock.dateFormat = "HH:mm:ss"
        // 2026-10-29 15:16:02.123 UTC, displayed in the user's local time zone.
        let date = try XCTUnwrap(ISO8601DateFormatter().date(from: "2026-10-29T15:16:02Z"))
        XCTAssertEqual(tcp.time, clock.string(from: date))

        let udp = records[1]
        XCTAssertEqual(udp.proto, "UDP")
        XCTAssertNil(udp.src)
        XCTAssertNil(udp.process)
        XCTAssertEqual(udp.policyChain, "DIRECT")
    }

    func testSearchMatchesProcessAndExistingFields() throws {
        let records = try connections()
        for query in ["", "sAfArI", "EXAMPLE.COM", "proxy", "hk"] {
            XCTAssertTrue(records[0].matches(query), query)
        }
        XCTAssertFalse(records[0].matches("Firefox"))
        XCTAssertTrue(records[1].matches("1.1.1.1"))
        XCTAssertFalse(records[1].matches("Safari"))
    }
}
