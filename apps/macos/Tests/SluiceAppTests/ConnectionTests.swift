import XCTest
@testable import SluiceApp

final class ConnectionTests: XCTestCase {
    private func decode(_ fields: String = "") throws -> Connection {
        let json = """
            {
                "id": 1, "time": "12:34:56", "proto": "TCP",
                "target": "example.com:443", "policy": "Proxy",
                "rule": "DOMAIN-SUFFIX,example.com", "outbound": "HK"
                \(fields)
            }
            """
        return try JSONDecoder().decode(Connection.self, from: Data(json.utf8))
    }

    func testDecodesConnectionWithProcess() throws {
        let connection = try decode(#", "process": "Safari", "up": 1536, "down": 1048576, "duration_ms": 42.5, "status": "active""#)
        XCTAssertEqual(connection.process, "Safari")
        XCTAssertEqual(connection.up, 1536)
        XCTAssertEqual(connection.down, 1048576)
        XCTAssertEqual(connection.durationMs, 42.5)
        XCTAssertEqual(connection.status, "active")
        XCTAssertEqual(connection.policyChain, "Proxy → HK")
    }

    func testDecodesConnectionWithoutProcess() throws {
        let connection = try decode()
        XCTAssertNil(connection.process)
        XCTAssertNil(connection.up)
        XCTAssertNil(connection.down)
        XCTAssertNil(connection.durationMs)
        XCTAssertNil(connection.status)
        XCTAssertEqual(connection.target, "example.com:443")
        XCTAssertEqual(connection.rule, "DOMAIN-SUFFIX,example.com")
    }

    func testDecodesNullProcessAndZeroTraffic() throws {
        let connection = try decode(#", "process": null, "up": 0, "down": 0"#)
        XCTAssertNil(connection.process)
        XCTAssertEqual(connection.up, 0)
        XCTAssertEqual(connection.down, 0)
    }

    func testSearchMatchesProcessAndExistingFields() throws {
        let connection = try decode(#", "process": "Safari""#)
        for query in ["", "sAfArI", "EXAMPLE.COM", "proxy", "hk"] {
            XCTAssertTrue(connection.matches(query), query)
        }
        XCTAssertFalse(connection.matches("Firefox"))
        XCTAssertTrue(try decode().matches("example.com"))
        XCTAssertFalse(try decode().matches("Safari"))
    }
}
