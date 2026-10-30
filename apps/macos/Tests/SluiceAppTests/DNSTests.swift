import XCTest
@testable import SluiceApp

final class DNSTests: XCTestCase {
    func testDecodesRealCacheResponse() throws {
        let json = """
            {"entries":[
                {"name":"example.com","type":"A","ttl":59,"answers":["93.184.215.14","93.184.215.15"]},
                {"name":"example.com","type":"AAAA","ttl":0,"answers":["2001:db8::1"]},
                {"name":"empty.example","type":"A","ttl":12,"answers":[]}
            ]}
            """
        let cache = try JSONDecoder().decode(DNSCache.self, from: Data(json.utf8))
        XCTAssertEqual(cache.entries.count, 3)
        let entry = cache.entries[0]
        XCTAssertEqual(entry.name, "example.com")
        XCTAssertEqual(entry.type, "A")
        XCTAssertEqual(entry.ttl, 59)
        XCTAssertEqual(entry.answers, ["93.184.215.14", "93.184.215.15"])
        XCTAssertEqual(cache.entries[1].ttl, 0)
        XCTAssertEqual(cache.entries[1].answers, ["2001:db8::1"])
        XCTAssertTrue(cache.entries[2].answers.isEmpty)
        XCTAssertNotEqual(entry.id, cache.entries[1].id)
        for query in ["", "EXAMPLE.COM", "a", "215.15"] {
            XCTAssertTrue(entry.matches(query), query)
        }
        XCTAssertFalse(entry.matches("other.example"))
    }

    func testDecodesEmptyCacheAndFlushResult() throws {
        let cache = try JSONDecoder().decode(DNSCache.self, from: Data(#"{"entries":[]}"#.utf8))
        XCTAssertTrue(cache.entries.isEmpty)
        let result = try JSONDecoder().decode(DNSFlushResult.self, from: Data(#"{"flushed":3}"#.utf8))
        XCTAssertEqual(result.flushed, 3)
    }
}
