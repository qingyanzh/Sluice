import XCTest
@testable import SluiceApp

final class LatencyTests: XCTestCase {
    func testLatencyClassificationBoundaries() {
        let cases: [(Int?, LatencyClassification)] = [
            (nil, .untested), (-1, .timeout), (Int.min, .timeout),
            (0, .good), (199, .good), (200, .ok), (499, .ok),
            (500, .slow), (Int.max, .slow),
        ]
        for (milliseconds, expected) in cases {
            XCTAssertEqual(LatencyClassification(milliseconds: milliseconds), expected, "\(String(describing: milliseconds))")
        }
    }

    func testLatencyLabelsDistinguishUntestedTimeoutAndMeasured() {
        XCTAssertEqual(latencyText(nil), "未测试")
        XCTAssertEqual(latencyText(-1), "超时")
        XCTAssertEqual(latencyText(0), "0 ms")
        XCTAssertEqual(latencyText(500), "500 ms")
    }

    func testOnlySelectGroupsAllowManualSwitching() throws {
        for type in ["select", "url-test", "fallback", "load-balance"] {
            let json = """
                {"group":"Proxy","type":"\(type)","selected":"HK","options":[
                    {"name":"HK","latency_ms":125},{"name":"US","latency_ms":-1},
                    {"name":"JP","latency_ms":null}
                ]}
                """
            let group = try JSONDecoder().decode(PolicyGroup.self, from: Data(json.utf8))
            XCTAssertEqual(group.isSelectable, type == "select")
            XCTAssertEqual(group.selected, "HK")
            XCTAssertEqual(group.options.map { LatencyClassification(milliseconds: $0.latencyMs) }, [.good, .timeout, .untested])
        }
    }
}
