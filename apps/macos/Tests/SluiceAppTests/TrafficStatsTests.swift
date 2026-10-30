import XCTest
@testable import SluiceApp

final class TrafficStatsTests: XCTestCase {
    func testDecodesStatsContractAndSparsePolicyRates() throws {
        let json = #"""
        {
          "up": 9007199254740993, "down": 12000, "active": 3,
          "policies": [{"name":"代理","up":1234,"down":10000}, {"name":"DIRECT","up":100,"down":2000}],
          "nodes": [{"name":"HK","up":1234,"down":10000}],
          "history": [
            {"time_ms":1793286962123,"up":100,"down":500,"policies":[{"policy":"代理","up":80,"down":400}]},
            {"time_ms":1793286963123,"up":0,"down":0,"policies":[]},
            {"time_ms":1793286964123,"up":30,"down":60,"policies":[{"policy":"DIRECT","up":30,"down":60}]}
          ]
        }
        """#
        let stats = try JSONDecoder().decode(TrafficStats.self, from: Data(json.utf8))
        XCTAssertEqual(stats.up, 9_007_199_254_740_993) // Totals retain UInt64 precision.
        XCTAssertEqual(stats.down, 12000)
        XCTAssertEqual(stats.active, 3)
        XCTAssertEqual(stats.policies.map(\.name), ["代理", "DIRECT"])
        XCTAssertEqual(stats.policies[0].up, 1234)
        XCTAssertEqual(stats.policies[1].down, 2000)
        XCTAssertEqual(stats.nodes[0].name, "HK")
        XCTAssertEqual(stats.nodes[0].up, 1234)
        XCTAssertEqual(stats.nodes[0].down, 10000)
        XCTAssertEqual(stats.history.map(\.timeMs), [1793286962123, 1793286963123, 1793286964123])
        XCTAssertEqual(stats.rates(for: nil).map(\.down), [500, 0, 60])
        XCTAssertEqual(stats.rates(for: "代理").map(\.up), [80, 0, 0])
        XCTAssertEqual(stats.rates(for: "代理").map(\.down), [400, 0, 0])
        XCTAssertEqual(stats.rates(for: "DIRECT").map(\.down), [0, 0, 60])
        XCTAssertEqual(stats.rates(for: nil)[0].time.timeIntervalSince1970, 1793286962.123, accuracy: 0.0001)
        XCTAssertEqual(stats.policyNames, ["DIRECT", "代理"])
    }

    func testDecodesEmptyStatsAtStartup() throws {
        let json = #"{"up":0,"down":0,"active":0,"policies":[],"nodes":[],"history":[]}"#
        let stats = try JSONDecoder().decode(TrafficStats.self, from: Data(json.utf8))
        XCTAssertTrue(stats.rates(for: nil).isEmpty)
        XCTAssertTrue(stats.policyNames.isEmpty)
    }

    func testPolicyPickerIncludesTotalsAndHistoryWithoutDuplicates() throws {
        let json = #"""
        {
          "up":100,"down":200,"active":1,
          "policies":[{"name":"DIRECT","up":100,"down":200},{"name":"Idle","up":0,"down":0}],
          "nodes":[],
          "history":[
            {"time_ms":1000,"up":10,"down":20,"policies":[{"policy":"Historical","up":10,"down":20}]},
            {"time_ms":2000,"up":10,"down":20,"policies":[{"policy":"DIRECT","up":10,"down":20}]}
          ]
        }
        """#
        let stats = try JSONDecoder().decode(TrafficStats.self, from: Data(json.utf8))
        XCTAssertEqual(stats.policyNames, ["DIRECT", "Historical", "Idle"])
        XCTAssertEqual(stats.rates(for: "Idle").map(\.up), [0, 0])
        XCTAssertEqual(stats.rates(for: "Historical").map(\.down), [20, 0])
        XCTAssertEqual(stats.rates(for: nil).map(\.up), [10, 10])
    }

    func testMalformedStatsAreRejectedInsteadOfBecomingEmptyHistory() {
        for json in [
            #"{"up":0,"down":0,"active":0,"policies":[],"nodes":[]}"#,
            #"{"up":-1,"down":0,"active":0,"policies":[],"nodes":[],"history":[]}"#,
            #"{"up":0,"down":0,"active":0,"policies":[],"nodes":[],"history":[{"time_ms":1000,"up":0,"down":0}]}"#,
        ] {
            XCTAssertThrowsError(try JSONDecoder().decode(TrafficStats.self, from: Data(json.utf8)))
        }
    }

    func testRingUsesElapsedTimeAndIncludesIdleSamples() {
        var ring = TrafficHistory()
        record(&ring, second: 0, up: 100, down: 200)
        XCTAssertTrue(ring.samples.isEmpty) // No rate until a baseline exists.
        record(&ring, second: 0.3, up: 130, down: 260)
        XCTAssertTrue(ring.samples.isEmpty)
        record(&ring, second: 2, up: 300, down: 600)
        XCTAssertEqual(ring.samples.count, 1)
        XCTAssertEqual(ring.samples[0].up, 100)
        XCTAssertEqual(ring.samples[0].down, 200)
        record(&ring, second: 3, up: 300, down: 600)
        XCTAssertEqual(ring.samples.last?.up, 0)
        XCTAssertEqual(ring.samples.last?.down, 0)
    }

    func testRingWrapsInChronologicalOrderAndRetainsOnly600Seconds() {
        var ring = TrafficHistory()
        for second in 0...1205 {
            record(&ring, second: Double(second), up: UInt64(second * 10), down: UInt64(second * 20))
        }
        XCTAssertEqual(ring.samples.count, 600)
        XCTAssertEqual(ring.samples.first?.time, date(606))
        XCTAssertEqual(ring.samples.last?.time, date(1205))
        XCTAssertTrue(ring.samples.allSatisfy { $0.up == 10 && $0.down == 20 })
        record(&ring, second: 2000, up: 12060, down: 24120)
        XCTAssertEqual(ring.samples.count, 1)
        XCTAssertEqual(ring.samples[0].up, 10.0 / 795, accuracy: 0.000001)
    }

    func testCounterResetClearsHistoryAndEstablishesNewBaseline() {
        for resetUpload in [true, false] {
            var ring = TrafficHistory()
            record(&ring, second: 0, up: 100, down: 200)
            record(&ring, second: 1, up: 200, down: 400)
            record(&ring, second: 2, up: resetUpload ? 0 : 200, down: resetUpload ? 400 : 0)
            XCTAssertTrue(ring.samples.isEmpty)
            record(&ring, second: 3, up: resetUpload ? 10 : 210, down: resetUpload ? 420 : 20)
            XCTAssertEqual(ring.samples.last?.up, 10)
            XCTAssertEqual(ring.samples.last?.down, 20)
        }
    }

    func testDuplicateAndOutOfOrderTimesDoNotChangeBaseline() {
        var ring = TrafficHistory()
        record(&ring, second: 10, up: 100, down: 200)
        record(&ring, second: 10, up: 800, down: 900)
        record(&ring, second: 9, up: 0, down: 0)
        record(&ring, second: 11, up: 110, down: 220)
        XCTAssertEqual(ring.samples.count, 1)
        XCTAssertEqual(ring.samples[0].up, 10)
        XCTAssertEqual(ring.samples[0].down, 20)
    }

    func testRingSubtractsLargeCountersBeforeConvertingToFloatingPoint() {
        var ring = TrafficHistory()
        record(&ring, second: 0, up: UInt64.max - 10, down: UInt64.max - 20)
        record(&ring, second: 1, up: UInt64.max, down: UInt64.max)
        XCTAssertEqual(ring.samples.first?.up, 10)
        XCTAssertEqual(ring.samples.first?.down, 20)
        record(&ring, second: 2, up: 0, down: 0)
        XCTAssertTrue(ring.samples.isEmpty)
        record(&ring, second: 3, up: 1, down: 2)
        XCTAssertEqual(ring.samples.first?.up, 1)
        XCTAssertEqual(ring.samples.first?.down, 2)
    }

    private func date(_ second: Double) -> Date {
        Date(timeIntervalSince1970: 1_700_000_000 + second)
    }

    private func record(_ ring: inout TrafficHistory, second: Double, up: UInt64, down: UInt64) {
        ring.record(Traffic(up: up, down: down, active: 0), at: date(second))
    }
}
