import XCTest
@testable import SluiceApp

final class LiveRatesTests: XCTestCase {
    func testExactlyOneSourceIsSelectedAcrossConnectAndDisconnect() throws {
        var source = LiveRateSource()
        let poll = try XCTUnwrap(source.lease(for: .poll))
        XCTAssertTrue(source.accepts(poll))
        XCTAssertNil(source.lease(for: .events))

        source.setConnected(true)
        let events = try XCTUnwrap(source.lease(for: .events))
        XCTAssertTrue(source.accepts(events))
        XCTAssertFalse(source.accepts(poll), "A late traffic/stats poll must not overwrite SSE rates, counts or history")
        XCTAssertNil(source.lease(for: .poll))

        source.setConnected(false)
        XCTAssertFalse(source.accepts(events))
        XCTAssertFalse(source.accepts(poll), "An old poll must stay invalid even when polling is selected again")
        XCTAssertTrue(source.accepts(try XCTUnwrap(source.lease(for: .poll))))
    }

    func testLeaseSurvivesRepeatedStateButNotReconnect() throws {
        var source = LiveRateSource()
        source.setConnected(true)
        let firstStream = try XCTUnwrap(source.lease(for: .events))
        source.setConnected(true)
        XCTAssertTrue(source.accepts(firstStream))
        source.setConnected(false)
        source.setConnected(true)
        XCTAssertFalse(source.accepts(firstStream))
        XCTAssertTrue(source.accepts(try XCTUnwrap(source.lease(for: .events))))
    }

    func testEMASeedsAndDampsAlternatingSamples() {
        var rate = RateSmoother()
        XCTAssertEqual(rate.update(100), 100)
        XCTAssertEqual(rate.update(300), 200)
        XCTAssertEqual(rate.update(100), 150)
        XCTAssertEqual(rate.update(300), 225)
    }

    func testIdleSnapsToExactlyZeroOnSecondTick() {
        var rate = RateSmoother()
        rate.update(1_000_000)
        XCTAssertEqual(rate.update(0), 500_000)
        XCTAssertEqual(rate.update(0), 0)
        XCTAssertEqual(rate.update(0), 0)
        XCTAssertEqual(rate.update(100), 50)
    }

    func testNonzeroTickBreaksZeroStreak() {
        var rate = RateSmoother()
        rate.update(100)
        rate.update(0)
        rate.update(100)
        XCTAssertEqual(rate.update(0), 37.5)
        XCTAssertEqual(rate.update(0), 0)
    }

    func testNonfiniteSamplesAreIgnoredAndNegativeRatesAreIdle() {
        var rate = RateSmoother()
        rate.update(100)
        XCTAssertEqual(rate.update(.nan), 100)
        XCTAssertEqual(rate.update(.infinity), 100)
        XCTAssertEqual(rate.update(-10), 50)
        XCTAssertEqual(rate.update(-1), 0)
    }

    func testDirectionsSmoothAndStopIndependently() {
        var rates = DisplayedRates()
        rates.update(up: 100, down: 1000)
        rates.update(up: 0, down: 2000)
        rates.update(up: 0, down: 1000)
        XCTAssertEqual(rates.up.value, 0)
        XCTAssertEqual(rates.up.formatted.text, "0 KB/s")
        XCTAssertEqual(rates.up.menuText, "0.0 KB/s")
        XCTAssertEqual(rates.down.value, 1250)
    }

    func testBinaryUnitHysteresisAroundMegabyteBoundary() {
        var formatter = RateUnitFormatter()
        let megabyte = 1024.0 * 1024
        XCTAssertEqual(formatter.format(megabyte - 1).unit, "KB")
        XCTAssertEqual(formatter.format(megabyte).unit, "MB")
        for fraction in [0.99, 1.01, 0.95, 0.9, 1.0] {
            XCTAssertEqual(formatter.format(megabyte * fraction).unit, "MB")
        }
        XCTAssertEqual(formatter.format(megabyte * 0.899).unit, "KB")
        XCTAssertEqual(formatter.format(megabyte * 0.99).unit, "KB")
        XCTAssertEqual(formatter.format(megabyte).unit, "MB")
    }

    func testDecimalMenuUnitHysteresisAndFixedPrecision() {
        var formatter = RateUnitFormatter.menuBar
        XCTAssertEqual(formatter.format(1_000_000).text, "1.0 MB/s")
        XCTAssertEqual(formatter.format(950_000).text, "1.0 MB/s")
        XCTAssertEqual(formatter.format(900_000).unit, "MB")
        XCTAssertEqual(formatter.format(899_999).unit, "KB")
        XCTAssertEqual(formatter.format(12_340_000).text, "12 MB/s")
        XCTAssertEqual(formatter.format(123_000_000).text, "123 MB/s")
        XCTAssertEqual(formatter.format(1_000_000_000).text, "1.0 GB/s")
    }

    func testUnitSelectionHandlesLargeJumpsAndResetsOnIdle() {
        var formatter = RateUnitFormatter()
        XCTAssertEqual(formatter.format(pow(1024, 4)).unit, "TB")
        XCTAssertEqual(formatter.format(1024).unit, "KB")
        XCTAssertEqual(formatter.format(0), FormattedRate(number: "0", unit: "KB"))
        XCTAssertEqual(formatter.format(.nan).text, "0 KB/s")
        XCTAssertEqual(formatter.format(-1).text, "0 KB/s")
        XCTAssertEqual(formatter.format(300).text, "0.3 KB/s")
    }
}
