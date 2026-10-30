import AppKit
import XCTest
@testable import SluiceApp

final class MenuBarTests: XCTestCase {
    func testStatusItemWidthIsIdenticalAcrossRatesInEveryDisplayMode() {
        let samples: [Double] = [
            0, 1, 9.9, 99.9, 999, 999.99,
            1_000, 12_340, 999_900, 999_999,
            1_000_000, 12_340_000, 123_000_000, 999_900_000,
        ]
        for size: CGFloat in [9, 10] {
            let font = NSFont.monospacedDigitSystemFont(ofSize: size, weight: .regular)
            for mode in MenuBarDisplayMode.allCases {
                let layout = MenuBarLayout(mode: mode, font: font)
                let width = menuBarStatusItemWidth(mode: mode, font: font)
                var upload = RateUnitFormatter.menuBar
                var download = RateUnitFormatter.menuBar
                for (up, down) in zip(samples + samples.reversed(), samples.reversed() + samples) {
                    let upText = upload.format(up).text
                    let downText = download.format(down).text
                    for showsMode in [true, false] {
                        let image = MenuBarLabel.image(layout: layout, upload: upText, download: downText,
                                                       modeMark: "R", showsMode: showsMode, dark: false, ink: .black)
                        XCTAssertEqual(image.size.width + 12, width, "\(mode), upload \(up), download \(down)")
                        XCTAssertEqual(image.size.height, 22)
                    }
                    // Check the actual strings used by the renderer fit.
                    for row in MenuBarLabel.speedRows(mode: mode, upload: upText, download: downText) {
                        XCTAssertLessThanOrEqual((row as NSString).size(withAttributes: [.font: font]).width,
                                                 layout.speedWidth, row)
                    }
                }
            }
        }
    }

    func testWidthAccountsForDisplayModeFontAndEverySupportedUnit() {
        let font = NSFont.monospacedDigitSystemFont(ofSize: 9, weight: .regular)
        let speed = MenuBarLayout(mode: .speedOnly, font: font)
        let combined = MenuBarLayout(mode: .iconAndSpeed, font: font)
        XCTAssertEqual(combined.statusItemLength, speed.statusItemLength + 33)
        XCTAssertGreaterThan(speed.statusItemLength, menuBarStatusItemWidth(mode: .iconOnly, font: font))
        XCTAssertGreaterThan(menuBarStatusItemWidth(mode: .speedOnly,
                                                  font: .monospacedDigitSystemFont(ofSize: 12, weight: .regular)),
                             speed.statusItemLength)
        let widths = ["B", "KB", "MB", "GB", "TB"].map { unit in
            ("999.9 \(unit)/s" as NSString).size(withAttributes: [.font: font]).width
        }
        XCTAssertEqual(speed.speedWidth, ceil(widths.max()!))
        XCTAssertEqual(speed.statusItemLength, speed.speedWidth + 12)
        XCTAssertLessThan(speed.speedWidth,
                          ("↑ 999.9 MB/s" as NSString).size(withAttributes: [.font: font]).width)
        for width in widths {
            XCTAssertLessThanOrEqual(width, speed.speedWidth)
        }
    }

    func testRenderedSpeedStringsHaveNoArrowsAndKeepUploadAboveDownload() {
        let samples: [Double] = [0, 999, 1_000, 1_000_000, 1_000_000_000, 1_000_000_000_000]
        for mode in MenuBarDisplayMode.allCases {
            for rate in samples {
                let upload = menuBarSpeed(rate)
                let download = menuBarSpeed(rate * 2)
                let rows = MenuBarLabel.speedRows(mode: mode, upload: upload, download: download)
                XCTAssertEqual(rows, mode.showsSpeed ? [upload, download] : [])
                for row in rows {
                    XCTAssertFalse(row.contains { "↑↓↟↡⇑⇓⬆⬇".contains($0) }, row)
                }
            }
        }
    }

    func testFixedNumericColumnsSurviveRoundingBoundariesAndExtremeInputs() {
        var formatter = RateUnitFormatter.menuBar
        for value in [0, 999.99, 1_000, 999_999.99, 1_000_000, 999_999_999.99,
                      1_000_000_000, 1_000_000_000_000, Double.greatestFiniteMagnitude,
                      .nan, .infinity, -1] {
            let number = formatter.format(value).number
            XCTAssertEqual(number.count, 5, "\(value): \(number)")
            XCTAssertEqual(number.suffix(2).first, ".")
        }
        XCTAssertEqual(menuBarSpeed(999_999), "999.9 KB/s")
    }
}
