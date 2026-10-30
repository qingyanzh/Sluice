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
                        XCTAssertEqual(image.size.width + 12, width, "\(mode), ↑\(up), ↓\(down)")
                        XCTAssertEqual(image.size.height, 22)
                    }
                    // Check actual two-line content fits, including both arrows.
                    if mode.showsSpeed {
                        for row in ["↑ \(upText)", "↓ \(downText)"] {
                            XCTAssertLessThanOrEqual((row as NSString).size(withAttributes: [.font: font]).width,
                                                     layout.speedWidth, row)
                        }
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
        for unit in ["B", "KB", "MB", "GB", "TB"] {
            for arrow in ["↑", "↓"] {
                let row = "\(arrow) 999.9 \(unit)/s" as NSString
                XCTAssertLessThanOrEqual(row.size(withAttributes: [.font: font]).width, speed.speedWidth)
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
