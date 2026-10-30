import AppKit
import XCTest
@testable import SluiceApp

final class LineNumberRulerTests: XCTestCase {
    @MainActor
    func testNumbersStayOnFirstFragmentAcrossWrappingAndResize() throws {
        let view = NSTextView(frame: NSRect(x: 0, y: 0, width: 180, height: 800))
        view.font = NSFont.monospacedSystemFont(ofSize: 12.5, weight: .regular)
        view.textContainerInset = NSSize(width: 6, height: 12)
        let longLine = "P = select, " + String(repeating: "节点😀, ", count: 30)
        view.string = "[Proxy Group]\n\(longLine)\n\n[Rule]\nFINAL,P\n"
        let container = try XCTUnwrap(view.textContainer)
        container.widthTracksTextView = false
        let layout = try XCTUnwrap(view.layoutManager)
        for width in [180.0, 360.0] {
            container.containerSize = NSSize(width: width, height: .greatestFiniteMagnitude)
            let markers = LineNumberRuler.markers(in: view)
            XCTAssertEqual(markers.map(\.number), [1, 2, 3, 4, 5, 6])
            let firstHeight = markers[0].rect.height
            XCTAssertGreaterThan(markers[2].rect.minY - markers[1].rect.minY, firstHeight * 2,
                                 "The wrapped line must occupy multiple visual lines")
            XCTAssertEqual(markers[3].rect.minY - markers[2].rect.minY, firstHeight, accuracy: 0.5)
            let ruleOffset = (view.string as NSString).range(of: "[Rule]").location
            let glyph = layout.glyphIndexForCharacter(at: ruleOffset)
            let fragment = layout.lineFragmentRect(forGlyphAt: glyph, effectiveRange: nil)
            XCTAssertEqual(markers[3].rect.minY, fragment.minY + view.textContainerOrigin.y, accuracy: 0.5)
            XCTAssertGreaterThan(markers[5].rect.minY, markers[4].rect.minY, "Trailing empty line gets its own number")
        }
    }
}
