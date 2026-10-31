import AppKit
import XCTest
@testable import SluiceApp

final class MenuColumnLayoutTests: XCTestCase {
    @MainActor func testDetailsUseTheTrailingGutterWithoutMovingSubmenuArrowsAway() throws {
        let menu = NSMenu(); menu.autoenablesItems = false
        let first = NSMenuItem(title: "出站模式", action: nil, keyEquivalent: "")
        first.submenu = NSMenu(title: "出站模式"); menu.addItem(first)
        let second = NSMenuItem(title: "默认选择", action: nil, keyEquivalent: "")
        second.submenu = NSMenu(title: "默认选择"); menu.addItem(second)
        menu.addItem(NSMenuItem(title: "复制终端代理命令", action: nil, keyEquivalent: ""))
        MenuBarStatusItem.alignRightColumn(of: menu, [
            .init(item: first, name: "出站模式", detail: "R"),
            .init(item: second, name: "默认选择", detail: "Hong Kong | 01"),
        ])
        let title = try XCTUnwrap(second.attributedTitle)
        let attachment = try XCTUnwrap(title.attribute(.attachment, at: title.length - 1, effectiveRange: nil) as? NSTextAttachment)
        XCTAssertEqual(first.attributedTitle?.size().width, title.size().width, "Details must share one trailing column")
        let menuWidth = menu.size.width
        let textWidth = title.size().width
        let cell = try XCTUnwrap(attachment.attachmentCell as? TrailingMenuDetailCell)
        XCTAssertEqual(cell.trailingInset, 0, "The parent title area already reserves its arrow column")
        for width: CGFloat in [180, 260, 400] {
            let bounds = NSRect(x: 0, y: 0, width: width, height: 20)
            let frame = cell.drawingFrame(NSRect(x: 70, y: 0, width: 60, height: 16), in: bounds)
            XCTAssertEqual(frame.maxX, bounds.maxX, "Content must follow the actual menu width")
        }
        XCTAssertEqual(title.size().width, textWidth)
        XCTAssertEqual(menu.size.width, menuWidth, "Drawing in the gutter must not push the arrow away")
    }

    @MainActor func testOptionMenusKeepTheirOwnTrailingMargin() throws {
        let menu = NSMenu()
        let item = NSMenuItem(title: "Hong Kong", action: nil, keyEquivalent: "")
        menu.addItem(item)
        MenuBarStatusItem.alignRightColumn(of: menu, [.init(item: item, name: "Hong Kong", detail: "1462 ms")])
        let title = try XCTUnwrap(item.attributedTitle)
        let attachment = try XCTUnwrap(title.attribute(.attachment, at: title.length - 1, effectiveRange: nil) as? NSTextAttachment)
        let cell = try XCTUnwrap(attachment.attachmentCell as? TrailingMenuDetailCell)
        XCTAssertEqual(cell.trailingInset, 8)
        let frame = cell.drawingFrame(NSRect(x: 50, y: 0, width: 60, height: 16), in: NSRect(x: 0, y: 0, width: 240, height: 20))
        XCTAssertEqual(frame.maxX, 232)
    }
}
