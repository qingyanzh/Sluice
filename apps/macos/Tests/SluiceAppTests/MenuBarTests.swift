import AppKit
import Combine
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
        XCTAssertEqual(combined.statusItemLength, speed.statusItemLength + 25)
        XCTAssertGreaterThan(speed.statusItemLength, menuBarStatusItemWidth(mode: .iconOnly, font: font))
        XCTAssertGreaterThan(menuBarStatusItemWidth(mode: .speedOnly,
                                                  font: .monospacedDigitSystemFont(ofSize: 12, weight: .regular)),
                             speed.statusItemLength)
        let widths = ["KB", "MB", "GB", "TB"].map { unit in "999 \(unit)/s" }.map {
            ($0 as NSString).size(withAttributes: [.font: font]).width
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
            // At most three digits: "9.9" or "999", never "1000".
            XCTAssertLessThanOrEqual(number.count, 3, "\(value): \(number)")
            XCTAssertLessThanOrEqual(Double(number) ?? .infinity, 999, "\(value): \(number)")
        }
        XCTAssertEqual(menuBarSpeed(999_999), "999 KB/s")
    }

    private var directory: URL!
    private var defaults: UserDefaults!
    private var suite: String!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let config = directory.appendingPathComponent("sluice.conf")
        try "[General]\n".write(to: config, atomically: true, encoding: .utf8)
        suite = "MenuBarTests.\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: suite)!
        defaults.set(config.path, forKey: "configPath")
    }

    override func tearDownWithError() throws {
        defaults.removePersistentDomain(forName: suite)
        try FileManager.default.removeItem(at: directory)
    }

    @MainActor
    private func makeCore() -> Core {
        Core(defaults: defaults, profilesDirectory: directory.appendingPathComponent("profiles"))
    }

    private func group(selected: String, latency: Int = 10) -> PolicyGroup {
        PolicyGroup(group: "Proxy", type: "select", selected: selected,
                    options: [GroupOption(name: "HK", latencyMs: latency), GroupOption(name: "US", latencyMs: nil)])
    }

    /// Drain the model's queued @Published reads and post-tracking refresh.
    @MainActor
    private func drainMainQueue() async {
        await withCheckedContinuation { continuation in
            DispatchQueue.main.async { continuation.resume() }
        }
    }

    @MainActor
    func testSnapshotStaysFrozenAcrossSubmenuNavigationAndRepeatedCoreUpdates() async {
        let core = makeCore()
        core.updateGroups([group(selected: "HK")])
        let notifications = NotificationCenter()
        let model = MenuBarModel(core: core, diagnostics: DiagnosticsExporter(), notifications: notifications)
        let original = model.value
        var updates = 0
        let subscription = model.$value.dropFirst().sink { _ in updates += 1 }
        defer { subscription.cancel() }
        let root = NSMenu()
        let submenu = NSMenu()
        notifications.post(name: NSMenu.didBeginTrackingNotification, object: root)
        notifications.post(name: NSMenu.didBeginTrackingNotification, object: submenu)

        for latency in 20...23 {
            core.updateGroups([group(selected: "US", latency: latency)])
            await drainMainQueue()
            XCTAssertEqual(model.value, original)
        }
        defaults.set(MenuBarDisplayMode.speedOnly.rawValue, forKey: "menuBarDisplayMode")
        defaults.set(false, forKey: "menuBarShowOutboundMode")
        notifications.post(name: UserDefaults.didChangeNotification, object: defaults)
        notifications.post(name: NSMenu.didEndTrackingNotification, object: submenu)
        await drainMainQueue()
        XCTAssertEqual(model.value, original)
        XCTAssertEqual(updates, 0)

        // A second submenu can open without releasing the root's snapshot.
        notifications.post(name: NSMenu.didBeginTrackingNotification, object: submenu)
        notifications.post(name: NSMenu.didEndTrackingNotification, object: submenu)
        await drainMainQueue()
        XCTAssertEqual(model.value, original)
        notifications.post(name: NSMenu.didEndTrackingNotification, object: root)
        XCTAssertEqual(model.value, original, "Keep action receivers alive until dispatch finishes")
        await drainMainQueue()
        XCTAssertEqual(model.value.groups, [group(selected: "US", latency: 23)])
        XCTAssertEqual(model.value.displayMode, .speedOnly)
        XCTAssertFalse(model.value.showOutboundMode)
        XCTAssertEqual(updates, 1)
    }

    @MainActor
    func testEndTrackingReadsChangesMadeByTheSelectedAction() async {
        let core = makeCore()
        let notifications = NotificationCenter()
        let model = MenuBarModel(core: core, diagnostics: DiagnosticsExporter(), notifications: notifications)
        let root = NSMenu()
        notifications.post(name: NSMenu.didBeginTrackingNotification, object: root)
        notifications.post(name: NSMenu.didEndTrackingNotification, object: root)

        // AppKit can send didEndTracking before invoking the button action.
        defaults.set(MenuBarDisplayMode.iconOnly.rawValue, forKey: "menuBarDisplayMode")
        defaults.set(false, forKey: "menuBarShowOutboundMode")
        core.updateGroups([group(selected: "US")])
        XCTAssertTrue(model.value.groups.isEmpty)
        XCTAssertEqual(model.value.displayMode, .iconAndSpeed)
        await drainMainQueue()
        XCTAssertEqual(model.value.groups.first?.selected, "US")
        XCTAssertEqual(model.value.displayMode, .iconOnly)
        XCTAssertFalse(model.value.showOutboundMode)
    }

    @MainActor
    func testUnrelatedPublicationsDoNotRebuildMenuAndIdleChangesRefresh() async {
        let core = makeCore()
        let model = MenuBarModel(core: core, diagnostics: DiagnosticsExporter())
        var updates = 0
        let subscription = model.$value.dropFirst().sink { _ in updates += 1 }
        defer { subscription.cancel() }
        core.lastActionError = "An error shown in the main window"
        core.objectWillChange.send()
        await drainMainQueue()
        XCTAssertEqual(updates, 0)
        core.updateGroups([group(selected: "HK")])
        await drainMainQueue()
        XCTAssertEqual(model.value.groups.first?.selected, "HK")
        XCTAssertEqual(updates, 1)
    }
}

extension MenuBarTests {
    func testIdenticalPublicationsRenderOneImageAndEveryDrawingInputInvalidates() {
        let publisher = ObservableObjectPublisher()
        var cache = MenuBarImageCache()
        var renders = 0
        let font = NSFont.monospacedDigitSystemFont(ofSize: 9, weight: .regular)
        func key(mode: MenuBarDisplayMode = .iconAndSpeed, font: NSFont? = nil,
                 upload: String = "0 B/s", download: String = "0 B/s", mark: String = "R",
                 showsMode: Bool = true, dark: Bool = false, ink: NSColor = .black) -> MenuBarImageKey {
            MenuBarImageKey(mode: mode, font: font ?? .monospacedDigitSystemFont(ofSize: 9, weight: .regular),
                            upload: upload, download: download, modeMark: mark,
                            showsMode: showsMode, dark: dark, ink: ink)
        }
        let subscription = publisher.sink {
            _ = cache.image(for: key(), render: {
                renders += 1
                return NSImage(size: NSSize(width: 20, height: 22))
            })
        }
        for _ in 0..<1_000 { publisher.send() }
        XCTAssertEqual(renders, 1)
        subscription.cancel()
        for changed in [key(mode: .iconOnly), key(font: font.withSize(12)), key(upload: "1 KB/s"),
                        key(download: "2 KB/s"), key(mark: "D"), key(showsMode: false),
                        key(dark: true), key(ink: .systemRed), key(ink: .black.withAlphaComponent(0.55))] {
            _ = cache.image(for: key(), render: { NSImage() })
            XCTAssertNotNil(cache.image(for: changed, render: { NSImage() }))
            XCTAssertNil(cache.image(for: changed, render: { XCTFail("Identical appearance callback must not render"); return NSImage() }))
        }
    }

    func testMonitoringIsNeverScheduledForStoppedOrFailedCore() {
        XCTAssertFalse(MonitoringPolicy.shouldPoll(state: .stopped))
        XCTAssertFalse(MonitoringPolicy.shouldPoll(state: .failed("invalid config")))
        XCTAssertTrue(MonitoringPolicy.shouldPoll(state: .starting))
        XCTAssertTrue(MonitoringPolicy.shouldPoll(state: .running))
        for state in [Core.State.stopped, .failed("invalid config"), .starting, .running] {
            XCTAssertFalse(MonitoringPolicy.shouldFollowEvents(state: state, windowVisible: false))
        }
        XCTAssertTrue(MonitoringPolicy.shouldFollowEvents(state: .running, windowVisible: true))
        XCTAssertFalse(MonitoringPolicy.shouldFollowEvents(state: .stopped, windowVisible: true))
        XCTAssertEqual((0..<30).filter { MonitoringPolicy.maintenanceDue(windowVisible: false, tick: $0) }, [0, 10, 20])
        XCTAssertTrue((0..<30).allSatisfy { MonitoringPolicy.maintenanceDue(windowVisible: true, tick: $0) })
    }
}
