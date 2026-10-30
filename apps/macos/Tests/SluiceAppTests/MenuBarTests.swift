import AppKit
import Combine
import XCTest
@testable import SluiceApp

final class MenuBarTests: XCTestCase {
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
