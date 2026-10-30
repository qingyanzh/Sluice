import AppKit
import Combine

/// Only values rendered by the menu. Core also publishes logs, requests and
/// traffic every second; none of those should invalidate a tracked native menu.
struct MenuBarState: Equatable {
    let state: Core.State
    let profileName: String
    let trafficLabel: String
    let otherSystemProxy: String?
    let isActive: Bool
    let mode: OutboundMode
    let groups: [PolicyGroup]
    let testingGroups: Set<String>
    let systemProxyOn: Bool
    let canSetSystemProxy: Bool
    let enhancedMode: Bool
    let reloading: Bool
    let displayMode: MenuBarDisplayMode
    let showOutboundMode: Bool
    let isExporting: Bool

    @MainActor
    init(core: Core, diagnostics: DiagnosticsExporter) {
        state = core.state
        profileName = URL(fileURLWithPath: core.configPath).deletingPathExtension().lastPathComponent
        trafficLabel = "↓ \(formatBytes(core.downRate))/s   ↑ \(formatBytes(core.upRate))/s   ·   \(core.traffic?.active ?? 0) 个连接"
        otherSystemProxy = core.otherSystemProxy
        isActive = core.isActive
        mode = OutboundMode(rawValue: core.mode) ?? .rule
        groups = core.groups.filter(\.isSelectable)
        testingGroups = core.testingGroups
        systemProxyOn = core.systemProxyOn
        canSetSystemProxy = core.summary.httpListen != nil || core.summary.socksListen != nil
        enhancedMode = core.summary.enhancedMode
        reloading = core.reloading
        displayMode = core.preferences.string(forKey: "menuBarDisplayMode")
            .flatMap(MenuBarDisplayMode.init(rawValue:)) ?? .iconAndSpeed
        showOutboundMode = core.preferences.object(forKey: "menuBarShowOutboundMode") as? Bool ?? true
        isExporting = diagnostics.state.isExporting
    }
}

/// Freeze the entire menu during native tracking, including submenu navigation.
/// The status-item label observes Core separately and continues showing live rates.
@MainActor
final class MenuBarModel: ObservableObject {
    @Published private(set) var value: MenuBarState
    private let core: Core
    private let diagnostics: DiagnosticsExporter
    private var trackingMenus: Set<ObjectIdentifier> = []
    private var subscriptions: Set<AnyCancellable> = []

    init(core: Core, diagnostics: DiagnosticsExporter,
         notifications: NotificationCenter = .default) {
        self.core = core
        self.diagnostics = diagnostics
        value = MenuBarState(core: core, diagnostics: diagnostics)

        core.objectWillChange.merge(with: diagnostics.objectWillChange)
            .merge(with: notifications.publisher(for: UserDefaults.didChangeNotification).map { _ in () })
            // Read @Published properties after their setters have completed.
            .receive(on: DispatchQueue.main)
            .sink { [weak self] in self?.refresh() }
            .store(in: &subscriptions)

        // Tracking notifications must be handled synchronously, before any queued
        // Core update can rebuild the menu. AppKit posts them on the main thread.
        notifications.publisher(for: NSMenu.didBeginTrackingNotification)
            .sink { [weak self] notification in
                guard let menu = notification.object as? NSMenu else { return }
                self?.trackingMenus.insert(ObjectIdentifier(menu))
            }
            .store(in: &subscriptions)
        notifications.publisher(for: NSMenu.didEndTrackingNotification)
            .sink { [weak self] notification in
                guard let menu = notification.object as? NSMenu else { return }
                self?.trackingMenus.remove(ObjectIdentifier(menu))
                // Menu actions may run after didEndTracking. Preserve their SwiftUI
                // receivers until AppKit has finished dispatching the selection.
                DispatchQueue.main.async { [weak self] in self?.refresh() }
            }
            .store(in: &subscriptions)
    }

    func refresh() {
        guard trackingMenus.isEmpty else { return }
        let next = MenuBarState(core: core, diagnostics: diagnostics)
        if next != value { value = next }
    }
}
