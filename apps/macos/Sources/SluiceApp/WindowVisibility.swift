import AppKit
import SwiftUI

enum MonitoringPolicy {
    static func shouldPoll(state: Core.State) -> Bool {
        state == .starting || state == .running
    }

    static func shouldFollowEvents(state: Core.State, windowVisible: Bool) -> Bool {
        state == .running && windowVisible
    }

    static func maintenanceDue(windowVisible: Bool, tick: Int) -> Bool {
        windowVisible || tick % 10 == 0
    }
}

/// Window ordering/occlusion can change without SwiftUI's onDisappear firing.
struct WindowVisibilityObserver: NSViewRepresentable {
    let changed: (Bool) -> Void

    func makeNSView(context: Context) -> VisibilityView { VisibilityView(changed: changed) }
    func updateNSView(_ nsView: VisibilityView, context: Context) {}

    final class VisibilityView: NSView {
        private let changed: (Bool) -> Void
        private var observers: [NSObjectProtocol] = []

        init(changed: @escaping (Bool) -> Void) {
            self.changed = changed
            super.init(frame: .zero)
        }

        required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            observers.forEach(NotificationCenter.default.removeObserver)
            observers = []
            if let window {
                for name in [NSWindow.didChangeOcclusionStateNotification, NSWindow.didMiniaturizeNotification,
                             NSWindow.didDeminiaturizeNotification, NSWindow.willCloseNotification] {
                    observers.append(NotificationCenter.default.addObserver(forName: name, object: window, queue: .main) { [weak self] note in
                        if note.name == NSWindow.willCloseNotification { self?.changed(false) }
                        else { self?.reportVisibility() }
                    })
                }
            }
            // Don't publish from a representable update.
            DispatchQueue.main.async { [weak self] in self?.reportVisibility() }
        }

        private func reportVisibility() {
            changed(window.map { $0.isVisible && !$0.isMiniaturized && $0.occlusionState.contains(.visible) } ?? false)
        }

        deinit { observers.forEach(NotificationCenter.default.removeObserver) }
    }
}
