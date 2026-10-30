import AppKit
import SwiftUI

struct ActiveConnectionMenu: View {
    let connection: ActiveConnection
    let core: Core

    var body: some View {
        RowContextMenu { [connection, core] in
            Self.menu(connection: connection,
                      canClose: core.state == .running && core.activeConnections.contains { $0.id == connection.id },
                      close: { core.closeConnection($0) })
        }
    }

    static func menu(connection: ActiveConnection, canClose: Bool, copy: @escaping (String) -> Void = copyText,
                     close: @escaping (UInt64) -> Void) -> NSMenu {
        let menu = RowContextMenu.Menu()
        menu.addAction("复制目标") { copy(connection.target) }
        menu.addAction("复制策略链") { copy(connection.policyChain) }
        menu.addItem(.separator())
        menu.addAction("断开连接", isEnabled: canClose) { close(connection.id) }
        return menu
    }
}

/// Snapshot actions when tracking begins, independently of SwiftUI row updates.
struct RowContextMenu: NSViewRepresentable {
    var makeMenu: () -> NSMenu

    func makeNSView(context: Context) -> MenuView { MenuView() }

    func updateNSView(_ view: MenuView, context: Context) { view.makeMenu = makeMenu }

    class MenuView: NSView {
        var makeMenu: (() -> NSMenu)?

        // Leave ordinary clicks to the SwiftUI selection button underneath.
        override func hitTest(_ point: NSPoint) -> NSView? {
            guard let event = NSApp.currentEvent,
                  event.type == .rightMouseDown || (event.type == .leftMouseDown && event.modifierFlags.contains(.control))
            else { return nil }
            return super.hitTest(point)
        }

        override func menu(for event: NSEvent) -> NSMenu? { makeMenu?() }

        override func rightMouseDown(with event: NSEvent) { openMenu(for: event) }

        override func mouseDown(with event: NSEvent) {
            if event.modifierFlags.contains(.control) { openMenu(for: event) }
            else { super.mouseDown(with: event) }
        }

        private func openMenu(for event: NSEvent) {
            guard let menu = menu(for: event) else { return }
            // AppKit tracks synchronously. Keep the original menu and its targets alive
            // through dispatch, even if SwiftUI removes this view during tracking.
            withExtendedLifetime((self, menu)) { track(menu, with: event) }
        }

        func track(_ menu: NSMenu, with event: NSEvent) {
            NSMenu.popUpContextMenu(menu, with: event, for: self)
        }
    }

    final class Menu: NSMenu {
        // NSMenuItem.target is weak; the menu must own separate action receivers.
        private var actions: [Action] = []

        init() {
            super.init(title: "")
            autoenablesItems = false
        }

        required init(coder: NSCoder) { fatalError() }

        func addAction(_ title: String, isEnabled: Bool = true, perform: @escaping () -> Void) {
            let receiver = Action(perform)
            actions.append(receiver)
            let item = NSMenuItem(title: title, action: #selector(Action.performMenuAction(_:)), keyEquivalent: "")
            item.target = receiver
            item.isEnabled = isEnabled
            addItem(item)
        }
    }

    private final class Action: NSObject {
        let perform: () -> Void

        init(_ perform: @escaping () -> Void) { self.perform = perform }

        @objc func performMenuAction(_ sender: NSMenuItem) { perform() }
    }
}
