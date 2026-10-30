import AppKit
import SwiftUI

final class AppDelegate: NSObject, NSApplicationDelegate {
    var core: Core?
    private var menuBar: MenuBarStatusItem?

    @MainActor
    func installMenuBar(core: Core, openWindow: OpenWindowAction) {
        self.core = core
        guard menuBar == nil else { return }
        menuBar = MenuBarStatusItem(core: core) { pane in
            if let pane { core.requestedPane = pane }
            openWindow(id: "main")
            NSApp.activate(ignoringOtherApps: true)
        }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Running from `swift run` has no bundle; make it a regular app with a Dock icon.
        NSApp.setActivationPolicy(.regular)
        if let iconURL = Bundle.main.url(forResource: "Sluice", withExtension: "icns"),
           let icon = NSImage(contentsOf: iconURL) {
            NSApp.applicationIconImage = icon
        }
        NSApp.activate(ignoringOtherApps: true)
        _ = Updater.shared
    }

    func applicationWillTerminate(_ notification: Notification) {
        MainActor.assumeIsolated { core?.stopForQuit() }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
}

@main
struct SluiceApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var core = Core(attachment: E2ELaunch.current)

    init() {
        // `Sluice --helper status|register|unregister|hello` manages the helper without the UI.
        let args = CommandLine.arguments
        if let i = args.firstIndex(of: "--helper") { exit(HelperClient.command(args.count > i + 1 ? args[i + 1] : "")) }
    }

    var body: some Scene {
        Window("Sluice", id: "main") {
            MainView()
                .environmentObject(core)
                .defaultAppStorage(core.preferences)
                .background(MenuBarInstaller { openWindow in
                    delegate.installMenuBar(core: core, openWindow: openWindow)
                })
                .task { if let launch = E2ELaunch.current { await launch.prepareWindow(core: core) } }
        }
        .defaultSize(width: 1120, height: 860)
        .commands {
            CommandGroup(after: .appInfo) { CheckForUpdatesButton() }
        }
    }
}

/// Capture the scene's window action once; the delegate retains the status item
/// even after the last app window closes.
private struct MenuBarInstaller: View {
    @Environment(\.openWindow) private var openWindow
    let install: (OpenWindowAction) -> Void

    var body: some View { Color.clear.onAppear { install(openWindow) } }
}
