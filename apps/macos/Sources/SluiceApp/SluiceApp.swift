import AppKit
import SwiftUI

final class AppDelegate: NSObject, NSApplicationDelegate {
    var core: Core?

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Running from `swift run` has no bundle; make it a regular app with a Dock icon.
        NSApp.setActivationPolicy(.regular)
        if let iconURL = Bundle.main.url(forResource: "Sluice", withExtension: "icns"),
           let icon = NSImage(contentsOf: iconURL) {
            NSApp.applicationIconImage = icon
        }
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationWillTerminate(_ notification: Notification) {
        MainActor.assumeIsolated { core?.stopForQuit() }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
}

@main
struct SluiceApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var core = Core()

    init() {
        // `Sluice --helper status|register|unregister|hello` manages the helper without the UI.
        let args = CommandLine.arguments
        if let i = args.firstIndex(of: "--helper") { exit(HelperClient.command(args.count > i + 1 ? args[i + 1] : "")) }
    }

    var body: some Scene {
        Window("Sluice", id: "main") {
            MainView()
                .environmentObject(core)
                .onAppear { delegate.core = core }
        }
        .defaultSize(width: 1120, height: 860)

        MenuBarExtra {
            MenuBarContent().environmentObject(core)
        } label: {
            MenuBarLabel().environmentObject(core)
        }
    }
}
