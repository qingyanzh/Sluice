import AppKit
import SwiftUI

final class AppDelegate: NSObject, NSApplicationDelegate {
    var core: Core?

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Running from `swift run` has no bundle; make it a regular app with a Dock icon.
        NSApp.setActivationPolicy(.regular)
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

    var body: some Scene {
        Window("Sluice", id: "main") {
            MainView()
                .environmentObject(core)
                .onAppear { delegate.core = core }
        }
        .defaultSize(width: 980, height: 640)

        MenuBarExtra {
            MenuBarContent().environmentObject(core)
        } label: {
            Image(systemName: core.state == .running ? "drop.fill" : "drop")
        }
    }
}

struct MenuBarContent: View {
    @EnvironmentObject var core: Core
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Text("Sluice: \(core.state.label)")
        if core.isActive {
            Button("Stop") { core.stop() }
        } else {
            Button("Start") { core.start() }
        }
        Divider()
        ForEach(core.groups.filter(\.isSelectable)) { g in
            Picker(g.group, selection: Binding(get: { g.selected }, set: { core.select(group: g.group, option: $0) })) {
                ForEach(g.options, id: \.name) { Text($0.name).tag($0.name) }
            }
        }
        if !core.groups.isEmpty { Divider() }
        Toggle("System Proxy", isOn: Binding(get: { core.systemProxyOn }, set: { core.setSystemProxy($0) }))
        Divider()
        Button("Open Sluice") {
            openWindow(id: "main")
            NSApp.activate(ignoringOtherApps: true)
        }
        Button("Quit Sluice") { NSApp.terminate(nil) }.keyboardShortcut("q")
    }
}
