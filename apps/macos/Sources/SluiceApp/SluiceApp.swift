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
        .defaultSize(width: 1000, height: 680)

        MenuBarExtra {
            MenuBarContent().environmentObject(core)
        } label: {
            MenuBarLabel().environmentObject(core)
        }
    }
}

struct MenuBarContent: View {
    @EnvironmentObject var core: Core
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Text("Sluice：\(core.state.label)")
        if core.state == .running {
            Text("↑ \(formatBytes(core.upRate))/s   ↓ \(formatBytes(core.downRate))/s")
        }
        if core.isActive {
            Button("停止") { core.stop() }
        } else {
            Button("启动") { core.start() }
        }
        Divider()
        Picker("出站模式", selection: Binding(get: { core.mode }, set: { core.setMode($0) })) {
            ForEach(OutboundMode.allCases) { Text($0.title).tag($0.rawValue) }
        }
        .pickerStyle(.inline)
        .disabled(core.state != .running)
        Divider()
        ForEach(core.groups.filter(\.isSelectable)) { g in
            Picker(g.group, selection: Binding(get: { g.selected }, set: { core.select(group: g.group, option: $0) })) {
                ForEach(g.options, id: \.name) { o in
                    let (t, _) = latencyStyle(o.latencyMs)
                    Text(o.latencyMs == nil ? o.name : "\(o.name)    \(t)").tag(o.name)
                }
            }
        }
        if !core.groups.isEmpty { Divider() }
        Toggle("设置为系统代理", isOn: Binding(get: { core.systemProxyOn }, set: { core.setSystemProxy($0) }))
        Toggle("增强模式", isOn: Binding(get: { core.summary.enhancedMode }, set: { on in
            Task { if let err = await core.setEnhancedMode(on) { core.lastActionError = "增强模式: \(err)" } }
        }))
        Divider()
        Button("重新载入配置") { core.reload() }.disabled(core.state != .running).keyboardShortcut("r")
        Button("显示主窗口") {
            openWindow(id: "main")
            NSApp.activate(ignoringOtherApps: true)
        }
        .keyboardShortcut("0")
        Divider()
        Button("退出 Sluice") { NSApp.terminate(nil) }.keyboardShortcut("q")
    }
}

/// Drop icon, plus the download speed while traffic is flowing.
struct MenuBarLabel: View {
    @EnvironmentObject var core: Core
    var body: some View {
        HStack(spacing: 3) {
            Image(systemName: core.state == .running ? "drop.fill" : "drop")
            if core.state == .running && core.downRate + core.upRate >= 1024 {
                Text("↓\(formatBytes(core.downRate))/s").monospacedDigit()
            }
        }
    }
}
