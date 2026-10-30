import AppKit
import SwiftUI

enum MenuBarDisplayMode: String, CaseIterable, Identifiable {
    case iconAndSpeed, iconOnly, speedOnly

    var id: String { rawValue }
    var title: String {
        switch self {
        case .iconAndSpeed: "显示图标和实时速度"
        case .iconOnly: "仅显示图标"
        case .speedOnly: "仅显示实时速度"
        }
    }
    var showsIcon: Bool { self != .speedOnly }
    var showsSpeed: Bool { self != .iconOnly }
}

/// The status bar menu keeps the frequent controls available without opening a window.
struct MenuBarContent: View {
    @EnvironmentObject private var core: Core
    @Environment(\.openWindow) private var openWindow
    @AppStorage("menuBarDisplayMode") private var displayMode = MenuBarDisplayMode.iconAndSpeed
    @AppStorage("menuBarShowOutboundMode") private var showOutboundMode = true

    private var profileName: String {
        URL(fileURLWithPath: core.configPath).deletingPathExtension().lastPathComponent
    }

    private var outboundMode: OutboundMode {
        OutboundMode(rawValue: core.mode) ?? .rule
    }

    var body: some View {
        Text("Sluice · \(core.state.label)")
        Text("配置：\(profileName)")
        if core.state == .running {
            Text("↓ \(formatBytes(core.downRate))/s   ↑ \(formatBytes(core.upRate))/s   ·   \(core.traffic?.active ?? 0) 个连接")
        } else if core.systemProxyOn {
            Text("系统代理已开启，内核未运行")
        }

        Divider()
        Button(core.isActive ? "停止 Sluice" : "启动 Sluice", systemImage: core.isActive ? "stop.fill" : "play.fill") {
            if core.isActive { core.stop() } else { core.start() }
        }
        .disabled(core.state == .starting)

        Divider()
        Menu {
            ForEach(OutboundMode.allCases) { mode in
                Toggle(mode.title, isOn: Binding(
                    get: { core.mode == mode.rawValue },
                    set: { if $0 { core.setMode(mode.rawValue) } }
                ))
            }
        } label: {
            Label("出站模式：\(outboundMode.title)", systemImage: outboundMode.icon)
        }
        .disabled(core.state != .running)

        if core.groups.contains(where: \.isSelectable) {
            Divider()
            ForEach(core.groups.filter(\.isSelectable)) { group in
                Menu {
                    ForEach(group.options, id: \.name) { option in
                        Toggle(optionLabel(option), isOn: Binding(
                            get: { group.selected == option.name },
                            set: { if $0 { core.select(group: group.group, option: option.name) } }
                        ))
                    }
                    Divider()
                    Button("测试延迟", systemImage: "speedometer") { core.test(group: group.group) }
                        .disabled(core.testingGroups.contains(group.group))
                } label: {
                    Label("\(group.group)：\(group.selected)", systemImage: "point.3.connected.trianglepath.dotted")
                }
            }
        }

        Divider()
        Toggle("设置为系统代理", isOn: Binding(
            get: { core.systemProxyOn },
            set: { core.setSystemProxy($0) }
        ))
        .disabled(core.summary.httpListen == nil && core.summary.socksListen == nil)
        Toggle("增强模式", isOn: Binding(
            get: { core.summary.enhancedMode },
            set: { on in
                Task {
                    if let error = await core.setEnhancedMode(on) { core.lastActionError = "增强模式：\(error)" }
                }
            }
        ))

        Divider()
        Button("重新载入配置", systemImage: "arrow.triangle.2.circlepath") { core.reload() }
            .disabled(core.state != .running || core.reloading)
            .keyboardShortcut("r")
        Button("重启内核", systemImage: "arrow.clockwise") { core.restart() }
            .disabled(!core.isActive)

        Divider()
        Menu("菜单栏显示") {
            ForEach(MenuBarDisplayMode.allCases) { option in
                Toggle(option.title, isOn: Binding(
                    get: { displayMode == option },
                    set: { if $0 { displayMode = option } }
                ))
            }
            Divider()
            Toggle("显示当前的出站模式", isOn: $showOutboundMode)
        }

        Divider()
        Button("显示主窗口", systemImage: "macwindow") { showWindow() }
            .keyboardShortcut("0")
        Button("查看请求", systemImage: "arrow.up.arrow.down.circle") { showWindow(.requests) }
        Button("编辑当前配置", systemImage: "curlybraces.square") { showWindow(.profile) }

        Divider()
        Button("退出 Sluice", systemImage: "power") { NSApp.terminate(nil) }
            .keyboardShortcut("q")
    }

    private func optionLabel(_ option: GroupOption) -> String {
        guard let latency = option.latencyMs else { return option.name }
        return "\(option.name)    \(latencyStyle(latency).0)"
    }

    private func showWindow(_ pane: Pane? = nil) {
        if let pane { core.requestedPane = pane }
        openWindow(id: "main")
        NSApp.activate(ignoringOtherApps: true)
    }
}

/// The five-bar geometry of the app icon, rendered in the system menu-bar tint.
struct SluiceMark: Shape {
    func path(in rect: CGRect) -> Path {
        let bars: [(x: CGFloat, top: CGFloat, height: CGFloat)] = [
            (0.000, 0.593, 0.250),
            (0.214, 0.407, 0.593),
            (0.436, 0.093, 0.807),
            (0.657, 0.000, 0.593),
            (0.871, 0.157, 0.250),
        ]
        var path = Path()
        for bar in bars {
            let frame = CGRect(x: rect.minX + rect.width * bar.x,
                               y: rect.minY + rect.height * bar.top,
                               width: rect.width * 0.129,
                               height: rect.height * bar.height)
            path.addRoundedRect(in: frame, cornerSize: CGSize(width: frame.width / 2, height: frame.width / 2))
        }
        return path
    }
}

/// A compact status mark with outbound mode and significant download traffic.
struct MenuBarLabel: View {
    @EnvironmentObject private var core: Core
    @AppStorage("menuBarDisplayMode") private var displayMode = MenuBarDisplayMode.iconAndSpeed
    @AppStorage("menuBarShowOutboundMode") private var showOutboundMode = true
    @AppStorage("menuBarDimWhenNotProxying") private var dimWhenNotProxying = true

    private static let statusIcon: NSImage? = {
        guard let url = Bundle.main.url(forResource: "SluiceMenuBarIcon", withExtension: "png"),
              let image = NSImage(contentsOf: url) else { return nil }
        image.isTemplate = true
        image.size = NSSize(width: 14, height: 15)
        return image
    }()

    var body: some View {
        HStack(spacing: 4) {
            if displayMode.showsIcon {
                if let icon = Self.statusIcon {
                    Image(nsImage: icon)
                        .renderingMode(.template)
                        .frame(width: 14, height: 15)
                        .foregroundStyle(iconTone)
                        .accessibilityHidden(true)
                } else {
                    SluiceMark()
                        .fill(iconTone)
                        .frame(width: 14, height: 15)
                        .accessibilityHidden(true)
                }
            }
            if showOutboundMode && core.state == .running {
                Text(modeMark).font(.system(size: 10, weight: .semibold))
            }
            if displayMode.showsSpeed {
                VStack(alignment: .leading, spacing: -2) {
                    Text("↓\(formatBytes(core.downRate))/s")
                    Text("↑\(formatBytes(core.upRate))/s")
                }
                .font(.system(size: 9, weight: .medium))
                .monospacedDigit()
                .lineLimit(1)
                .accessibilityElement(children: .combine)
            }
        }
        .accessibilityLabel("Sluice，\(core.state.label)\(showOutboundMode && core.state == .running ? "，\(modeName)" : "")\(displayMode.showsSpeed ? "，下载每秒 \(formatBytes(core.downRate))，上传每秒 \(formatBytes(core.upRate))" : "")")
    }

    private var iconTone: Color {
        if core.state.isFailed { return DS.fail }
        if dimWhenNotProxying && !core.systemProxyOn && !core.summary.enhancedMode { return .secondary }
        return .primary
    }

    private var modeName: String { (OutboundMode(rawValue: core.mode) ?? .rule).title }

    private var modeMark: String {
        switch OutboundMode(rawValue: core.mode) ?? .rule {
        case .direct: "直连"
        case .global: "全局"
        case .rule: "规则"
        }
    }
}
