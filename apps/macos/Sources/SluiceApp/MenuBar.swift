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

/// Surge's compact status-item rate: decimal units, whole KB/s, then up to
/// four numeric characters for MB/s and above.
func menuBarSpeed(_ bytesPerSecond: Double) -> String {
    let bytes = bytesPerSecond.isFinite ? max(0, bytesPerSecond) : 0
    if bytes == 0 { return "0 KB/s" }
    var value = bytes / 1_000
    if value < 1_000 { return String(format: "%.0f KB/s", value) }

    for unit in ["MB/s", "GB/s", "TB/s"] {
        value /= 1_000
        if value < 1_000 || unit == "TB/s" {
            let number = ["%.2f", "%.1f", "%.0f"]
                .map { String(format: $0, value) }
                .first { $0.count <= 4 } ?? String(format: "%.0f", value)
            return "\(number) \(unit)"
        }
    }
    return "0 KB/s"
}

/// The status bar menu keeps the frequent controls available without opening a window.
struct MenuBarContent: View, Equatable {
    let core: Core
    @StateObject private var menu: MenuBarModel
    private let diagnostics = DiagnosticsExporter.shared
    @Environment(\.openWindow) private var openWindow

    init(core: Core) {
        self.core = core
        _menu = StateObject(wrappedValue: MenuBarModel(core: core, diagnostics: .shared))
    }

    // The App scene also observes Core. Its live status-label updates must not
    // invalidate this content; only MenuBarModel should publish menu changes.
    static func == (lhs: Self, rhs: Self) -> Bool { lhs.core === rhs.core }

    var body: some View {
        let state = menu.value
        Text("Sluice · \(state.state.label)")
        Text("配置：\(state.profileName)")
        if state.state == .running {
            Text(state.trafficLabel)
        } else if state.systemProxyOn {
            Text("系统代理已开启，内核未运行")
        }
        if let other = state.otherSystemProxy { Text("系统代理：\(other)") }

        Divider()
        Button(state.isActive ? "停止 Sluice" : "启动 Sluice", systemImage: state.isActive ? "stop.fill" : "play.fill") {
            if core.isActive { core.stop() } else { core.start() }
        }
        .disabled(state.state == .starting)

        Divider()
        Menu {
            ForEach(OutboundMode.allCases) { mode in
                let rawValue = mode.rawValue
                Button { [core, rawValue] in core.setMode(rawValue) } label: {
                    menuChoice(mode.title, selected: state.mode == mode)
                }
            }
        } label: {
            Label("出站模式：\(state.mode.title)", systemImage: state.mode.icon)
        }
        .disabled(state.state != .running)

        if !state.groups.isEmpty {
            Divider()
            ForEach(state.groups) { group in
                let groupName = group.group
                Menu {
                    ForEach(group.options, id: \.name) { option in
                        let optionName = option.name
                        Button { [core, groupName, optionName] in
                            core.select(group: groupName, option: optionName)
                        } label: {
                            Label {
                                menuChoice(optionLabel(option), selected: group.selected == optionName)
                            } icon: {
                                Image(nsImage: latencyIcon(option.latencyMs)).renderingMode(.original)
                            }
                        }
                    }
                    Divider()
                    Button(state.testingGroups.contains(groupName) ? "测试中…" : "测试延迟", systemImage: "speedometer") { [core, groupName] in
                        core.test(group: groupName)
                    }
                    .disabled(state.testingGroups.contains(groupName))
                } label: {
                    Label("\(group.group)：\(group.selected)", systemImage: "point.3.connected.trianglepath.dotted")
                }
                .disabled(state.state != .running)
            }
        }

        Divider()
        Toggle("设置为系统代理", isOn: Binding(
            get: { state.systemProxyOn },
            set: { core.setSystemProxy($0) }
        ))
        .disabled(!state.canSetSystemProxy)
        Toggle("增强模式", isOn: Binding(
            get: { state.enhancedMode },
            set: { on in
                Task {
                    if let error = await core.setEnhancedMode(on) { core.lastActionError = "增强模式：\(error)" }
                }
            }
        ))

        Divider()
        Button("重新载入配置", systemImage: "arrow.triangle.2.circlepath") { core.reload() }
            .disabled(state.state != .running || state.reloading)
            .keyboardShortcut("r")
        Button("重启内核", systemImage: "arrow.clockwise") { core.restart() }
            .disabled(!state.isActive)

        Divider()
        Menu("菜单栏显示") {
            ForEach(MenuBarDisplayMode.allCases) { option in
                let rawValue = option.rawValue
                Button { [core, rawValue] in
                    core.preferences.set(rawValue, forKey: "menuBarDisplayMode")
                } label: {
                    menuChoice(option.title, selected: state.displayMode == option)
                }
            }
            Divider()
            Button { [core, show = !state.showOutboundMode] in
                core.preferences.set(show, forKey: "menuBarShowOutboundMode")
            } label: {
                menuChoice("显示当前的出站模式", selected: state.showOutboundMode)
            }
        }

        Divider()
        Button("显示主窗口", systemImage: "macwindow") { showWindow() }
            .keyboardShortcut("0")
        Button("查看请求", systemImage: "arrow.up.arrow.down.circle") { showWindow(.requests) }
        Button("编辑当前配置", systemImage: "curlybraces.square") { showWindow(.profile) }
        Button("导出诊断信息…", systemImage: "stethoscope") {
            if core.lastActionError?.hasPrefix("导出诊断信息失败：") == true { core.lastActionError = nil }
            Task {
                await diagnostics.export(api: core.state == .running ? core.api : nil,
                                         binary: core.coreBinary, configPath: core.configPath, reveal: true)
                if case .failed(let message) = diagnostics.state {
                    core.lastActionError = "导出诊断信息失败：\(message)"
                    showWindow(.overview)
                }
            }
        }
        .disabled(state.isExporting)

        Divider()
        CheckForUpdatesButton()
        Button("退出 Sluice", systemImage: "power") { NSApp.terminate(nil) }
            .keyboardShortcut("q")
    }

    private func menuChoice(_ title: String, selected: Bool) -> Text {
        Text(selected ? "✓ \(title)" : title)
    }

    private func optionLabel(_ option: GroupOption) -> String {
        "\(option.name)    \(latencyText(option.latencyMs))"
    }

    /// Native menus use an image for the badge dot, preserving its semantic colour.
    private func latencyIcon(_ milliseconds: Int?) -> NSImage {
        let color = NSColor(latencyStyle(milliseconds).1)
        return NSImage(size: NSSize(width: 12, height: 12), flipped: false) { _ in
            color.setFill()
            NSBezierPath(ovalIn: NSRect(x: 3, y: 3, width: 6, height: 6)).fill()
            return true
        }
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

/// Surge-style status item: icon with an optional mode badge, then two speed rows.
struct MenuBarLabel: View {
    @EnvironmentObject private var core: Core
    @Environment(\.colorScheme) private var colorScheme
    @AppStorage("menuBarDisplayMode") private var displayMode = MenuBarDisplayMode.iconAndSpeed
    @AppStorage("menuBarShowOutboundMode") private var showOutboundMode = true
    @AppStorage("menuBarDimWhenNotProxying") private var dimWhenNotProxying = true

    private static let statusIcon: NSImage? = {
        guard let url = Bundle.main.url(forResource: "SluiceMenuBarIcon", withExtension: "png"),
              let image = NSImage(contentsOf: url) else { return nil }
        image.isTemplate = true
        image.size = NSSize(width: 15, height: 15)
        return image
    }()

    var body: some View {
        Image(nsImage: statusImage)
        .accessibilityLabel("Sluice，\(core.state.label)\(showOutboundMode && displayMode.showsIcon ? "，\(modeName)" : "")\(displayMode.showsSpeed ? "，上传每秒 \(menuBarSpeed(core.upRate))，下载每秒 \(menuBarSpeed(core.downRate))" : "")")
    }

    /// A single AppKit image gives MenuBarExtra the complete intrinsic width and
    /// two-line height. SwiftUI text stacks are clipped to one line in its label.
    private var statusImage: NSImage {
        let upload = menuBarSpeed(core.upRate) as NSString
        let download = menuBarSpeed(core.downRate) as NSString
        let font = NSFont.systemFont(ofSize: 9)
        let measure: [NSAttributedString.Key: Any] = [.font: font]
        let speedWidth = ceil(max(upload.size(withAttributes: measure).width,
                                  download.size(withAttributes: measure).width)) + 2
        // Keep the text clear of the 8-point mode badge, as Surge does.
        let speedX: CGFloat = displayMode.showsIcon ? (showOutboundMode ? 33 : 26) : 0
        let width = displayMode.showsSpeed ? speedX + speedWidth : (showOutboundMode ? 23 : 18)
        let dark = colorScheme == .dark
        let dimmed = dimWhenNotProxying && !core.systemProxyOn && !core.summary.enhancedMode
        let ink = (core.state.isFailed ? NSColor.systemRed : dark ? NSColor.white : NSColor.black)
            .withAlphaComponent(dimmed ? 0.55 : 1)
        let icon = Self.statusIcon
        let mode = modeMark as NSString
        let showsIcon = displayMode.showsIcon
        let showsSpeed = displayMode.showsSpeed
        let showsMode = showOutboundMode

        return NSImage(size: NSSize(width: width, height: 22), flipped: false) { _ in
            if showsIcon {
                let iconRect = NSRect(x: 1, y: 3, width: 15, height: 15)
                if let icon {
                    icon.draw(in: iconRect)
                    if let context = NSGraphicsContext.current?.cgContext {
                        context.setBlendMode(.sourceAtop)
                        context.setFillColor(ink.cgColor)
                        context.fill(iconRect)
                        context.setBlendMode(.normal)
                    }
                } else {
                    ink.setFill()
                    let path = SluiceMark().path(in: iconRect).cgPath
                    NSGraphicsContext.current?.cgContext.addPath(path)
                    NSGraphicsContext.current?.cgContext.fillPath()
                }
                if showsMode {
                    let badge = NSRect(x: 14, y: 2, width: 8, height: 8)
                    (dark ? NSColor.white : NSColor.black.withAlphaComponent(0.7)).setFill()
                    NSBezierPath(roundedRect: badge, xRadius: 2, yRadius: 2).fill()
                    let centered = NSMutableParagraphStyle()
                    centered.alignment = .center
                    mode.draw(in: NSRect(x: 14, y: 1.5, width: 8, height: 8), withAttributes: [
                        .font: NSFont.menuBarFont(ofSize: 6),
                        .foregroundColor: dark ? NSColor.black : NSColor.white,
                        .paragraphStyle: centered,
                    ])
                }
            }
            if showsSpeed {
                let centered = NSMutableParagraphStyle()
                centered.alignment = .center
                centered.lineBreakMode = .byTruncatingTail
                let attributes: [NSAttributedString.Key: Any] = [
                    .font: font,
                    .foregroundColor: ink,
                    .paragraphStyle: centered,
                ]
                upload.draw(in: NSRect(x: speedX, y: 12, width: speedWidth, height: 9), withAttributes: attributes)
                download.draw(in: NSRect(x: speedX, y: 3, width: speedWidth, height: 9), withAttributes: attributes)
            }
            return true
        }
    }

    private var modeName: String { (OutboundMode(rawValue: core.mode) ?? .rule).title }

    private var modeMark: String {
        switch OutboundMode(rawValue: core.mode) ?? .rule {
        case .direct: "D"
        case .global: "G"
        case .rule: "R"
        }
    }
}
