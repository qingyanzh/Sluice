import AppKit
import Combine
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

func menuBarSpeed(_ bytesPerSecond: Double) -> String {
    var formatter = RateUnitFormatter.menuBar
    return formatter.format(bytesPerSecond).text
}

/// Value-independent geometry. Measure the actual drawing font once, reserving
/// every supported unit, including the widest five-column number.
/// The badge always has room, so toggling it cannot move neighbouring items.
struct MenuBarLayout {
    let font: NSFont
    let mode: MenuBarDisplayMode
    let speedWidth: CGFloat
    let speedX: CGFloat
    let imageSize: NSSize
    let statusItemLength: CGFloat

    init(mode: MenuBarDisplayMode, font: NSFont) {
        self.mode = mode
        self.font = font
        speedWidth = ceil(["B", "KB", "MB", "GB", "TB"].map { unit in
            ("999.9 \(unit)/s" as NSString).size(withAttributes: [.font: font]).width
        }.max() ?? 0)
        speedX = mode.showsIcon ? 33 : 0
        let width = mode.showsSpeed ? speedX + speedWidth : 23
        imageSize = NSSize(width: width, height: 22)
        // NSStatusBarButton's image has six points of horizontal inset per side.
        statusItemLength = width + 12
    }
}

/// Pure width computation: rates, connection state, and badge text are deliberately
/// absent from the inputs. The controller caches this layout between setting changes.
func menuBarStatusItemWidth(mode: MenuBarDisplayMode, font: NSFont) -> CGFloat {
    MenuBarLayout(mode: mode, font: font).statusItemLength
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

/// Two rows drawn inside a cached rectangle; changing either rate only changes ink.
enum MenuBarLabel {
    /// Drawing order is top to bottom: upload, then download.
    static func speedRows(mode: MenuBarDisplayMode, upload: String, download: String) -> [String] {
        mode.showsSpeed ? [upload, download] : []
    }

    private static let statusIcon: NSImage? = {
        guard let url = Bundle.main.url(forResource: "SluiceMenuBarIcon", withExtension: "png"),
              let image = NSImage(contentsOf: url) else { return nil }
        image.isTemplate = true
        image.size = NSSize(width: 15, height: 15)
        return image
    }()

    static func image(layout: MenuBarLayout, upload: String, download: String,
                      modeMark: String, showsMode: Bool, dark: Bool, ink: NSColor) -> NSImage {
        let icon = statusIcon
        return NSImage(size: layout.imageSize, flipped: false) { _ in
            if layout.mode.showsIcon {
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
                    (modeMark as NSString).draw(in: NSRect(x: 14, y: 1.5, width: 8, height: 8), withAttributes: [
                        .font: NSFont.menuBarFont(ofSize: 6),
                        .foregroundColor: dark ? NSColor.black : NSColor.white,
                        .paragraphStyle: centered,
                    ])
                }
            }
            if layout.mode.showsSpeed {
                let aligned = NSMutableParagraphStyle()
                aligned.alignment = .right
                let attributes: [NSAttributedString.Key: Any] = [
                    .font: layout.font,
                    .foregroundColor: ink,
                    .paragraphStyle: aligned,
                ]
                for (index, row) in speedRows(mode: layout.mode, upload: upload, download: download).enumerated() {
                    (row as NSString).draw(in: NSRect(x: layout.speedX, y: CGFloat(11 - index * 11),
                                                     width: layout.speedWidth, height: 11), withAttributes: attributes)
                }
            }
            return true
        }
    }
}

/// Own the NSStatusItem so AppKit never derives its length from changing content.
@MainActor
final class MenuBarStatusItem: NSObject, NSMenuDelegate {
    private let core: Core
    private let showWindow: (Pane?) -> Void
    private let statusItem: NSStatusItem
    private var layout: MenuBarLayout
    private var subscriptions = Set<AnyCancellable>()
    private var appearanceObservation: NSKeyValueObservation?
    private var showsMode = true
    private var dimWhenNotProxying = true

    init(core: Core, showWindow: @escaping (Pane?) -> Void) {
        self.core = core
        self.showWindow = showWindow
        let defaults = core.preferences
        let mode = MenuBarDisplayMode(rawValue: defaults.string(forKey: "menuBarDisplayMode") ?? "") ?? .iconAndSpeed
        let font = Self.font(in: defaults)
        layout = MenuBarLayout(mode: mode, font: font)
        statusItem = NSStatusBar.system.statusItem(withLength: layout.statusItemLength)
        super.init()
        let menu = NSMenu()
        menu.delegate = self
        menu.autoenablesItems = false
        statusItem.menu = menu
        statusItem.button?.imagePosition = .imageOnly
        refreshSettings()
        // objectWillChange fires before @Published values are assigned. Deliver on
        // the next main-queue turn so the image uses the new rates and state.
        core.objectWillChange.receive(on: DispatchQueue.main).sink { [weak self] _ in
            self?.refreshImage()
        }.store(in: &subscriptions)
        NotificationCenter.default.publisher(for: UserDefaults.didChangeNotification)
            .receive(on: DispatchQueue.main).sink { [weak self] _ in
                self?.refreshSettings()
            }.store(in: &subscriptions)
        appearanceObservation = statusItem.button?.observe(\.effectiveAppearance) { [weak self] _, _ in
            Task { @MainActor in self?.refreshImage() }
        }
    }

    deinit { NSStatusBar.system.removeStatusItem(statusItem) }

    private static func font(in defaults: UserDefaults) -> NSFont {
        let size = defaults.double(forKey: "menuBarSpeedFontSize")
        return .monospacedDigitSystemFont(ofSize: size.isFinite && size > 0 ? size : 9, weight: .regular)
    }

    private func refreshSettings() {
        let defaults = core.preferences
        let mode = MenuBarDisplayMode(rawValue: defaults.string(forKey: "menuBarDisplayMode") ?? "") ?? .iconAndSpeed
        let font = Self.font(in: defaults)
        if mode != layout.mode || font != layout.font {
            layout = MenuBarLayout(mode: mode, font: font)
            statusItem.length = layout.statusItemLength
        }
        showsMode = defaults.object(forKey: "menuBarShowOutboundMode") as? Bool ?? true
        dimWhenNotProxying = defaults.object(forKey: "menuBarDimWhenNotProxying") as? Bool ?? true
        refreshImage()
    }

    private func refreshImage() {
        guard let button = statusItem.button else { return }
        let dark = button.effectiveAppearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
        let dimmed = dimWhenNotProxying && !core.systemProxyOn && !core.summary.enhancedMode
        let ink = (core.state.isFailed ? NSColor.systemRed : dark ? NSColor.white : NSColor.black)
            .withAlphaComponent(dimmed ? 0.55 : 1)
        let mode = OutboundMode(rawValue: core.mode) ?? .rule
        let mark: String = switch mode {
        case .direct: "D"
        case .global: "G"
        case .rule: "R"
        }
        button.image = MenuBarLabel.image(layout: layout, upload: core.displayedRates.up.menuText,
                                         download: core.displayedRates.down.menuText, modeMark: mark,
                                         showsMode: showsMode, dark: dark, ink: ink)
        button.setAccessibilityLabel("Sluice，\(core.state.label)\(showsMode && layout.mode.showsIcon ? "，\(mode.title)" : "")\(layout.mode.showsSpeed ? "，上传每秒 \(core.displayedRates.up.menuText)，下载每秒 \(core.displayedRates.down.menuText)" : "")")
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        menu.addItem(NSMenuItem(title: "Sluice · \(core.state.label)", action: nil, keyEquivalent: ""))
        let profile = URL(fileURLWithPath: core.configPath).deletingPathExtension().lastPathComponent
        menu.addItem(NSMenuItem(title: "配置：\(profile)", action: nil, keyEquivalent: ""))
        if core.state == .running {
            menu.addItem(NSMenuItem(title: "↓ \(core.displayedRates.down.formatted.text)   ↑ \(core.displayedRates.up.formatted.text)   ·   \(core.traffic?.active ?? 0) 个连接", action: nil, keyEquivalent: ""))
        } else if core.systemProxyOn {
            menu.addItem(NSMenuItem(title: "系统代理已开启，内核未运行", action: nil, keyEquivalent: ""))
        }
        if let other = core.otherSystemProxy {
            menu.addItem(NSMenuItem(title: "系统代理：\(other)", action: nil, keyEquivalent: ""))
        }
        menu.addItem(.separator())
        add(to: menu, core.isActive ? "停止 Sluice" : "启动 Sluice", symbol: core.isActive ? "stop.fill" : "play.fill", enabled: core.state != .starting) { [core] in
            if core.isActive { core.stop() } else { core.start() }
        }
        menu.addItem(.separator())
        let mode = OutboundMode(rawValue: core.mode) ?? .rule
        let modes = submenu(in: menu, title: "出站模式：\(mode.title)", symbol: "point.3.connected.trianglepath.dotted", enabled: core.state == .running)
        for option in OutboundMode.allCases {
            add(to: modes, option.title, symbol: option.icon, checked: option == mode) { [core] in core.setMode(option.rawValue) }
        }
        if core.groups.contains(where: \.isSelectable) {
            menu.addItem(.separator())
            for group in core.groups.filter(\.isSelectable) {
                let options = submenu(in: menu, title: "\(group.group)：\(group.selected)", symbol: "point.3.connected.trianglepath.dotted", enabled: core.state == .running)
                for option in group.options {
                    let item = add(to: options, "\(option.name)    \(latencyText(option.latencyMs))", checked: group.selected == option.name) { [core] in
                        core.select(group: group.group, option: option.name)
                    }
                    item.image = latencyIcon(option.latencyMs)
                }
                options.addItem(.separator())
                let testing = core.testingGroups.contains(group.group)
                add(to: options, testing ? "测试中…" : "测试延迟", symbol: "speedometer", enabled: !testing) { [core] in core.test(group: group.group) }
            }
        }
        menu.addItem(.separator())
        add(to: menu, "设置为系统代理", enabled: core.summary.httpListen != nil || core.summary.socksListen != nil,
            checked: core.systemProxyOn) { [core] in core.setSystemProxy(!core.systemProxyOn) }
        add(to: menu, "增强模式", checked: core.summary.enhancedMode) { [core] in
            Task {
                if let error = await core.setEnhancedMode(!core.summary.enhancedMode) { core.lastActionError = "增强模式：\(error)" }
            }
        }
        menu.addItem(.separator())
        add(to: menu, "重新载入配置", key: "r", symbol: "arrow.triangle.2.circlepath", enabled: core.state == .running && !core.reloading) { [core] in core.reload() }
        add(to: menu, "重启内核", symbol: "arrow.clockwise", enabled: core.isActive) { [core] in core.restart() }
        menu.addItem(.separator())
        let display = submenu(in: menu, title: "菜单栏显示")
        for option in MenuBarDisplayMode.allCases {
            add(to: display, option.title, checked: layout.mode == option) { [weak self] in
                self?.core.preferences.set(option.rawValue, forKey: "menuBarDisplayMode")
                self?.refreshSettings()
            }
        }
        display.addItem(.separator())
        add(to: display, "显示当前的出站模式", checked: showsMode) { [weak self] in
            guard let self else { return }
            core.preferences.set(!showsMode, forKey: "menuBarShowOutboundMode")
            refreshSettings()
        }
        menu.addItem(.separator())
        add(to: menu, "显示主窗口", key: "0", symbol: "macwindow") { [showWindow] in showWindow(nil) }
        add(to: menu, "查看请求", symbol: "arrow.up.arrow.down.circle") { [showWindow] in showWindow(.requests) }
        add(to: menu, "编辑当前配置", symbol: "curlybraces.square") { [showWindow] in showWindow(.profile) }
        let diagnostics = DiagnosticsExporter.shared
        add(to: menu, "导出诊断信息…", symbol: "stethoscope", enabled: !diagnostics.state.isExporting) { [core, showWindow] in
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
        menu.addItem(.separator())
        add(to: menu, "检查更新…", symbol: "arrow.down.circle", enabled: Updater.shared.canCheck) { Updater.shared.checkForUpdates() }
        add(to: menu, "退出 Sluice", key: "q", symbol: "power") { NSApp.terminate(nil) }
    }

    @discardableResult
    private func add(to menu: NSMenu, _ title: String, key: String = "", symbol: String? = nil, enabled: Bool = true,
                     checked: Bool = false, action: @escaping () -> Void) -> NSMenuItem {
        let item = MenuBarAction(title: title, key: key, action: action)
        if let symbol { item.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil) }
        item.isEnabled = enabled
        item.state = checked ? .on : .off
        menu.addItem(item)
        return item
    }

    private func submenu(in menu: NSMenu, title: String, symbol: String? = nil, enabled: Bool = true) -> NSMenu {
        let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        if let symbol { item.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil) }
        item.isEnabled = enabled
        let submenu = NSMenu(title: title)
        submenu.autoenablesItems = false
        item.submenu = submenu
        menu.addItem(item)
        return submenu
    }

    private func latencyIcon(_ milliseconds: Int?) -> NSImage {
        let color = NSColor(latencyStyle(milliseconds).1)
        return NSImage(size: NSSize(width: 12, height: 12), flipped: false) { _ in
            color.setFill()
            NSBezierPath(ovalIn: NSRect(x: 3, y: 3, width: 6, height: 6)).fill()
            return true
        }
    }
}

@MainActor
private final class MenuBarAction: NSMenuItem {
    private let handler: () -> Void

    init(title: String, key: String, action: @escaping () -> Void) {
        handler = action
        super.init(title: title, action: #selector(invoke), keyEquivalent: key)
        target = self
    }

    required init(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    @objc private func invoke() { handler() }
}
