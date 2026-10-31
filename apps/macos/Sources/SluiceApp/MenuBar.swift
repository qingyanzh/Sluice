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
struct MenuBarImageKey: Equatable {
    let mode: MenuBarDisplayMode
    let font: NSFont
    let upload: String
    let download: String
    let modeMark: String
    let showsMode: Bool
    let dark: Bool
    let ink: NSColor
}

struct MenuBarImageCache {
    private var lastKey: MenuBarImageKey?

    mutating func image(for key: MenuBarImageKey, render: () -> NSImage) -> NSImage? {
        guard key != lastKey else { return nil }
        // Commit before assigning button.image, which can trigger appearance KVO.
        lastKey = key
        return render()
    }
}

@MainActor
final class MenuBarStatusItem: NSObject, NSMenuDelegate {
    private let core: Core
    private let menuModel: MenuBarModel
    private let showWindow: (Pane?) -> Void
    private let statusItem: NSStatusItem
    private var layout: MenuBarLayout
    private var subscriptions = Set<AnyCancellable>()
    private var appearanceObservation: NSKeyValueObservation?
    private var showsMode = true
    private var dimWhenNotProxying = true
    private var imageCache = MenuBarImageCache()
    private var refreshPending = false
    private var accessibilityLabel: String?

    init(core: Core, showWindow: @escaping (Pane?) -> Void) {
        self.core = core
        menuModel = MenuBarModel(core: core, diagnostics: .shared)
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
        core.objectWillChange.sink { [weak self] _ in
            self?.scheduleRefresh()
        }.store(in: &subscriptions)
        NotificationCenter.default.publisher(for: UserDefaults.didChangeNotification)
            .receive(on: DispatchQueue.main).sink { [weak self] _ in
                self?.refreshSettings()
            }.store(in: &subscriptions)
        appearanceObservation = statusItem.button?.observe(\.effectiveAppearance) { [weak self] _, _ in
            Task { @MainActor in self?.scheduleRefresh() }
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
        scheduleRefresh()
    }

    private func scheduleRefresh() {
        guard !refreshPending else { return }
        refreshPending = true
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            refreshPending = false
            refreshImage()
        }
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
        let key = MenuBarImageKey(mode: layout.mode, font: layout.font,
                                  upload: layout.mode.showsSpeed ? core.displayedRates.up.menuText : "",
                                  download: layout.mode.showsSpeed ? core.displayedRates.down.menuText : "",
                                  modeMark: showsMode && layout.mode.showsIcon ? mark : "",
                                  showsMode: showsMode, dark: dark, ink: ink)
        if let image = imageCache.image(for: key, render: {
            MenuBarLabel.image(layout: layout, upload: key.upload, download: key.download,
                               modeMark: key.modeMark, showsMode: key.showsMode, dark: dark, ink: ink)
        }) { button.image = image }
        let label = "Sluice，\(core.state.label)\(showsMode && layout.mode.showsIcon ? "，\(mode.title)" : "")\(layout.mode.showsSpeed ? "，上传每秒 \(core.displayedRates.up.menuText)，下载每秒 \(core.displayedRates.down.menuText)" : "")"
        if accessibilityLabel != label {
            accessibilityLabel = label
            button.setAccessibilityLabel(label)
        }
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        // Freeze menu choices during tracking; the fixed-width status label
        // continues receiving live rates independently.
        menuModel.refresh()
        let state = menuModel.value
        menu.removeAllItems()
        menu.addItem(NSMenuItem(title: "Sluice · \(state.state.label)", action: nil, keyEquivalent: ""))
        menu.addItem(NSMenuItem(title: "配置：\(state.profileName)", action: nil, keyEquivalent: ""))
        if state.state == .running {
            menu.addItem(NSMenuItem(title: "↓ \(core.displayedRates.down.formatted.text)   ↑ \(core.displayedRates.up.formatted.text)   ·   \(core.traffic?.active ?? 0) 个连接", action: nil, keyEquivalent: ""))
        } else if state.systemProxyOn {
            menu.addItem(NSMenuItem(title: "系统代理已开启，内核未运行", action: nil, keyEquivalent: ""))
        }
        if let other = state.otherSystemProxy {
            menu.addItem(NSMenuItem(title: "系统代理：\(other)", action: nil, keyEquivalent: ""))
        }
        menu.addItem(.separator())
        add(to: menu, state.isActive ? "停止 Sluice" : "启动 Sluice", symbol: state.isActive ? "stop.fill" : "play.fill", enabled: state.state != .starting) { [core] in
            if core.isActive { core.stop() } else { core.requestStart() }
        }
        menu.addItem(.separator())
        let mode = state.mode
        let modes = submenu(in: menu, title: "出站模式：\(mode.title)", symbol: mode.icon, enabled: state.state == .running)
        for option in OutboundMode.allCases {
            let rawValue = option.rawValue
            add(to: modes, option.title, symbol: option.icon, checked: option == mode) { [core, rawValue] in core.setMode(rawValue) }
        }
        if !state.groups.isEmpty {
            menu.addItem(.separator())
            for group in state.groups {
                let groupName = group.group
                let options = submenu(in: menu, title: "\(groupName)：\(group.selected)", symbol: "point.3.connected.trianglepath.dotted", enabled: state.state == .running)
                for option in group.options {
                    let optionName = option.name
                    let item = add(to: options, "\(optionName)    \(latencyText(option.latencyMs))", checked: group.selected == optionName) { [core, groupName, optionName] in
                        core.select(group: groupName, option: optionName)
                    }
                    item.image = latencyIcon(option.latencyMs)
                }
                options.addItem(.separator())
                let testing = state.testingGroups.contains(groupName)
                add(to: options, testing ? "测试中…" : "测试延迟", symbol: "speedometer", enabled: !testing) { [core, groupName] in core.test(group: groupName) }
            }
        }
        menu.addItem(.separator())
        add(to: menu, "设置为系统代理", enabled: state.canSetSystemProxy,
            checked: state.systemProxyOn) { [core, on = !state.systemProxyOn] in core.setSystemProxy(on) }
        add(to: menu, "增强模式", checked: state.enhancedMode) { [core, on = !state.enhancedMode] in
            Task {
                if let error = await core.setEnhancedMode(on) { core.lastActionError = "增强模式：\(error)" }
            }
        }
        menu.addItem(.separator())
        add(to: menu, "重新载入配置", key: "r", symbol: "arrow.triangle.2.circlepath", enabled: state.state == .running && !state.reloading) { [core] in core.reload() }
        add(to: menu, "重启内核", symbol: "arrow.clockwise", enabled: state.isActive) { [core] in core.restart() }
        menu.addItem(.separator())
        let display = submenu(in: menu, title: "菜单栏显示")
        for option in MenuBarDisplayMode.allCases {
            let rawValue = option.rawValue
            add(to: display, option.title, checked: state.displayMode == option) { [weak self, core, rawValue] in
                core.preferences.set(rawValue, forKey: "menuBarDisplayMode")
                self?.refreshSettings()
            }
        }
        display.addItem(.separator())
        add(to: display, "显示当前的出站模式", checked: state.showOutboundMode) { [weak self, show = !state.showOutboundMode] in
            guard let self else { return }
            core.preferences.set(show, forKey: "menuBarShowOutboundMode")
            refreshSettings()
        }
        menu.addItem(.separator())
        add(to: menu, "显示主窗口", key: "0", symbol: "macwindow") { [showWindow] in showWindow(nil) }
        add(to: menu, "查看请求", symbol: "arrow.up.arrow.down.circle") { [showWindow] in showWindow(.requests) }
        add(to: menu, "编辑当前配置", symbol: "curlybraces.square") { [showWindow] in showWindow(.profile) }
        let diagnostics = DiagnosticsExporter.shared
        add(to: menu, "导出诊断信息…", symbol: "stethoscope", enabled: !state.isExporting) { [core, showWindow] in
            if core.lastActionError?.hasPrefix("导出诊断信息失败：") == true { core.lastActionError = nil }
            Task {
                await diagnostics.export(api: core.state == .running ? core.api : nil,
                                         binary: core.coreBinary, configPath: core.configPath)
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
