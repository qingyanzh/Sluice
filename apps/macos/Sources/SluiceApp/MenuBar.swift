import AppKit
import Combine
import SwiftUI

private extension NSFont {
    var bold: NSFont { NSFontManager.shared.convert(self, toHaveTrait: .boldFontMask) }
}

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
        speedWidth = ceil(["KB", "MB", "GB", "TB"].map { unit in "999 \(unit)/s" }.map {
            ($0 as NSString).size(withAttributes: [.font: font]).width
        }.max() ?? 0)
        speedX = mode.showsIcon ? 25 : 0
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

    func inspectMenu() {
        guard E2ELaunch.current != nil else { return }
        DispatchQueue.main.async { [weak self] in
            guard let self, let view = NSApp.keyWindow?.contentView else { return }
            let menu = NSMenu()
            menu.delegate = self
            menu.autoenablesItems = false
            menu.popUp(positioning: nil, at: NSPoint(x: view.bounds.width - 20, y: view.bounds.height - 30), in: view)
        }
    }

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
        let ink = (core.state.isFailed ? NSColor(DS.fail) : dark ? NSColor.white : NSColor.black)
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

    /// Same order as Surge's menu: main window; outbound mode; one row per policy group
    /// (current choice on the right); network quality; busiest processes; takeover
    /// switches and the terminal proxy command; a features submenu; profiles and
    /// reload; quit. A stopped core gets one line and a start action at the top.
    func menuNeedsUpdate(_ menu: NSMenu) {
        // Freeze menu choices during tracking; the fixed-width status label
        // continues receiving live rates independently.
        menuModel.refresh()
        let state = menuModel.value
        let running = state.state == .running
        menu.removeAllItems()

        add(to: menu, "显示主窗口", key: "m") { [showWindow] in showWindow(nil) }
        if !running {
            menu.addItem(info(state.systemProxyOn ? "内核未运行 · 系统代理仍指向 Sluice" : "内核\(state.state.label)"))
            add(to: menu, "启动内核", symbol: "play.fill", enabled: state.state != .starting) { [core] in core.requestStart() }
        }

        let modeTag = modeBadge(state.mode)
        let qualityTag = latencyBadge(networkLatency(state))
        let processes = busiestProcesses()
        var rows: [RightColumn] = []

        menu.addItem(.separator())
        let modes = submenu(in: menu, title: "出站模式", enabled: running)
        rows.append(RightColumn(item: menu.items.last!, name: "出站模式", image: modeTag))
        for option in OutboundMode.allCases {
            let rawValue = option.rawValue
            add(to: modes, option.title, symbol: option.icon, checked: option == state.mode) { [core, rawValue] in core.setMode(rawValue) }
        }

        menu.addItem(.separator())
        if running, !state.groups.isEmpty {
            menu.addItem(.sectionHeader(title: "策略组"))
            for group in state.groups {
                let groupName = group.group
                let options = submenu(in: menu, title: subscriptionShortLabel(groupName))
                rows.append(RightColumn(item: menu.items.last!, name: subscriptionShortLabel(groupName), detail: subscriptionShortLabel(group.selected),
                                        color: outboundColor(group.selected)))
                var optionRows: [RightColumn] = []
                for option in group.options {
                    let optionName = option.name
                    let item = add(to: options, subscriptionShortLabel(optionName), checked: group.selected == optionName) { [core, groupName, optionName] in
                        core.select(group: groupName, option: optionName)
                    }
                    optionRows.append(RightColumn(item: item, name: subscriptionShortLabel(optionName), detail: latencyText(option.latencyMs),
                                                  color: NSColor(latencyStyle(option.latencyMs).1)))
                    item.image = latencyIcon(option.latencyMs)
                }
                options.addItem(.separator())
                let testing = state.testingGroups.contains(groupName)
                add(to: options, testing ? "测试中…" : "测试延迟", symbol: "speedometer", enabled: !testing) { [core, groupName] in core.test(group: groupName) }
                Self.alignRightColumn(of: options, optionRows)
            }
        } else {
            menu.addItem(info(running ? "配置中没有策略组 · 可在「策略」页新建" : "启动内核后可在此切换节点"))
        }

        menu.addItem(.separator())
        let subscriptions = submenu(in: menu, title: core.subscriptionNotices.isEmpty ? "订阅" : "订阅 · 有更新")
        if core.subscriptions.isEmpty {
            subscriptions.addItem(info("尚未添加订阅"))
        }
        for status in core.subscriptions {
            let used = status.used.map(SubscriptionFormat.bytes)
            let total = status.total.flatMap { $0 > 0 ? SubscriptionFormat.bytes($0) : nil }
            let traffic = used.map { u in total.map { "\(u) / \($0)" } ?? "已用 \(u)" } ?? "流量未提供"
            let expiry = status.expiryDate.map { "到期 " + $0.formatted(.dateTime.year().month(.twoDigits).day(.twoDigits)) }
            subscriptions.addItem(.sectionHeader(title: status.group))
            subscriptions.addItem(info([traffic, expiry, "\(status.nodeCount) 个节点"].compactMap { $0 }.joined(separator: " · ")))
            if status.lastError != nil { subscriptions.addItem(info("上次更新失败：" + FriendlyError.explain(status.lastError ?? "").headline)) }
        }
        for notice in core.subscriptionNotices.prefix(3) {
            subscriptions.addItem(info("「\(notice.source)」\(notice.summary)"))
        }
        subscriptions.addItem(.separator())
        add(to: subscriptions, core.updatingSubscriptions ? "正在更新…" : "全部更新", symbol: "arrow.triangle.2.circlepath",
            enabled: !core.subscriptions.isEmpty && !core.updatingSubscriptions) { [core] in
            Task { if let error = await core.updateSubscriptions() { core.lastActionError = "订阅没有更新\n\(error)" } }
        }
        add(to: subscriptions, "管理订阅…", symbol: "link") { [showWindow] in showWindow(.subscriptions) }

        menu.addItem(.separator())
        let quality = add(to: menu, "网络质量", enabled: running && state.testingGroups.isEmpty) { [core] in core.testAll() }
        rows.append(RightColumn(item: quality, name: "网络质量", image: qualityTag, dimmed: true))
        quality.toolTip = "当前节点的延迟，点击重新测试全部策略组"

        menu.addItem(.separator())
        menu.addItem(.sectionHeader(title: "进程与客户端"))
        if processes.isEmpty {
            menu.addItem(info(running ? "暂无活动连接" : "—"))
        } else {
            for (name, rate) in processes {
                let item = add(to: menu, name) { [showWindow] in showWindow(.requests) }
                rows.append(RightColumn(item: item, name: name, detail: menuBarSpeed(rate)))
                item.image = processIcon(name)
            }
        }

        menu.addItem(.separator())
        add(to: menu, "设置为系统代理", key: "s", enabled: state.canSetSystemProxy,
            checked: state.systemProxyOn) { [core, on = !state.systemProxyOn] in core.setSystemProxy(on) }
        add(to: menu, "增强模式", key: "e", checked: state.enhancedMode) { [core, on = !state.enhancedMode] in
            Task {
                if let error = await core.setEnhancedMode(on) { core.lastActionError = "增强模式没有切换\n\(error)" }
            }
        }
        add(to: menu, "复制终端代理命令", key: "c", enabled: terminalProxyCommand != nil) { [weak self] in
            if let command = self?.terminalProxyCommand { copyText(command) }
        }

        menu.addItem(.separator())
        let features = submenu(in: menu, title: "功能")
        add(to: features, "查看请求", symbol: "arrow.up.arrow.down.circle") { [showWindow] in showWindow(.requests) }
        add(to: features, "编辑策略组", symbol: "square.stack.3d.up") { [showWindow] in showWindow(.policy) }
        add(to: features, "编辑当前配置", symbol: "curlybraces.square") { [showWindow] in showWindow(.profile) }
        features.addItem(.separator())
        add(to: features, state.isActive ? "停止内核" : "启动内核", symbol: state.isActive ? "stop.fill" : "play.fill",
            enabled: state.state != .starting) { [core] in
            if core.isActive { core.stop() } else { core.requestStart() }
        }
        add(to: features, "重启内核", symbol: "arrow.clockwise", enabled: state.isActive) { [core] in core.restart() }
        features.addItem(.separator())
        let display = submenu(in: features, title: "菜单栏显示", symbol: "menubar.rectangle")
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
        features.addItem(.separator())
        let diagnostics = DiagnosticsExporter.shared
        add(to: features, "导出诊断信息…", symbol: "stethoscope", enabled: !state.isExporting) { [core, showWindow] in
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
        add(to: features, "检查更新…", symbol: "arrow.down.circle", enabled: Updater.shared.canCheck) { Updater.shared.checkForUpdates() }

        menu.addItem(.separator())
        let profiles = submenu(in: menu, title: "切换配置", enabled: !core.profileNames.isEmpty)
        for name in core.profileNames {
            add(to: profiles, name, checked: name == state.profileName) { [core, name] in
                Task {
                    do { try await core.switchProfile(to: name) }
                    catch { core.lastActionError = "配置没有切换\n\(error.localizedDescription)" }
                }
            }
        }
        add(to: menu, "重载配置", key: "r", enabled: running && !state.reloading) { [core] in core.reload() }

        menu.addItem(.separator())
        add(to: menu, "退出", key: "q") { NSApp.terminate(nil) }
        Self.alignRightColumn(of: menu, rows)
    }

    /// Direct green, reject red, any proxy or group indigo: the same grammar as the window.
    private func outboundColor(_ name: String) -> NSColor {
        NSColor(name == "DIRECT" ? DS.ok : name == "REJECT" ? DS.fail : DS.info)
    }

    /// Latency of what traffic currently uses: the main group's selection, if tested.
    private func networkLatency(_ state: MenuBarState) -> Int? {
        guard let group = state.groups.first, let option = group.options.first(where: { $0.name == group.selected }) else { return nil }
        return core.nodeLatencies[option.name] ?? option.latencyMs
    }

    /// Up to five processes with the highest current rate.
    private func busiestProcesses() -> [(String, Double)] {
        var rates: [String: Double] = [:]
        for connection in core.activeConnections {
            rates[connection.process ?? "其他", default: 0] += Double(connection.rateUp + connection.rateDown)
        }
        return rates.sorted { $0.value == $1.value ? $0.key < $1.key : $0.value > $1.value }.prefix(5).map { ($0.key, $0.value) }
    }

    /// `export https_proxy=… http_proxy=… all_proxy=…` for the configured listeners.
    private var terminalProxyCommand: String? {
        var parts: [String] = []
        if let (host, port) = SystemProxy.split(core.summary.httpListen) {
            parts += ["https_proxy=http://\(host):\(port)", "http_proxy=http://\(host):\(port)"]
        }
        if let (host, port) = SystemProxy.split(core.summary.socksListen) { parts.append("all_proxy=socks5://\(host):\(port)") }
        return parts.isEmpty ? nil : "export " + parts.joined(separator: " ")
    }

    private func processIcon(_ name: String) -> NSImage? {
        let app = NSWorkspace.shared.runningApplications.first { $0.localizedName == name || $0.executableURL?.lastPathComponent == name }
        let icon = app?.icon ?? NSImage(systemSymbolName: "gearshape", accessibilityDescription: nil)
        icon?.size = NSSize(width: 16, height: 16)
        return icon
    }

    /// A small filled tag: the outbound mode letter.
    private func modeBadge(_ mode: OutboundMode) -> NSImage {
        let letter = switch mode { case .direct: "D"; case .global: "G"; case .rule: "R" }
        return tag(letter, color: NSColor(DS.accent), width: 18)
    }

    /// A small filled tag with the latency, coloured like the app's latency badges.
    private func latencyBadge(_ milliseconds: Int?) -> NSImage {
        let (text, color) = latencyStyle(milliseconds)
        return tag(text, color: milliseconds == nil ? .tertiaryLabelColor : NSColor(color), width: nil)
    }

    private func tag(_ text: String, color: NSColor, width: CGFloat?) -> NSImage {
        let font = NSFont.systemFont(ofSize: 10.5, weight: .semibold)
        let textWidth = (text as NSString).size(withAttributes: [.font: font]).width
        let size = NSSize(width: width ?? ceil(textWidth + 12), height: 16)
        return NSImage(size: size, flipped: false) { rect in
            color.setFill()
            NSBezierPath(roundedRect: rect, xRadius: 4, yRadius: 4).fill()
            let paragraph = NSMutableParagraphStyle()
            paragraph.alignment = .center
            (text as NSString).draw(in: NSRect(x: 0, y: 1.5, width: rect.width, height: 13), withAttributes: [
                .font: font, .foregroundColor: NSColor.white, .paragraphStyle: paragraph,
            ])
            return true
        }
    }

    /// A non-interactive line (status, rates, hints).
    private func info(_ title: String) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        item.isEnabled = false
        return item
    }

    private func info(attributed: NSAttributedString) -> NSMenuItem {
        let item = info(attributed.string)
        item.attributedTitle = attributed
        return item
    }

    /// A row whose detail (text or a small tag) sits flush with the menu's right edge.
    struct RightColumn {
        let item: NSMenuItem
        let name: String
        var detail: String? = nil
        var color: NSColor = .secondaryLabelColor
        var image: NSImage? = nil
        var dimmed = false
    }

    /// Reserve enough intrinsic space, then align detail drawing to AppKit's actual
    /// title field width. Parent menus reserve their native arrow column; option
    /// menus without arrows keep an additional eight-point inner margin.
    static func alignRightColumn(of menu: NSMenu, _ rows: [RightColumn]) {
        let font = NSFont.menuFont(ofSize: 0)
        let detailFont = NSFont.monospacedDigitSystemFont(ofSize: font.pointSize, weight: .regular)
        var rows = rows
        let listed = Set(rows.map { ObjectIdentifier($0.item) })
        for item in menu.items {
            if let action = item as? MenuBarAction, let shortcut = action.shortcut, !listed.contains(ObjectIdentifier(item)) {
                rows.append(RightColumn(item: item, name: item.title, detail: shortcut, color: .tertiaryLabelColor))
            }
        }
        guard !rows.isEmpty else { return }
        func width(_ text: String) -> CGFloat { (text as NSString).size(withAttributes: [.font: font]).width }
        let special = Set(rows.map { ObjectIdentifier($0.item) })
        let plain = menu.items.filter { !$0.isSeparatorItem && !special.contains(ObjectIdentifier($0)) }.map { width($0.title) }
        let needed = rows.map { row in width(row.name) + 24 + (row.image?.size.width ?? row.detail.map { ($0 as NSString).size(withAttributes: [.font: detailFont]).width } ?? 0) }
        let tab = ceil((plain + needed).max() ?? 0)
        let paragraph = NSMutableParagraphStyle()
        paragraph.tabStops = [NSTextTab(textAlignment: .right, location: tab)]
        let trailingInset: CGFloat = menu.items.contains(where: { $0.submenu != nil }) ? 0 : 8
        for row in rows {
            let title = NSMutableAttributedString(string: row.name, attributes: [
                .font: font, .paragraphStyle: paragraph,
                .foregroundColor: row.dimmed || !row.item.isEnabled ? NSColor.secondaryLabelColor : NSColor.labelColor,
            ])
            let detailImage = row.image ?? row.detail.map { detail in
                let text = NSAttributedString(string: detail, attributes: [
                    .font: detailFont,
                    .foregroundColor: row.item.isEnabled ? row.color : NSColor.tertiaryLabelColor,
                ])
                let size = NSSize(width: ceil(text.size().width), height: ceil(text.size().height))
                return NSImage(size: size, flipped: false) { _ in text.draw(at: .zero); return true }
            }
            if let image = detailImage {
                let attachment = NSTextAttachment()
                attachment.bounds = NSRect(x: 0, y: -3, width: image.size.width, height: image.size.height)
                let cell = TrailingMenuDetailCell(imageCell: image)
                cell.trailingInset = trailingInset
                attachment.attachmentCell = cell
                title.append(NSAttributedString(string: "\t", attributes: [.paragraphStyle: paragraph]))
                title.append(NSAttributedString(attachment: attachment))
            }
            row.item.attributedTitle = title
            row.item.setAccessibilityLabel([row.name, row.detail].compactMap { $0 }.joined(separator: "，"))
        }
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

/// AppKit can widen the title field beyond its attributed string's tab stop.
/// Align against the actual field bounds; option menus also need an inner margin.
final class TrailingMenuDetailCell: NSTextAttachmentCell {
    var trailingInset: CGFloat = 0
    func drawingFrame(_ frame: NSRect, in bounds: NSRect?) -> NSRect {
        guard let bounds else { return frame }
        var result = frame
        result.origin.x = bounds.maxX - trailingInset - frame.width
        return result
    }
    override func draw(withFrame cellFrame: NSRect, in controlView: NSView?) {
        image?.draw(in: drawingFrame(cellFrame, in: controlView?.bounds))
    }
}

@MainActor
private final class MenuBarAction: NSMenuItem {
    private let handler: () -> Void
    /// Drawn in the right column with the other details ("⌘M") instead of in AppKit's
    /// separate key-equivalent column, so everything on the right lines up.
    let shortcut: String?

    init(title: String, key: String, action: @escaping () -> Void) {
        handler = action
        shortcut = key.isEmpty ? nil : "⌘" + key.uppercased()
        super.init(title: title, action: #selector(invoke), keyEquivalent: "")
        target = self
    }

    required init(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    @objc private func invoke() { handler() }
}
