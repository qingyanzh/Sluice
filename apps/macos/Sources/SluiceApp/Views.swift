import AppKit
import Charts
import ServiceManagement
import SwiftUI

enum Pane: String, CaseIterable, Identifiable {
    case activity, overview, requests, policy, nodes, rule, logs, dns, profile
    var id: String { rawValue }

    var title: String {
        switch self {
        case .activity: "活动"
        case .overview: "设置"
        case .requests: "请求"
        case .policy: "策略"
        case .nodes: "节点"
        case .rule: "规则"
        case .logs: "日志"
        case .dns: "DNS 缓存"
        case .profile: "配置"
        }
    }

    var icon: String {
        switch self {
        case .activity: "gauge.with.needle"
        case .overview: "gearshape"
        case .requests: "arrow.up.arrow.down.circle"
        case .policy: "signpost.right"
        case .nodes: "globe.asia.australia"
        case .rule: "line.3.horizontal.decrease.circle"
        case .logs: "doc.text"
        case .dns: "network"
        case .profile: "curlybraces.square"
        }
    }

    /// One line under the pane title saying what the pane is for.
    var subtitle: String {
        switch self {
        case .activity: "运行状态与实时流量"
        case .overview: "接管方式、代理服务、启动与外观"
        case .requests: ""
        case .policy: "出站模式与策略组"
        case .nodes: "配置中的节点和订阅"
        case .rule: "自上而下匹配，命中即停止"
        case .logs: "内核输出"
        case .dns: "缓存的域名解析与剩余有效期"
        case .profile: ""
        }
    }

    /// Sidebar sections, Surge-style: an untitled top group, then titled groups.
    static let sections: [(String?, [Pane])] = [
        (nil, [.activity]),
        ("代理", [.requests, .policy, .nodes, .rule]),
        ("工具", [.logs, .dns, .profile]),
    ]
    /// 设置 sits apart at the bottom of the sidebar, above the status footer.
    static let pinned: Pane = .overview
    /// Sidebar order, which is also the ⌘1…⌘9 order.
    static let ordered: [Pane] = sections.flatMap(\.1) + [pinned]
}

/// Outbound modes, in the order Surge shows them.
enum OutboundMode: String, CaseIterable, Identifiable {
    case direct, global, rule
    var id: String { rawValue }
    var title: String {
        switch self {
        case .direct: "直接连接"
        case .global: "全局代理"
        case .rule: "规则判定"
        }
    }
    var icon: String {
        switch self {
        case .direct: "arrow.left.and.right"
        case .global: "globe"
        case .rule: "arrow.triangle.branch"
        }
    }
    var explanation: String {
        switch self {
        case .direct: "所有请求直接连接，不经过任何代理。"
        case .global: "所有请求都交给 FINAL 规则的策略处理。"
        case .rule: "根据规则系统判定处理方式。"
        }
    }
}

/// The sidebar sits on the page colour with no divider, so it reads as part of the
/// window rather than a separate panel. Selection is a white pill that slides.
struct Sidebar: View {
    @Binding var pane: Pane?
    @Namespace private var ns

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    ForEach(Pane.sections, id: \.1) { title, panes in
                        VStack(alignment: .leading, spacing: 4) {
                            if let title {
                                Text(title).font(DS.small.weight(.medium)).foregroundStyle(DS.ink3)
                                    .padding(.leading, 14).padding(.bottom, 6)
                            }
                            ForEach(panes) { row($0) }
                        }
                    }
                }
                .padding(.horizontal, 14).padding(.top, 58).padding(.bottom, 24)
            }
            .scrollIndicators(.never)
            row(Pane.pinned).padding(.horizontal, 14).padding(.bottom, 8)
            StatusFooter().padding(.horizontal, 14).padding(.bottom, 14)
        }
        .frame(width: DS.sidebarWidth)
    }

    @State private var hovered: Pane?

    private func row(_ p: Pane) -> some View {
        let on = pane == p
        return Button {
            withAnimation(DS.spring) { pane = p }
        } label: {
            HStack(spacing: 10) {
                Image(systemName: p.icon)
                    .font(.system(size: 17, weight: .regular))
                    .foregroundStyle(on ? DS.accent : DS.ink2)
                    .frame(width: 24, height: 24)
                Text(p.title).font(DS.navigation.weight(on ? .semibold : .regular))
                Spacer()
            }
            .foregroundStyle(on ? Color.primary : DS.ink2)
            .padding(.leading, 12).padding(.trailing, 14).frame(height: DS.navigationRowHeight)
            .background {
                if on {
                    RoundedRectangle(cornerRadius: DS.smallRadius, style: .continuous).fill(DS.surface)
                        .shadow(color: .black.opacity(0.035), radius: 2, y: 1)
                        .matchedGeometryEffect(id: "selection", in: ns)
                } else if hovered == p {
                    RoundedRectangle(cornerRadius: DS.smallRadius, style: .continuous).fill(Color.primary.opacity(0.035))
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(PressableStyle())
        .help("\(p.title)  ⌘\((Pane.ordered.firstIndex(of: p) ?? 0) + 1)")
        .onHover { inside in withAnimation(.easeOut(duration: 0.15)) { hovered = inside ? p : (hovered == p ? nil : hovered) } }
    }
}

/// The app's own appearance setting, independent of the system's.
enum Appearance: String, CaseIterable {
    case system, light, dark
    var title: String {
        switch self {
        case .system: "跟随系统"
        case .light: "浅色"
        case .dark: "深色"
        }
    }
    var icon: String {
        switch self {
        case .system: "circle.lefthalf.filled"
        case .light: "sun.max"
        case .dark: "moon"
        }
    }
    var scheme: ColorScheme? {
        switch self {
        case .system: nil
        case .light: .light
        case .dark: .dark
        }
    }
}

/// A sheet another pane asks the nodes pane to open.
enum NodesIntent { case node, subscription }

struct MainView: View {
    @EnvironmentObject var core: Core
    @State private var pane: Pane? = .activity
    @StateObject private var configDraft = ConfigDraft()
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var nodesIntent: NodesIntent?
    @AppStorage("appearance") private var appearance = Appearance.system

    var body: some View {
        HStack(spacing: 0) {
            Sidebar(pane: $pane)
                .background {
                    // ⌘1…⌘9 jump to panes in sidebar order.
                    ForEach(Array(Pane.ordered.enumerated()), id: \.element) { i, p in
                        Button("") { withAnimation(DS.spring) { pane = p } }
                            .keyboardShortcut(KeyEquivalent(Character("\(i + 1)")), modifiers: .command)
                            .opacity(0).frame(width: 0, height: 0).accessibilityHidden(true)
                    }
                }
            VStack(spacing: 0) {
                if let err = core.lastActionError {
                    ErrorBanner(message: err) { core.lastActionError = nil }
                }
                if core.systemProxyOn && core.state != .running && core.state != .starting {
                    // Inconsistent and harmful: the system sends traffic to a port nobody listens on.
                    Notice(tone: DS.warn, icon: "exclamationmark.triangle.fill", title: "系统代理已开启，但内核未运行",
                           detail: "此时经过系统代理的网络请求都会失败。启动 Sluice，或关闭系统代理恢复直接上网。") {
                        Button("关闭系统代理") { core.setSystemProxy(false) }.glassButton()
                        Button("启动 Sluice") { core.start() }.glassButton(prominent: true)
                    }
                    .padding(.horizontal, DS.gutter).padding(.top, 8)
                }
                Group {
                switch pane ?? .activity {
                case .activity: ActivityView(pane: $pane, nodesIntent: $nodesIntent)
                case .overview: OverviewView()
                case .requests: RequestsView()
                case .policy: PolicyView()
                case .nodes: NodesView(intent: $nodesIntent)
                case .rule: RuleView(pane: $pane)
                case .logs: LogsView()
                case .dns: DNSView()
                case .profile: ConfigView(draft: configDraft)
                }
                }
                .id(pane)
                .frame(maxWidth: DS.maxContentWidth)
                .frame(maxWidth: .infinity)
                .transition(.asymmetric(insertion: .opacity.combined(with: .offset(y: 8)), removal: .opacity))
            }
            .animation(.smooth(duration: 0.25), value: pane)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            .padding(.top, 40)
            .background(Backdrop())
            .toolbarBackground(.hidden, for: .windowToolbar)
            .toolbar {
                ToolbarItemGroup(placement: .primaryAction) {
                    TogglePill(title: "系统代理", on: core.systemProxyOn,
                               warning: core.systemProxyOn && core.state != .running && core.state != .starting) { core.setSystemProxy(!core.systemProxyOn) }
                        .disabled(core.summary.httpListen == nil && core.summary.socksListen == nil)
                        .help(core.systemProxyOn && core.state != .running ? "系统代理已开启，但内核未运行：网络请求会失败" : "把系统的 HTTP/HTTPS/SOCKS 代理指向 Sluice")
                    EnhancedModePill()
                }
            }
        }
        .background(Backdrop())
        .ignoresSafeArea(.container, edges: .top)
        .navigationTitle("")
        .preferredColorScheme(appearance.scheme)
        .tint(DS.accent)
        .transaction { if reduceMotion { $0.animation = nil; $0.disablesAnimations = true } }
        .frame(minWidth: 900, minHeight: 640)
        .onAppear {
            if let requested = core.requestedPane {
                pane = requested
                core.requestedPane = nil
            }
            core.refreshSystemProxy()
            core.startIfAutoStart()
        }
        .onChange(of: core.requestedPane) { _, requested in
            if let requested {
                pane = requested
                core.requestedPane = nil
            }
        }
    }
}

// MARK: shared bits

struct StatusDot: View {
    let state: Core.State
    var color: Color { state.tone }
    var body: some View {
        Circle().fill(color).frame(width: 8, height: 8)
            .background {
                // A soft halo breathes while the core is running.
                if state == .running {
                    Circle().fill(color.opacity(0.35)).frame(width: 8, height: 8)
                        .phaseAnimator([1.0, 2.2]) { v, scale in v.scaleEffect(scale).opacity(2.4 - scale) }
                            animation: { _ in .easeInOut(duration: 1.4) }
                }
            }
            .animation(.smooth, value: color)
    }
}

extension Core.State {
    /// The state colour grammar applied to the core: green running, orange starting, grey stopped, red failed.
    var tone: Color {
        switch self {
        case .running: DS.ok
        case .starting: DS.warn
        case .stopped: DS.off
        case .failed: DS.fail
        }
    }
}

/// The hero status mark: a soft tinted disc holding a symbol, with a breathing
/// ring while running.
struct StatusOrb: View {
    let state: Core.State
    private var color: Color { state.tone }
    private var symbol: String {
        switch state {
        case .running: "checkmark"
        case .starting: "ellipsis"
        case .stopped: "power"
        case .failed: "exclamationmark"
        }
    }
    var body: some View {
        ZStack {
            Circle().fill(color.opacity(0.12))
            if state == .running {
                Circle().strokeBorder(color.opacity(0.35), lineWidth: 1.5)
                    .phaseAnimator([1.0, 1.35]) { v, k in v.scaleEffect(k).opacity(1.6 - k) } animation: { _ in .easeInOut(duration: 1.6) }
            }
            Image(systemName: symbol).font(.system(size: 15, weight: .bold)).foregroundStyle(color)
                .contentTransition(.symbolEffect(.replace))
        }
        .frame(width: 44, height: 44)
        .animation(DS.spring, value: symbol)
    }
}

/// The one icon container used everywhere (sidebar, cards, rows): an SF Symbol in a
/// continuous rounded square. At rest it is a quiet grey tile; when on, it fills with
/// the accent and the glyph turns white and filled.
struct IconTile: View {
    let symbol: String
    var on = false
    var size: CGFloat = 30
    /// Fill when on; the accent unless the tile marks a warning or an error.
    var tone: Color = DS.accent
    var body: some View {
        RoundedRectangle(cornerRadius: size * 0.3, style: .continuous)
            .fill(on ? AnyShapeStyle(tone) : AnyShapeStyle(Color.primary.opacity(0.075)))
            .overlay {
                Image(systemName: symbol)
                    .symbolVariant(on ? .fill : .none)
                    .font(.system(size: size * 0.5, weight: .medium))
                    .foregroundStyle(on ? Color.white : DS.ink2)
                    .contentTransition(.symbolEffect(.replace))
            }
            .frame(width: size, height: size)
            .animation(DS.spring, value: on)
            // Decorative: the label next to it already says what it is.
            .accessibilityHidden(true)
    }
}

/// The one status chip used everywhere: a dot and a short label in a tinted capsule.
struct StatusBadge: View {
    let text: String
    var tone: Color = .secondary
    var body: some View {
        HStack(spacing: 5) {
            Circle().fill(tone).frame(width: 6, height: 6)
            Text(text).font(DS.caption).lineLimit(1).truncationMode(.middle)
        }
        .foregroundStyle(tone == .secondary ? DS.ink2 : tone)
        .padding(.horizontal, 8).padding(.vertical, 3)
        .background(tone.opacity(tone == .secondary ? 0.08 : 0.10), in: Capsule())
    }
}

/// Toolbar capsule with a status dot, like Surge's System Proxy / Enhanced Mode buttons.
struct TogglePill: View {
    let title: String
    let on: Bool
    /// On, but not doing its job (e.g. system proxy set while the core is stopped).
    var warning = false
    let action: () -> Void
    var body: some View {
        Button(action: action) {
            HStack(spacing: 6) {
                let dot: Color = warning ? DS.warn : on ? DS.ok : DS.off.opacity(0.6)
                Circle().fill(dot).frame(width: 7, height: 7)
                    .scaleEffect(on ? 1 : 0.8)
                    .animation(DS.spring, value: on)
                Text(title).font(DS.small.weight(on ? .semibold : .medium))
                    .foregroundStyle(on ? Color.primary : DS.ink2)
            }
            .padding(.horizontal, 4)
        }
    }
}

struct EnhancedModePill: View {
    @EnvironmentObject var core: Core
    @State private var busy = false
    var body: some View {
        TogglePill(title: "增强模式", on: core.summary.enhancedMode && (core.privileged || !core.isActive)) {
            busy = true
            Task {
                if let err = await core.setEnhancedMode(!core.summary.enhancedMode) { core.lastActionError = "增强模式: \(err)" }
                busy = false
            }
        }
        .disabled(busy)
        .help("增强模式以 root 运行内核以接管不遵循系统代理的应用（需要管理员密码）")
    }
}

struct StatusFooter: View {
    @EnvironmentObject var core: Core
    var body: some View {
        HStack(spacing: 8) {
            Image(nsImage: NSApp.applicationIconImage).resizable().frame(width: 28, height: 28)
            VStack(alignment: .leading, spacing: 1) {
                Text("Sluice").font(DS.label.weight(.semibold))
                HStack(spacing: 4) {
                    StatusDot(state: core.state)
                    Text(core.privileged ? "\(core.state.label) · root" : core.state.label).font(DS.caption).foregroundStyle(DS.ink2)
                }
            }
            Spacer()
            StartStopButton(compact: true)
                .buttonStyle(RoundIconStyle())
        }
        .padding(.horizontal, 12).padding(.vertical, 12)
        .background(DS.surface.opacity(0.65), in: RoundedRectangle(cornerRadius: DS.radius, style: .continuous))
    }
}

struct StartStopButton: View {
    @EnvironmentObject var core: Core
    var compact = false
    var body: some View {
        if core.isActive {
            Button { core.stop() } label: { Label("停止", systemImage: "stop.fill").contentTransition(.symbolEffect(.replace)) }
                .labelStyle(compact ? AnyLabelStyle(.iconOnly) : AnyLabelStyle(.titleAndIcon))
                .help("停止 Sluice")
        } else {
            Button { core.start() } label: { Label("启动", systemImage: "play.fill").contentTransition(.symbolEffect(.replace)) }
                .labelStyle(compact ? AnyLabelStyle(.iconOnly) : AnyLabelStyle(.titleAndIcon))
                .help("启动 Sluice")
        }
    }
}

struct AnyButtonStyle: ButtonStyle {
    private let make: (Configuration) -> AnyView
    init<S: ButtonStyle>(_ style: S) { make = { AnyView(style.makeBody(configuration: $0)) } }
    func makeBody(configuration: Configuration) -> some View { make(configuration) }
}

struct AnyLabelStyle: LabelStyle {
    private let make: (Configuration) -> AnyView
    init<S: LabelStyle>(_ style: S) { make = { AnyView(style.makeBody(configuration: $0)) } }
    func makeBody(configuration: Configuration) -> some View { make(configuration) }
}

struct ErrorBanner: View {
    let message: String
    let dismiss: () -> Void
    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            Image(systemName: "exclamationmark.triangle.fill").font(.system(size: 13, weight: .semibold))
                .foregroundStyle(.white)
                .frame(width: 28, height: 28)
                .background(Color.red.gradient, in: RoundedRectangle(cornerRadius: 8.4, style: .continuous))
            Text(message).font(DS.label).textSelection(.enabled).lineLimit(3)
                .frame(maxWidth: .infinity, alignment: .leading)
            Button(action: dismiss) { Image(systemName: "xmark") }
                .buttonStyle(RoundIconStyle())
                .accessibilityLabel("关闭")
        }
        .padding(10)
        .background(Color.red.opacity(0.08), in: RoundedRectangle(cornerRadius: DS.radius, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: DS.radius, style: .continuous).strokeBorder(Color.red.opacity(0.25), lineWidth: 0.5))
        .padding(.horizontal, DS.gutter).padding(.top, 8)
        .transition(.move(edge: .top).combined(with: .opacity))
    }
}

func latencyStyle(_ latency: Int?) -> (String, Color) {
    let color: Color
    switch LatencyClassification(milliseconds: latency) {
    case .untested: color = DS.ink3
    case .good: color = DS.ok
    case .ok: color = DS.warn
    case .slow, .timeout: color = DS.fail
    }
    return (latencyText(latency), color)
}

struct LatencyBadge: View {
    let latency: Int?
    var body: some View {
        let (text, color) = latencyStyle(latency)
        StatusBadge(text: text, tone: color)
            .monospacedDigit()
    }
}

/// Both panes share the same test state, including progress across pane changes.
struct TestAllLatencyButton: View {
    @EnvironmentObject private var core: Core

    var body: some View {
        Button { core.testAll() } label: {
            HStack(spacing: 6) {
                if !core.testingGroups.isEmpty {
                    ProgressView().controlSize(.small)
                    Text("测试中… \(core.testingTotal - core.testingGroups.count)/\(core.testingTotal)")
                        .monospacedDigit()
                } else {
                    Label("测试全部", systemImage: "speedometer")
                }
            }
        }
        .glassButton()
        .disabled(core.state != .running || core.groups.isEmpty || !core.testingGroups.isEmpty)
        .help("并发测试所有策略组的节点延迟")
    }
}

/// Shared layout, colour, type and motion tokens for the macOS interface.
/// See docs/design-language.md for the rules that use them.
enum DS {
    static let gutter: CGFloat = 28
    static let gap: CGFloat = 16
    static let cardPadding: CGFloat = 20
    static let sectionGap: CGFloat = 24
    static let sidebarWidth: CGFloat = 212
    static let navigationRowHeight: CGFloat = 44
    static let dashboardCardHeight: CGFloat = 224
    static let radius: CGFloat = 14
    static let smallRadius: CGFloat = 10
    static let spring = Animation.spring(response: 0.32, dampingFraction: 0.82)
    /// Entrance: cards rise into place one after another.
    static let entrance = Animation.spring(response: 0.5, dampingFraction: 0.86)

    /// Deep jade from the app icon; dark enough for white text on primary buttons.
    static let accent = Color(nsColor: NSColor(name: nil) { a in
        a.bestMatch(from: [.darkAqua]) == .darkAqua
            ? NSColor(red: 0.039, green: 0.514, blue: 0.502, alpha: 1)
            : NSColor(red: 0.031, green: 0.498, blue: 0.514, alpha: 1)
    })
    /// Text inks, darker than the system secondary/tertiary so supporting text stays legible.
    /// ink2 is helper text; ink3 is the faintest text allowed (placeholders, hints).
    static let ink2 = Color(nsColor: NSColor(name: nil) { a in
        a.bestMatch(from: [.darkAqua]) == .darkAqua
            ? NSColor(red: 0.81, green: 0.82, blue: 0.85, alpha: 1)
            : NSColor(red: 0.28, green: 0.30, blue: 0.34, alpha: 1)
    })
    static let ink3 = Color(nsColor: NSColor(name: nil) { a in
        a.bestMatch(from: [.darkAqua]) == .darkAqua
            ? NSColor(red: 0.69, green: 0.71, blue: 0.75, alpha: 1)
            : NSColor(red: 0.38, green: 0.40, blue: 0.44, alpha: 1)
    })
    /// Border of secondary buttons and fields: visible enough to read as clickable.
    static let stroke = Color.primary.opacity(0.16)

    /// State colour grammar. Blue (accent) is action, selection, current page;
    /// green is confirmed working; orange is attention or an inconsistent state;
    /// red is failure; grey is off, unconfigured or no data. Nothing else carries colour.
    static let ok = Color(nsColor: NSColor(name: nil) { a in
        a.bestMatch(from: [.darkAqua]) == .darkAqua
            ? NSColor(red: 0.43, green: 0.82, blue: 0.60, alpha: 1)
            : NSColor(red: 0.13, green: 0.42, blue: 0.28, alpha: 1)
    })
    static let warn = Color(nsColor: NSColor(name: nil) { a in
        a.bestMatch(from: [.darkAqua]) == .darkAqua
            ? NSColor(red: 1.0, green: 0.72, blue: 0.34, alpha: 1)
            : NSColor(red: 0.59, green: 0.32, blue: 0.07, alpha: 1)
    })
    static let fail = Color(nsColor: NSColor(name: nil) { a in
        a.bestMatch(from: [.darkAqua]) == .darkAqua
            ? NSColor(red: 1.0, green: 0.48, blue: 0.49, alpha: 1)
            : NSColor(red: 0.72, green: 0.17, blue: 0.20, alpha: 1)
    })
    static let off = ink2

    /// Content never stretches past this width on wide windows.
    static let maxContentWidth: CGFloat = 1180

    static let page = Color(nsColor: NSColor(name: nil) { a in
        a.bestMatch(from: [.darkAqua]) == .darkAqua
            ? NSColor(red: 0.105, green: 0.105, blue: 0.115, alpha: 1)
            : NSColor(red: 0.962, green: 0.965, blue: 0.972, alpha: 1)
    })
    static let surface = Color(nsColor: NSColor(name: nil) { a in
        a.bestMatch(from: [.darkAqua]) == .darkAqua
            ? NSColor(red: 0.16, green: 0.16, blue: 0.175, alpha: 1)
            : .white
    })

    /// Type scale: one face (SF Pro) at a few fixed steps; rounded only for figures.
    static let title = Font.system(size: 24, weight: .semibold)
    static let display = Font.system(size: 22, weight: .medium)
    static let heading = Font.system(size: 14, weight: .semibold)
    static let navigation = Font.system(size: 14)
    static let label = Font.system(size: 13)
    static let small = Font.system(size: 12)
    static let caption = Font.system(size: 11, weight: .medium)
    static let code = Font.system(size: 12, design: .monospaced)
    static func figure(_ size: CGFloat) -> Font { .system(size: size, weight: .medium).monospacedDigit() }
}

/// Solid page colour: a quiet off-white in light mode, deep graphite in dark mode.
struct Backdrop: View {
    var body: some View { DS.page.ignoresSafeArea() }
}

/// A search field shaped like the other glass controls.
struct SearchField: View {
    @FocusState private var focused: Bool
    let prompt: String
    @Binding var text: String
    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass").foregroundStyle(DS.ink2)
            ZStack(alignment: .leading) {
                if text.isEmpty { Text(prompt).foregroundStyle(DS.ink3).allowsHitTesting(false) }
                TextField("", text: $text).textFieldStyle(.plain)
                    .focused($focused).accessibilityLabel(prompt)
                    .onExitCommand { text = ""; focused = false }
            }
            if !text.isEmpty {
                Button { text = "" } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(DS.ink3) }
                    .buttonStyle(.plain).accessibilityLabel("清除搜索")
            }
        }
        .background {
            Button("") { focused = true }.keyboardShortcut("f").hidden().accessibilityHidden(true)
        }
        .font(DS.label)
        .padding(.horizontal, 12).padding(.vertical, 6)
        .frame(width: 220)
        .liquidGlass(in: Capsule())
        // While it filters, a blue ring says the list is narrowed.
        .overlay(Capsule().strokeBorder(text.isEmpty ? Color.clear : DS.accent.opacity(0.7), lineWidth: 1.5))
        .animation(DS.spring, value: text.isEmpty)
    }
}

/// Segmented control: a Liquid Glass track whose selected segment is a tinted glass
/// thumb that slides between options.
struct GlassSegmented<T: Hashable>: View {
    let options: [(T, String, String?)]
    @Binding var selection: T
    @Namespace private var ns
    var body: some View {
        HStack(spacing: 2) {
            ForEach(options, id: \.0) { value, title, icon in
                let on = value == selection
                Button { withAnimation(DS.spring) { selection = value } } label: {
                    HStack(spacing: 5) {
                        if let icon { Image(systemName: icon).font(.system(size: 12, weight: .semibold)) }
                        Text(title)
                    }
                    .font(DS.label.weight(on ? .medium : .regular))
                    .foregroundStyle(on ? Color.primary : DS.ink2)
                    .frame(maxWidth: .infinity).padding(.vertical, 7)
                    .background {
                        if on {
                            Capsule().fill(DS.surface)
                                .shadow(color: .black.opacity(0.05), radius: 2, y: 1)
                                .matchedGeometryEffect(id: "thumb", in: ns)
                        }
                    }
                    .overlay(alignment: .bottom) {
                        if on { FlowMark(vertical: false).padding(.bottom, 2).matchedGeometryEffect(id: "mark", in: ns) }
                    }
                    .contentShape(Capsule())
                }
                .buttonStyle(PressableStyle())
            }
        }
        .padding(3)
        .liquidGlass(in: Capsule())
    }
}

extension View {
    /// Header above the pane's content; content scrolls under nothing, so headers stay crisp on glass.
    func paneHeader<H: View>(@ViewBuilder _ header: () -> H) -> some View {
        VStack(spacing: 0) { header(); self }
    }

    /// Content surface: a crisp card on the page colour, with a hairline and a soft shadow.
    func glass(radius: CGFloat = DS.radius, highlighted: Bool = false) -> some View {
        background(DS.surface, in: RoundedRectangle(cornerRadius: radius, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: radius, style: .continuous)
                .strokeBorder(highlighted ? DS.accent.opacity(0.8) : Color.primary.opacity(0.08),
                              lineWidth: highlighted ? 1.5 : 0.5))
            .shadow(color: .black.opacity(0.025), radius: 3, y: 1)
    }

    /// Liquid Glass for the control layer (macOS 26+), frosted material before that.
    @ViewBuilder
    func liquidGlass<S: Shape>(in shape: S, interactive: Bool = false) -> some View {
        if #available(macOS 26, *) {
            glassEffect(interactive ? .regular.interactive() : .regular, in: shape)
        } else {
            background(.regularMaterial, in: shape)
        }
    }

    /// Glass push button; `prominent` tints it with the accent colour.
    @ViewBuilder
    func glassButton(prominent: Bool = false) -> some View {
        if #available(macOS 26, *) {
            if prominent { buttonStyle(PrimaryCapsuleStyle()) } else { buttonStyle(SecondaryCapsuleStyle()) }
        } else {
            if prominent { buttonStyle(PrimaryCapsuleStyle()) } else { buttonStyle(SecondaryCapsuleStyle()) }
        }
    }

    /// A glass container for tables, lists and editors, inset by the gutter.
    func glassPanel() -> some View {
        scrollContentBackground(.hidden)
            .clipShape(RoundedRectangle(cornerRadius: DS.radius, style: .continuous))
            .glass()
            .entrance(0)
            .padding(.horizontal, DS.gutter).padding(.bottom, DS.gutter)
    }
}

/// The signature of the design language: a short accent capsule, the "flow mark",
/// marks whatever is active (selected sidebar item, selected segment).
struct FlowMark: View {
    var vertical = true
    var body: some View {
        Capsule().fill(DS.accent.gradient)
            .frame(width: vertical ? 3 : 16, height: vertical ? 14 : 3)
    }
}

/// A 26pt round icon button: accent when it starts something, quiet grey otherwise.
struct RoundIconStyle: ButtonStyle {
    var prominent = false
    @State private var hovering = false
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 12, weight: .medium))
            .foregroundStyle(prominent ? Color.white : DS.ink2)
            .frame(width: 30, height: 30)
            .background(prominent ? AnyShapeStyle(DS.accent.gradient) : AnyShapeStyle(Color.primary.opacity(hovering ? 0.13 : 0.08)), in: Circle())
            .scaleEffect(configuration.isPressed ? 0.9 : hovering ? 1.06 : 1)
            .animation(DS.spring, value: configuration.isPressed)
            .animation(DS.spring, value: hovering)
            .onHover { hovering = $0 }
    }
}

/// Every plain, tappable surface (rows, tiles, segments) sinks slightly while pressed.
struct PressableStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.97 : 1)
            .opacity(configuration.isPressed ? 0.85 : 1)
            .animation(DS.spring, value: configuration.isPressed)
    }
}

/// The one filled button: a soft accent capsule with white text.
struct PrimaryCapsuleStyle: ButtonStyle {
    /// The page's main action (start/stop on the home page) is one size up.
    var large = false
    @Environment(\.isEnabled) private var enabled
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(large ? DS.label.weight(.semibold) : DS.small.weight(.medium))
            .lineLimit(1).fixedSize()
            .foregroundStyle(.white)
            .padding(.horizontal, large ? 18 : 12).padding(.vertical, 4)
            .frame(minHeight: large ? 36 : 28)
            .background(DS.accent.opacity(enabled ? 1 : 0.4), in: Capsule())
            .opacity(configuration.isPressed ? 0.8 : 1)
            .scaleEffect(configuration.isPressed ? 0.97 : 1)
            .animation(DS.spring, value: configuration.isPressed)
    }
}

/// The secondary button: surface fill, a visible border and full-strength text, so it
/// reads as clickable next to helper text. Disabled is clearly faded (say why in `.help`).
struct SecondaryCapsuleStyle: ButtonStyle {
    var large = false
    @Environment(\.isEnabled) private var enabled
    @State private var hovering = false
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(large ? DS.label.weight(.semibold) : DS.small.weight(.medium))
            .lineLimit(1).fixedSize()
            .foregroundStyle(Color.primary)
            .padding(.horizontal, large ? 18 : 12).padding(.vertical, 4)
            .frame(minHeight: large ? 36 : 28)
            .background(hovering && enabled ? Color.primary.opacity(0.06) : DS.surface.opacity(0.9), in: Capsule())
            .overlay(Capsule().strokeBorder(DS.stroke, lineWidth: 1))
            .opacity(enabled ? (configuration.isPressed ? 0.75 : 1) : 0.55)
            .scaleEffect(configuration.isPressed ? 0.97 : 1)
            .animation(DS.spring, value: configuration.isPressed)
            .onHover { hovering = $0 }
    }
}

/// Big pane title with optional trailing controls, as at the top of every Surge pane.
struct PaneHeader<Trailing: View>: View {
    let title: String
    var subtitle: String?
    @ViewBuilder var trailing: Trailing
    var body: some View {
        ViewThatFits(in: .horizontal) {
            HStack(alignment: .center, spacing: 16) {
                heading
                Spacer(minLength: 12)
                HStack(spacing: 8) { trailing }.glassButton().fixedSize()
            }
            VStack(alignment: .leading, spacing: 12) {
                heading
                HStack(spacing: 8) { trailing }.glassButton()
            }
        }
        .padding(.horizontal, DS.gutter).padding(.top, 18).padding(.bottom, 22)
    }

    private var heading: some View {
        VStack(alignment: .leading, spacing: 2) {
                Text(title).font(DS.title).tracking(-0.3)
                if let subtitle, !subtitle.isEmpty {
                    Text(subtitle).font(DS.small).foregroundStyle(DS.ink2).lineLimit(1).truncationMode(.middle)
                }
        }
    }
}

extension PaneHeader where Trailing == EmptyView {
    init(title: String, subtitle: String? = nil) { self.init(title: title, subtitle: subtitle) { EmptyView() } }
}

/// Rounded card on the pane background.
struct CardModifier: ViewModifier {
    func body(content: Content) -> some View {
        content
            .padding(DS.cardPadding)
            .frame(maxWidth: .infinity, alignment: .topLeading)
            .glass()
    }
}

extension View {
    func card() -> some View { modifier(CardModifier()) }
}

/// Content rises into place when a pane opens, each piece a beat after the last.
struct Entrance: ViewModifier {
    let index: Int
    @State private var shown = false
    func body(content: Content) -> some View {
        content
            .opacity(shown ? 1 : 0)
            .offset(y: shown ? 0 : 14)
            .scaleEffect(shown ? 1 : 0.985, anchor: .top)
            .blur(radius: shown ? 0 : 4)
            .onAppear { withAnimation(DS.entrance.delay(Double(min(index, 12)) * 0.045)) { shown = true } }
    }
}

extension View {
    func entrance(_ index: Int) -> some View { modifier(Entrance(index: index)) }
}


/// Card caption with a tinted symbol, e.g. "↑ 上传".
struct CardTitle: View {
    let text: String
    let icon: String
    var body: some View {
        Label {
            Text(text).font(DS.label.weight(.medium)).foregroundStyle(DS.ink2)
        } icon: {
            Image(systemName: icon).font(.system(size: 11, weight: .medium)).foregroundStyle(DS.ink3)
        }
        .labelStyle(BadgeLabelStyle())
    }
}

struct BadgeLabelStyle: LabelStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 7) { configuration.icon; configuration.title }
    }
}

/// Section heading in the System Settings manner: small, secondary, above a group of cards.
struct SectionTitle: View {
    let text: String
    var color: Color = .secondary
    var body: some View {
        Text(text).font(DS.label.weight(.semibold)).foregroundStyle(DS.ink2)
            .padding(.top, 8).padding(.bottom, 2).padding(.leading, 1)
    }
}

struct BigNumber: View {
    let value: String
    var unit: String = ""
    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 3) {
            Text(value).font(DS.figure(28))
                .fixedSize()
                .contentTransition(.numericText())
            if !unit.isEmpty {
                Text(unit).font(DS.label).foregroundStyle(DS.ink2).fixedSize()
                    .contentTransition(.opacity)
            }
        }
        // Animate the row, not just the digits, so the unit slides as the number widens.
        .animation(.smooth(duration: 0.4), value: value)
        .animation(.smooth(duration: 0.4), value: unit)
    }
}

/// "12.3 KB/s" split into number and unit for big displays.
func splitRate(_ bytes: Double) -> (String, String) {
    let s = formatBytes(bytes)
    let parts = s.split(separator: " ")
    return (String(parts.first ?? ""), parts.count > 1 ? "\(parts[1])/s" : "B/s")
}

func splitBytes(_ bytes: Double) -> (String, String) {
    let parts = formatBytes(bytes).split(separator: " ")
    return (String(parts.first ?? ""), parts.count > 1 ? String(parts[1]) : "B")
}

// MARK: activity

extension String {
    func ifEmpty(_ fallback: String) -> String { isEmpty ? fallback : self }
}

// MARK: overview

struct OverviewView: View {
    @EnvironmentObject var core: Core
    @State private var enhancedBusy = false

    private let columns = [GridItem(.flexible(), spacing: DS.gap), GridItem(.flexible(), spacing: DS.gap)]

    var body: some View {
        ScrollViewReader { scroll in
            ScrollView {
                VStack(alignment: .leading, spacing: DS.gap) {
                    SectionTitle(text: "网络接管")
                    LazyVGrid(columns: columns, spacing: DS.gap) {
                        FeatureCard(icon: "network", title: "系统代理",
                                    detail: "接管遵循系统代理设置的应用，适合日常使用。",
                                    isOn: Binding(get: { core.systemProxyOn }, set: { core.setSystemProxy($0) }),
                                    status: core.systemProxyOn
                                        ? (core.state == .running ? "系统代理正在接管" : "已开启，内核未运行")
                                        : "未设置为系统代理",
                                    statusOn: core.systemProxyOn && core.state == .running,
                                    statusTone: core.systemProxyOn && core.state != .running ? DS.warn : nil)
                            .disabled(core.summary.httpListen == nil && core.summary.socksListen == nil)
                        FeatureCard(icon: "server.rack", title: "HTTP & SOCKS5 代理",
                                    detail: "为其他应用提供本机 HTTP 和 SOCKS5 代理。",
                                    status: [core.summary.httpListen.map { "HTTP \($0)" }, core.summary.socksListen.map { "SOCKS5 \($0)" }]
                                        .compactMap { $0 }.joined(separator: "  ").ifEmpty("已禁用"),
                                    statusOn: core.state == .running && (core.summary.httpListen != nil || core.summary.socksListen != nil))
                    }.entrance(0)
                    SectionTitle(text: "增强模式")
                    LazyVGrid(columns: columns, spacing: DS.gap) {
                        FeatureCard(icon: "shield.lefthalf.filled", title: "增强模式",
                                    detail: "同时接管不遵循系统代理的应用，需要管理员授权。",
                                    isOn: Binding(get: { core.summary.enhancedMode }, set: { on in
                                        enhancedBusy = true
                                        Task {
                                            if let err = await core.setEnhancedMode(on) { core.lastActionError = "增强模式: \(err)" }
                                            enhancedBusy = false
                                        }
                                    }),
                                    status: core.privileged ? "增强模式已激活" : core.summary.enhancedMode ? "已启用，启动后生效" : "已禁用",
                                    statusOn: core.privileged, contentHeight: 180)
                            .disabled(enhancedBusy)
                        HelperSettingsCard()
                    }.entrance(1)
                    SectionTitle(text: "代理服务")
                    LazyVGrid(columns: columns, spacing: DS.gap) {
                        FeatureCard(icon: "terminal", title: "控制 API",
                                    detail: "用于切换策略、读取流量和测试规则。",
                                    status: core.summary.apiPort.map { "127.0.0.1:\($0)" } ?? "未配置（应用需要它）",
                                    statusOn: core.state == .running && core.summary.apiPort != nil)
                        VStack(alignment: .leading, spacing: 12) {
                            HStack(spacing: 10) {
                                IconTile(symbol: "doc.text", size: 28)
                                Text("当前配置").font(DS.heading)
                            }
                            Text(core.configPath).font(DS.small).foregroundStyle(DS.ink2)
                                .lineLimit(2).truncationMode(.middle).textSelection(.enabled).help(core.configPath)
                            Spacer(minLength: 0)
                            Button("显示文件") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: core.configPath)]) }.glassButton()
                        }
                        .frame(minHeight: 120, alignment: .topLeading).card()
                    }.entrance(2)
                    HStack(spacing: 8) {
                        if let listen = core.summary.httpListen, let (host, port) = SystemProxy.split(listen) {
                            Button { copyText("http://\(host.contains(":") && !host.hasPrefix("[") ? "[\(host)]" : host):\(port)") } label: {
                                Label("复制 HTTP 地址", systemImage: "doc.on.doc")
                            }.glassButton()
                        }
                        if let listen = core.summary.socksListen, let (host, port) = SystemProxy.split(listen) {
                            Button { copyText("socks5://\(host.contains(":") && !host.hasPrefix("[") ? "[\(host)]" : host):\(port)") } label: {
                                Label("复制 SOCKS5 地址", systemImage: "doc.on.doc")
                            }.glassButton()
                        }
                        Spacer()
                    }
                    SectionTitle(text: "通用").id("maintenance")
                    LazyVGrid(columns: columns, spacing: DS.gap) {
                        FeatureCard(icon: "power", title: "打开应用时启动",
                                    detail: "打开 Sluice 时自动启动代理内核。",
                                    isOn: $core.autoStart,
                                    status: core.autoStart ? "已启用" : "已禁用", statusOn: core.autoStart)
                        LoginItemCard()
                    }.entrance(2)
                    UpdateSettingsCard().entrance(3)
                    AppearanceCard().entrance(4)
                    MenuBarSettingsCard().entrance(5)
                    SectionTitle(text: "诊断")
                    DiagnosticsSettingsCard().entrance(6)
                }
                .padding(.horizontal, DS.gutter).padding(.bottom, DS.gutter)
            }
            .paneHeader { PaneHeader(title: Pane.overview.title, subtitle: Pane.overview.subtitle) }
            .task {
                if E2ELaunch.current?.destination == "settings-maintenance" {
                    try? await Task.sleep(for: .seconds(2))
                    scroll.scrollTo("maintenance", anchor: .top)
                }
            }
        }
    }
}

struct FeatureCard: View {
    var icon: String = "circle"
    let title: String
    let detail: String
    var isOn: Binding<Bool>?
    let status: String
    let statusOn: Bool
    var statusTone: Color? = nil
    var contentHeight: CGFloat = 120

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                IconTile(symbol: icon, size: 28)
                Text(title).font(DS.heading)
                Spacer()
                if let isOn { Toggle(title, isOn: isOn).toggleStyle(.switch).labelsHidden().controlSize(.small).tint(DS.accent) }
            }
            Text(detail).font(DS.small).foregroundStyle(DS.ink2).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 8)
            StatusBadge(text: status, tone: statusTone ?? (statusOn ? DS.ok : .secondary))
        }
        .frame(height: contentHeight, alignment: .topLeading)
        .card()
    }
}

struct AppearanceCard: View {
    @AppStorage("appearance") private var appearance = Appearance.system
    var body: some View {
        HStack(spacing: 10) {
            IconTile(symbol: appearance.icon, size: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text("外观").font(DS.heading)
                Text("Sluice 窗口使用的颜色模式").font(DS.small).foregroundStyle(DS.ink2)
            }
            Spacer(minLength: 16)
            GlassSegmented(options: Appearance.allCases.map { ($0, $0.title, $0.icon) }, selection: $appearance)
                .frame(width: 320)
        }
        .card()
    }
}

struct MenuBarSettingsCard: View {
    @AppStorage("menuBarDisplayMode") private var displayMode = MenuBarDisplayMode.iconAndSpeed
    @AppStorage("menuBarShowOutboundMode") private var showOutboundMode = true
    @AppStorage("menuBarDimWhenNotProxying") private var dimWhenNotProxying = true

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 10) {
                IconTile(symbol: "menubar.rectangle", size: 28)
                VStack(alignment: .leading, spacing: 2) {
                    Text("菜单栏").font(DS.heading)
                    Text("选择顶部状态栏显示的内容").font(DS.small).foregroundStyle(DS.ink2)
                }
                Spacer(minLength: 16)
                Picker("菜单栏显示", selection: $displayMode) {
                    ForEach(MenuBarDisplayMode.allCases) { option in
                        Text(option.title).tag(option)
                    }
                }
                .labelsHidden()
                .frame(width: 200)
            }
            Divider()
            Toggle("显示当前的出站模式", isOn: $showOutboundMode)
            Toggle("未启用系统代理和增强模式时，将图标显示为灰色", isOn: $dimWhenNotProxying)
                .disabled(!displayMode.showsIcon)
        }
        .font(DS.label)
        .toggleStyle(.checkbox)
        .tint(DS.accent)
        .card()
    }
}

/// "Open at login" via SMAppService; only works for the bundled app (dist/Sluice.app).
struct LoginItemCard: View {
    @State private var enabled = SMAppService.mainApp.status == .enabled
    @State private var error: String?
    var body: some View {
        FeatureCard(icon: "person.crop.circle", title: "登录时打开",
                    detail: SMAppService.mainApp.status == .requiresApproval
                        ? "请在 系统设置 › 通用 › 登录项 中允许 Sluice。" : "登录 macOS 时自动打开 Sluice。",
                    isOn: Binding(get: { enabled }, set: set),
                    status: error ?? (enabled ? "已启用" : "已禁用"), statusOn: enabled,
                    statusTone: error == nil ? nil : DS.fail)
    }
    private func set(_ on: Bool) {
        do {
            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
        enabled = SMAppService.mainApp.status == .enabled
    }
}

// MARK: policy

struct PolicyView: View {
    @EnvironmentObject var core: Core
    @State private var filter = ""

    var body: some View {
        let mode = OutboundMode(rawValue: core.mode) ?? .rule
        let groups = core.groups.filter { group in
            filter.isEmpty || group.group.localizedCaseInsensitiveContains(filter)
                || group.options.contains { $0.name.localizedCaseInsensitiveContains(filter) }
        }
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                GlassSegmented(options: OutboundMode.allCases.map { ($0, $0.title, $0.icon) },
                               selection: Binding(get: { mode }, set: { core.setMode($0.rawValue) }))
                .disabled(core.state != .running)
                Text(mode.explanation).font(DS.small).foregroundStyle(DS.ink2)

                HStack {
                    SectionTitle(text: "策略组")
                    Spacer()
                    TestAllLatencyButton().controlSize(.small)
                }
                if core.groups.isEmpty {
                    EmptyState(icon: "signpost.right",
                               title: core.state == .running ? "没有策略组" : "Sluice 未运行",
                               detail: core.state == .running ? "在配置的 [Proxy Group] 中添加策略组。" : "启动 Sluice 后可以查看和切换策略组。",
                               action: core.isActive ? nil : ("启动 Sluice", { core.start() }) as (String, () -> Void)?)
                        .frame(minHeight: 260)
                } else if groups.isEmpty {
                    EmptyState(icon: "magnifyingglass", title: "没有匹配的策略", detail: "按策略组名称或节点名称搜索。", action: ("清除搜索", { filter = "" }))
                } else {
                    ForEach(Array(groups.enumerated()), id: \.element.id) { i, g in GroupSection(group: g, filter: filter).entrance(i) }
                }
            }
            .padding(.horizontal, DS.gutter).padding(.bottom, DS.gutter)
        }
        .paneHeader {
            PaneHeader(title: "策略", subtitle: Pane.policy.subtitle) {
                SearchField(prompt: "搜索策略组或节点", text: $filter)
            }
        }
    }
}

/// A policy group with every option laid out, so the current choice, latency and
/// availability compare at a glance. Manual groups switch by clicking an option.
struct GroupSection: View {
    @EnvironmentObject var core: Core
    let group: PolicyGroup
    var filter = ""

    static func kindLabel(_ type: String) -> String {
        switch type {
        case "select": "手动选择"
        case "url-test": "自动测试"
        case "fallback": "故障转移"
        case "load-balance": "负载均衡"
        default: type
        }
    }

    private var kindIcon: String {
        switch group.type {
        case "select": "hand.tap"
        case "url-test": "bolt"
        case "fallback": "arrow.uturn.down"
        case "load-balance": "scale.3d"
        default: "square.stack"
        }
    }

    var body: some View {
        let failed = group.options.filter { ($0.latencyMs ?? 0) < 0 }.count
        let tested = group.options.filter { $0.latencyMs != nil }.count
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 10) {
                IconTile(symbol: kindIcon, size: 28)
                VStack(alignment: .leading, spacing: 4) {
                    Text(group.group).font(DS.heading).lineLimit(1)
                    Text(group.isSelectable ? "\(Self.kindLabel(group.type)) · 点击选项切换" : "\(Self.kindLabel(group.type)) · 自动 · 当前：\(group.selected)")
                        .font(DS.caption).foregroundStyle(DS.ink2)
                }
                Spacer(minLength: 8)
                if tested > 0 {
                    Text(failed == 0 ? "\(tested) 个可用" : "\(tested - failed) 个可用 · \(failed) 个失败")
                        .font(DS.caption).foregroundStyle(failed == 0 ? DS.ink2 : failed == tested ? DS.fail : DS.warn)
                }
                if core.testingGroups.contains(group.group) { ProgressView().controlSize(.small).accessibilityLabel("正在测试") }
                Button(core.testingGroups.contains(group.group) ? "测试中…" : "测试") { core.test(group: group.group) }.glassButton()
                    .disabled(core.state != .running || core.testingGroups.contains(group.group))
                    .help("测试这个策略组里每个选项的延迟")
            }
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 200), spacing: 10)], spacing: 10) {
                ForEach(group.options.filter { filter.isEmpty || group.group.localizedCaseInsensitiveContains(filter) || $0.name.localizedCaseInsensitiveContains(filter) }, id: \.name) { OptionChip(group: group, option: $0) }
            }
        }
        .padding(DS.cardPadding)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glass()
    }
}

/// A node's latency and current selection; automatic groups remain read-only.
struct OptionChip: View {
    @EnvironmentObject var core: Core
    let group: PolicyGroup
    let option: GroupOption
    @State private var hovering = false

    var body: some View {
        optionContent.contextMenu {
            Button(core.testingNodes.contains(option.name) ? "测试中…" : "测试节点") { core.test(node: option.name) }
                .disabled(core.state != .running || core.testingNodes.contains(option.name))
        }
    }

    @ViewBuilder private var optionContent: some View {
        if group.isSelectable {
            Button {
                if group.selected != option.name { core.select(group: group.group, option: option.name) }
            } label: { content }
            .buttonStyle(PressableStyle())
            .disabled(core.state != .running)
            .help(group.selected == option.name ? "当前选择" : "切换到 \(option.name)")
        } else {
            content
                .help("自动选择 · 当前：\(group.selected)")
        }
    }

    private var content: some View {
        let chosen = group.selected == option.name
        return HStack(spacing: 8) {
            if chosen { Image(systemName: "checkmark").font(DS.caption).foregroundStyle(DS.accent) }
            Text(option.name).font(DS.label.weight(chosen ? .semibold : .regular)).lineLimit(1).truncationMode(.middle)
            Spacer(minLength: 4)
            LatencyBadge(latency: option.latencyMs)
        }
        .padding(.horizontal, 12).frame(height: 40)
        .background(chosen ? DS.accent.opacity(0.08) : hovering && group.isSelectable ? Color.primary.opacity(0.06) : Color.primary.opacity(0.035),
                    in: RoundedRectangle(cornerRadius: DS.smallRadius, style: .continuous))
        .overlay {
            if chosen {
                RoundedRectangle(cornerRadius: DS.smallRadius, style: .continuous).strokeBorder(DS.accent.opacity(0.35), lineWidth: 1)
            }
        }
        .contentShape(Rectangle())
        .onHover { hovering = $0 }
        .animation(DS.spring, value: chosen)
    }
}

// MARK: nodes

/// Header shared by every sheet: an accent tile, a title and one line on what to do.
struct SheetHeader: View {
    let icon: String
    let title: String
    let detail: String
    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            IconTile(symbol: icon, on: true, size: 36)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.system(size: 18, weight: .semibold))
                Text(detail).font(DS.small).foregroundStyle(DS.ink2).fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

/// A labelled input on a soft well, used inside sheets.
struct SheetField: View {
    let label: String
    let prompt: String
    @Binding var text: String
    var multiline = false
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label).font(DS.caption).foregroundStyle(DS.ink2)
            Group {
                if multiline {
                    ZStack(alignment: .topLeading) {
                        if text.isEmpty { Text(prompt).foregroundStyle(DS.ink3).allowsHitTesting(false) }
                        TextField("", text: $text, axis: .vertical).lineLimit(4...8)
                            .font(.system(size: 12.5, design: .monospaced))
                    }
                } else {
                    ZStack(alignment: .leading) {
                        if text.isEmpty { Text(prompt).foregroundStyle(DS.ink3).allowsHitTesting(false) }
                        TextField("", text: $text)
                    }
                }
            }
            .textFieldStyle(.plain)
            .font(DS.label)
            .padding(.horizontal, 12).padding(.vertical, 9)
            .background(Color.primary.opacity(0.045), in: RoundedRectangle(cornerRadius: DS.smallRadius, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: DS.smallRadius, style: .continuous).strokeBorder(Color.primary.opacity(0.08), lineWidth: 0.5))
        }
    }
}

/// Sheet footer: an error line if any, then cancel and the primary action.
struct SheetFooter: View {
    let error: String?
    var example: String?
    let primary: String
    let enabled: Bool
    let cancel: () -> Void
    let action: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let error { ErrorText(raw: error, example: example) }
            HStack(spacing: 8) {
                Spacer()
                Button("取消", action: cancel).keyboardShortcut(.cancelAction).glassButton()
                Button(primary, action: action).disabled(!enabled).glassButton(prominent: true)
            }
        }
    }
}

struct AddNodeSheet: View {
    @EnvironmentObject var core: Core
    @Environment(\.dismiss) private var dismiss
    @State private var input = ""
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            SheetHeader(icon: "server.rack", title: "添加节点",
                        detail: "粘贴分享链接（ss、vmess、vless、trojan、hysteria2），或一行 Surge 风格的代理配置。")
            SheetField(label: "分享链接或代理行", prompt: "例如 HK = ss, hk.example.com, 8388, encrypt-method=aes-256-gcm, password=…",
                       text: $input, multiline: true)
            SheetFooter(error: error, example: "HK = ss, hk.example.com, 8388, encrypt-method=aes-256-gcm, password=你的密码",
                        primary: busy ? "检查中…" : "添加", enabled: !busy && !input.isEmpty, cancel: { dismiss() }) {
                busy = true
                Task {
                    error = await core.addNode(input)
                    busy = false
                    if error == nil { dismiss() }
                }
            }
        }
        .padding(28).frame(width: 540)
    }
}

struct AddSubscriptionSheet: View {
    @EnvironmentObject var core: Core
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var url = ""
    @State private var filter = ""
    @State private var userAgent = ""
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            SheetHeader(icon: "link", title: "添加订阅", detail: "保存配置前会先下载订阅并检查其中的节点。")
            SheetField(label: "订阅地址", prompt: "https://…", text: $url)
            HStack(spacing: 12) {
                SheetField(label: "名称", prompt: "Subscription", text: $name)
                SheetField(label: "名称过滤（正则，可选）", prompt: "例如 香港|HK", text: $filter)
            }
            SheetField(label: "User-Agent（可选）", prompt: "留空使用默认值", text: $userAgent)
            SheetFooter(error: error, primary: busy ? "下载中…" : "添加", enabled: !busy && !url.isEmpty, cancel: { dismiss() }) {
                busy = true
                Task {
                    error = await core.addSubscription(name: name, url: url, filter: filter, userAgent: userAgent)
                    busy = false
                    if error == nil { dismiss() }
                }
            }
        }
        .padding(28).frame(width: 540)
    }
}

// MARK: requests

struct RequestsView: View {
    @EnvironmentObject var core: Core
    @State private var filter = ""
    @State private var kind = OutboundKind.all
    @State private var selection: Connection.ID?
    @State private var paused = false
    @State private var frozen: [Connection] = []
    @State private var activity = E2ELaunch.current?.destination == "requests-active"

    /// Which outbounds to show.
    enum OutboundKind: Hashable { case all, proxy, direct, reject
        func admits(_ outbound: String) -> Bool {
            switch self {
            case .all: true
            case .proxy: outbound != "DIRECT" && outbound != "REJECT"
            case .direct: outbound == "DIRECT"
            case .reject: outbound == "REJECT"
            }
        }
    }

    var body: some View {
        let source = paused ? frozen : core.connections
        let query = filter.trimmingCharacters(in: .whitespacesAndNewlines)
        let rows = source.reversed().filter {
            kind.admits($0.outbound) && $0.matches(query)
        }
        let showsProcess = source.contains { !($0.process ?? "").isEmpty }
        let filtering = kind != .all || !filter.isEmpty
        VStack(spacing: 0) {
            PaneHeader(title: "请求", subtitle: activity ? "\(core.activeConnections.count) 个活动 TCP 连接" : filtering ? "显示 \(rows.count) / \(source.count) 个请求" : "\(source.count) 个请求") {
                GlassSegmented(options: [(false, "最近", nil), (true, "活动", nil)], selection: $activity)
                    .frame(width: 140)
            }
            if activity {
                ActiveRequestsView()
            } else {
                HStack(spacing: 12) {
                    GlassSegmented(options: [(OutboundKind.all, "全部", nil), (.proxy, "代理", nil), (.direct, "直连", nil), (.reject, "拒绝", nil)],
                                   selection: $kind)
                        .frame(width: 250)
                    SearchField(prompt: "目标、进程、策略或出站", text: $filter)
                    Button {
                        if !paused { frozen = core.connections }
                        paused.toggle()
                    } label: { Label(paused ? "继续更新" : "暂停更新", systemImage: paused ? "play.fill" : "pause") }
                        .labelStyle(.iconOnly).help(paused ? "继续更新请求列表" : "暂停列表更新以查看请求，流量不受影响")
                    Button { core.clearConnections(); frozen = []; selection = nil } label: { Label("清除", systemImage: "trash") }
                        .labelStyle(.iconOnly).disabled(source.isEmpty)
                }
                .glassButton()
                .padding(.horizontal, DS.gutter).padding(.bottom, 12)
                HStack(spacing: DS.gap) {
                    VStack(spacing: 0) {
                        if showsProcess {
                            HStack(spacing: 12) {
                                Text("目标与路由").frame(maxWidth: .infinity, alignment: .leading)
                                Text("进程").frame(width: 100, alignment: .leading)
                            }
                            .font(DS.caption).foregroundStyle(DS.ink2)
                            .padding(.horizontal, 18).padding(.vertical, 12)
                            Divider()
                        }
                        ScrollView {
                            LazyVStack(spacing: 2) {
                                ForEach(Array(rows)) { c in
                                    RequestRow(connection: c, selected: c.id == selection, showsProcess: showsProcess) {
                                        withAnimation(DS.spring) { selection = c.id }
                                    }
                                    .contextMenu {
                                        Button("复制目标") { copyText(c.target) }
                                        Button("复制匹配规则") { copyText(c.rule) }
                                    }
                                }
                            }
                            .padding(6)
                        }
                        .overlay {
                            if rows.isEmpty {
                                if !core.isActive && core.connections.isEmpty {
                                    EmptyState(icon: "arrow.up.arrow.down", title: "Sluice 未运行",
                                               detail: "启动后，经过 Sluice 的连接会实时显示在这里。", action: ("启动 Sluice", { core.start() }))
                                } else {
                                    EmptyState(icon: "arrow.up.arrow.down", title: core.connections.isEmpty ? "还没有请求" : "没有匹配的请求",
                                               detail: filtering ? "试试其他关键词，或清除筛选查看全部请求。" : "经过 Sluice 的连接会实时显示在这里。",
                                               action: filtering ? ("清除筛选", { filter = ""; kind = .all }) : nil)
                                }
                            }
                        }
                    }
                    .frame(minWidth: 260, maxWidth: .infinity, maxHeight: .infinity)
                    .glass().entrance(0)
                    RequestDetail(connection: source.first { $0.id == selection })
                        .frame(width: 240)
                        .frame(maxHeight: .infinity, alignment: .top)
                        .glass().entrance(1)
                }
                .padding(.horizontal, DS.gutter).padding(.bottom, 8)
                HStack {
                    Circle().fill(paused ? DS.warn : core.state == .running ? DS.ok : DS.off).frame(width: 6, height: 6)
                    Text(paused ? "列表已暂停 · 网络流量继续运行" : "仅记录最近 2000 条连接事件")
                    Spacer()
                }.font(DS.caption).foregroundStyle(DS.ink2).padding(.horizontal, DS.gutter).padding(.bottom, 12)
            }
        }
        .onChange(of: rows.map(\.id)) {
            if let selection, !rows.contains(where: { $0.id == selection }) { self.selection = nil }
        }
    }
}

/// Colour-coded outbound name: direct green, reject red, proxies in the accent colour.
struct OutboundTag: View {
    let name: String
    var body: some View {
        let color: Color = name == "REJECT" ? .red : name == "DIRECT" ? .secondary : DS.accent
        StatusBadge(text: name, tone: color)
    }
}

/// One request: a destination icon, host:port, route, outbound and time.
struct RequestRow: View {
    let connection: Connection
    let selected: Bool
    let showsProcess: Bool
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                RequestDestinationIcon(outbound: connection.outbound)
                VStack(alignment: .leading, spacing: 6) {
                    HStack(spacing: 8) {
                        Text(connection.target).font(DS.label.weight(.medium)).lineLimit(1).truncationMode(.middle)
                            .help(connection.target)
                        Spacer(minLength: 4)
                        OutboundTag(name: connection.outbound)
                    }
                    HStack(spacing: 8) {
                        Text("\(connection.proto) · \(connection.rule)")
                            .font(DS.small).foregroundStyle(DS.ink2).lineLimit(1).truncationMode(.middle)
                        Spacer(minLength: 4)
                        Text(connection.time).font(DS.caption.monospacedDigit()).foregroundStyle(DS.ink3).fixedSize()
                    }
                }
                if showsProcess {
                    Text(connection.process ?? "").font(DS.small).foregroundStyle(DS.ink2)
                        .lineLimit(1).truncationMode(.middle)
                        .frame(width: 100, alignment: .leading)
                        .help(connection.process ?? "")
                }
            }
            .padding(.horizontal, 12).padding(.vertical, 12)
            .background {
                RoundedRectangle(cornerRadius: DS.smallRadius, style: .continuous)
                    .fill(selected ? DS.accent.opacity(0.08) : hovering ? Color.primary.opacity(0.035) : .clear)
            }
            .overlay {
                if selected {
                    RoundedRectangle(cornerRadius: DS.smallRadius, style: .continuous).strokeBorder(DS.accent.opacity(0.3), lineWidth: 1)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(PressableStyle())
        .onHover { hovering = $0 }
    }
}

/// A network destination; colour follows the outbound, without IP-derived initials.
struct RequestDestinationIcon: View {
    var outbound = "DIRECT"
    var body: some View {
        let tone: Color? = outbound == "REJECT" ? .red : outbound == "DIRECT" ? nil : DS.accent
        Image(systemName: "network")
            .font(.system(size: 14, weight: .medium))
            .foregroundStyle(tone ?? DS.ink2)
            .frame(width: 28, height: 28)
            .background((tone ?? .primary).opacity(tone == nil ? 0.07 : 0.12), in: RoundedRectangle(cornerRadius: 8.4, style: .continuous))
            .accessibilityLabel("网络目标")
    }
}

/// An inline call-out: what is wrong or missing, why it matters, and the fix.
struct Notice<Actions: View>: View {
    let tone: Color
    let icon: String
    let title: String
    let detail: String
    @ViewBuilder var actions: Actions
    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            Image(systemName: icon).font(.system(size: 20, weight: .regular)).foregroundStyle(tone).frame(width: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(DS.heading)
                Text(detail).font(DS.small).foregroundStyle(DS.ink2).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 12)
            HStack(spacing: 8) { actions }
        }
        .padding(16)
        .background(tone.opacity(0.05), in: RoundedRectangle(cornerRadius: DS.smallRadius + 2, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: DS.smallRadius + 2, style: .continuous).strokeBorder(tone.opacity(0.16), lineWidth: 0.5))
        .transition(.opacity.combined(with: .move(edge: .top)))
    }
}

/// A failure told the way people need it: the first line says what went wrong in plain
/// Chinese; any lines after it are the core's own message, folded under 详细信息.
/// Format errors also show a correct example to copy.
struct ErrorText: View {
    let raw: String
    var example: String?
    @State private var open = false
    var body: some View {
        let parts = raw.split(separator: "\n", maxSplits: 1).map(String.init)
        VStack(alignment: .leading, spacing: 6) {
            Label(parts.first ?? raw, systemImage: "exclamationmark.triangle.fill")
                .font(DS.small.weight(.medium)).foregroundStyle(DS.fail)
                .fixedSize(horizontal: false, vertical: true)
            if let example, raw.contains("格式不正确") {
                HStack(spacing: 8) {
                    Text(example).font(DS.code).textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 4)
                    Button {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(example, forType: .string)
                    } label: { Image(systemName: "doc.on.doc") }
                        .buttonStyle(RoundIconStyle()).help("复制示例").accessibilityLabel("复制示例")
                }
                .padding(.horizontal, 10).padding(.vertical, 6)
                .background(Color.primary.opacity(0.045), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            }
            if parts.count > 1 {
                DisclosureGroup("详细信息", isExpanded: $open) {
                    Text(parts[1]).font(DS.code).foregroundStyle(DS.ink2)
                        .textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                }
                .font(DS.caption).foregroundStyle(DS.ink2)
            }
        }
    }
}

/// The one empty-state component: an illustration, what is missing and why, one primary
/// action (and at most one secondary). Used by every empty pane and list.
struct EmptyState: View {
    let icon: String
    let title: String
    var detail: String = ""
    /// Optional next step, e.g. ("启动 Sluice", core.start).
    var action: (String, () -> Void)?
    var secondary: (String, () -> Void)?
    var body: some View {
        VStack(spacing: 8) {
            ZStack {
                Circle().fill(Color.primary.opacity(0.04)).frame(width: 56, height: 56)
                Image(systemName: icon).font(.system(size: 22, weight: .regular)).foregroundStyle(DS.ink3)
            }
            .padding(.bottom, 6)
            .accessibilityHidden(true)
            Text(title).font(DS.heading).foregroundStyle(Color.primary)
            if !detail.isEmpty {
                Text(detail).font(DS.small).foregroundStyle(DS.ink2).multilineTextAlignment(.center)
                    .frame(maxWidth: 360).fixedSize(horizontal: false, vertical: true)
            }
            if action != nil || secondary != nil {
                HStack(spacing: 8) {
                    if let action { Button(action.0, action: action.1).glassButton(prominent: true) }
                    if let secondary { Button(secondary.0, action: secondary.1).glassButton() }
                }
                .padding(.top, 8)
            }
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct RequestDetail: View {
    let connection: Connection?
    var body: some View {
        if let c = connection {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    HStack(spacing: 12) {
                        RequestDestinationIcon(outbound: c.outbound)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(c.target).font(DS.heading).lineLimit(2).textSelection(.enabled)
                            Text(c.proto).font(DS.caption).foregroundStyle(DS.ink2)
                        }
                    }
                    detailGroup("路由", [("规则", AnyView(Text(c.rule).textSelection(.enabled))),
                                         ("策略链", AnyView(Text(c.policyChain).textSelection(.enabled))),
                                         ("出站", AnyView(OutboundTag(name: c.outbound)))])
                    detailGroup("请求", [("时间", AnyView(Text(c.time).monospacedDigit())),
                                         ("进程", AnyView(Text(c.process ?? "—").textSelection(.enabled))),
                                         ("来源", AnyView(Text(c.src ?? "—").textSelection(.enabled))),
                                         ("目标", AnyView(Text(c.target).textSelection(.enabled)))])
                }
                .padding(20)
            }
            .id(c.id)
            .transition(.opacity)
        } else {
            EmptyState(icon: "sidebar.right", title: "未选择请求", detail: "选择左侧的请求查看详情")
        }
    }

    private func detailGroup(_ title: String, _ rows: [(String, AnyView)]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(DS.caption).foregroundStyle(DS.ink3)
            VStack(spacing: 0) {
                ForEach(Array(rows.enumerated()), id: \.offset) { i, row in
                    HStack(alignment: .firstTextBaseline) {
                        Text(row.0).font(DS.small).foregroundStyle(DS.ink2)
                        Spacer(minLength: 12)
                        row.1.font(DS.small).multilineTextAlignment(.trailing).fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(.vertical, 8)
                    if i < rows.count - 1 { Divider().opacity(0.5) }
                }
            }
            .padding(.horizontal, 12)
            .background(Color.primary.opacity(0.03), in: RoundedRectangle(cornerRadius: DS.smallRadius, style: .continuous))
        }
    }
}

// MARK: rule

struct RuleRow: Identifiable {
    let id: Int
    let type: String
    let value: String
    /// How the core names this rule in route results: "TYPE,value", or just "FINAL".
    var matchKey: String { value.isEmpty ? type.uppercased() : "\(type.uppercased()),\(value)" }
    let policy: String
    let options: String
}

struct RuleView: View {
    @EnvironmentObject var core: Core
    @Binding var pane: Pane?
    @State private var rules: [RuleRow] = []
    @State private var filter = ""
    @State private var target = "www.google.com"
    @State private var result: RouteResult?
    @State private var offline = false
    @State private var error: String?
    @State private var testing = false

    var body: some View {
        let rows = rules.filter {
            filter.isEmpty || $0.value.localizedCaseInsensitiveContains(filter) || $0.policy.localizedCaseInsensitiveContains(filter)
                || $0.type.localizedCaseInsensitiveContains(filter)
        }
        ScrollView {
            VStack(alignment: .leading, spacing: DS.gap) {
                routeTest.entrance(0)
                HStack {
                    SectionTitle(text: filter.isEmpty ? "规则 (\(rules.count))" : "规则 (\(rows.count) / \(rules.count))")
                    Spacer()
                    Text("添加、编辑和排序请在配置中修改").font(DS.caption).foregroundStyle(DS.ink2).padding(.top, 10)
                }
                // The list is only as tall as its rules: a short list stays short.
                VStack(spacing: 0) {
                    if rows.isEmpty {
                        EmptyState(icon: "line.3.horizontal.decrease.circle", title: rules.isEmpty ? "没有规则" : "没有匹配的规则",
                                   detail: rules.isEmpty ? "在配置的 [Rule] 中添加规则。" : "")
                            .frame(height: 180)
                    }
                    ForEach(rows) { rule in
                        ruleRow(rule)
                        if rule.id != rows.last?.id { Divider().padding(.leading, 50).opacity(0.5) }
                    }
                }
                .glass()
                .entrance(1)
            }
            .padding(.horizontal, DS.gutter).padding(.bottom, DS.gutter)
        }
        .paneHeader {
            PaneHeader(title: "规则", subtitle: Pane.rule.subtitle) {
                SearchField(prompt: "搜索规则", text: $filter)
                Button { pane = .profile } label: { Label("在配置中编辑", systemImage: "square.and.pencil") }
            }
        }
        .onAppear(perform: load)
        .onChange(of: core.state) { load(); result = nil; error = nil }
        .onChange(of: target) { result = nil; error = nil; offline = false }
    }

    private func ruleRow(_ rule: RuleRow) -> some View {
        let hit = result.map { $0.rule.caseInsensitiveCompare(rule.matchKey) == .orderedSame } ?? false
        return HStack(spacing: 12) {
            Text("\(rule.id)").font(DS.caption.monospacedDigit()).foregroundStyle(DS.ink3)
                .frame(width: 24, alignment: .trailing)
            Text(rule.type.uppercased()).font(DS.caption.monospaced())
                .foregroundStyle(DS.ink2)
                .padding(.horizontal, 7).padding(.vertical, 3)
                .background(Color.primary.opacity(0.05), in: Capsule())
                .frame(width: 150, alignment: .leading)
            Text(rule.value.ifEmpty("其余所有请求")).font(DS.label.weight(hit ? .semibold : .regular))
                .foregroundStyle(rule.value.isEmpty ? DS.ink2 : Color.primary)
                .lineLimit(1).truncationMode(.middle)
            if !rule.options.isEmpty {
                Text(rule.options).font(DS.caption).foregroundStyle(DS.ink3)
            }
            Spacer(minLength: 8)
            if hit { Text("命中").font(DS.caption).foregroundStyle(DS.accent) }
            OutboundTag(name: rule.policy)
        }
        .padding(.horizontal, 16).padding(.vertical, 11)
        .background(hit ? DS.accent.opacity(0.08) : .clear)
        .overlay(alignment: .leading) { if hit { FlowMark().padding(.leading, 3) } }
        .animation(DS.spring, value: hit)
    }

    /// The rule test as one compact toolbar row; its answer sits on the same line.
    private var routeTest: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "scope").font(.system(size: 12, weight: .semibold)).foregroundStyle(DS.ink2)
                    .accessibilityHidden(true)
                ZStack(alignment: .leading) {
                    if target.isEmpty { Text("测试主机，如 www.google.com").foregroundStyle(DS.ink3).allowsHitTesting(false) }
                    TextField("", text: $target).textFieldStyle(.plain).font(DS.label).onSubmit(check)
                        .accessibilityLabel("测试主机")
                }
                    .padding(.horizontal, 10).padding(.vertical, 5)
                    .background(DS.surface, in: Capsule())
                    .overlay(Capsule().strokeBorder(DS.stroke, lineWidth: 1))
                    .frame(minWidth: 180, maxWidth: .infinity)
                Button(testing ? "测试中…" : "测试", action: check).glassButton(prominent: true).disabled(target.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || testing)
                    .help(target.isEmpty ? "先输入要测试的主机" : "查看目标会匹配哪条规则，不会真正建立连接")
                Spacer(minLength: 8)
                Text(core.state == .running ? "内核判定" : "离线匹配")
                    .font(DS.caption).foregroundStyle(core.state == .running ? DS.ink2 : DS.warn)
                    .help(core.state == .running ? "由运行中的内核判定" : "内核未运行：按配置自上而下离线匹配，策略组的实际选择以运行时为准")
            }
                if let result {
                    HStack(spacing: 6) {
                        Image(systemName: "arrow.right").font(.system(size: 10, weight: .semibold)).foregroundStyle(DS.ink3)
                        Text(result.rule).font(DS.small.weight(.medium)).lineLimit(1).truncationMode(.middle)
                        Text("·").foregroundStyle(DS.ink3)
                        Text(result.policy).font(DS.small).foregroundStyle(DS.ink2).lineLimit(1)
                        OutboundTag(name: result.outbound)
                    }
                    .transition(.opacity)
                }
            if offline {
                Text("离线预览会跳过 GEOIP、规则集和需要 DNS 解析的规则；实际路由以启动后的内核结果为准。")
                    .font(DS.caption).foregroundStyle(DS.warn).fixedSize(horizontal: false, vertical: true)
            }
            if let error, result == nil { ErrorText(raw: error) }
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .glass()
        .animation(DS.spring, value: result?.rule)
    }

    private func load() {
        rules = ConfigText.lines(of: "Rule", in: core.readConfig()).enumerated().map { i, line in
            let parts = line.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            let type = parts.first ?? ""
            if type.uppercased() == "FINAL" {
                return RuleRow(id: i + 1, type: type, value: "", policy: parts.count > 1 ? parts[1] : "", options: parts.dropFirst(2).joined(separator: ","))
            }
            return RuleRow(id: i + 1, type: type, value: parts.count > 1 ? parts[1] : "",
                           policy: parts.count > 2 ? parts[2] : "", options: parts.dropFirst(3).joined(separator: ","))
        }
    }

    private func check() {
        guard !testing else { return }
        let submitted = target.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !submitted.isEmpty else { return }
        result = nil
        error = nil
        if core.state != .running {
            // No core to ask: match against the config the same way, top to bottom.
            load()
            offline = true
            if let hit = RuleMatcher.match(submitted, in: rules) {
                result = RouteResult(target: submitted, rule: hit.matchKey, policy: hit.policy, outbound: hit.policy)
                error = nil
            } else {
                result = nil
                error = "没有规则命中这个目标，且配置里没有 FINAL 规则。"
            }
            return
        }
        offline = false
        testing = true
        Task {
            defer { testing = false }
            do {
                let answer = try await core.route(submitted)
                if target.trimmingCharacters(in: .whitespacesAndNewlines) == submitted { result = answer; error = nil }
            } catch {
                if target.trimmingCharacters(in: .whitespacesAndNewlines) == submitted { result = nil; self.error = "规则测试失败。\n\(error.localizedDescription)" }
            }
        }
    }
}

/// Offline rule matching for the common Surge rule types, used while the core is stopped.
/// Types it can't judge without the core (GEOIP, PROCESS-NAME, …) are skipped.
enum RuleMatcher {
    static func match(_ target: String, in rules: [RuleRow]) -> RuleRow? {
        let host = hostPart(target).lowercased()
        for r in rules {
            let v = r.value.lowercased()
            switch r.type.uppercased() {
            case "DOMAIN": if host == v { return r }
            case "DOMAIN-SUFFIX": if host == v || host.hasSuffix("." + v) { return r }
            case "DOMAIN-KEYWORD": if host.contains(v) { return r }
            case "IP-CIDR": if let ip = ipv4(host), let (net, bits) = cidr(v), bits <= 32, bits == 0 || (ip ^ net) >> (32 - bits) == 0 { return r }
            case "FINAL": return r
            default: continue
            }
        }
        return nil
    }

    private static func hostPart(_ s: String) -> String {
        let t = s.trimmingCharacters(in: .whitespaces)
        if t.hasPrefix("["), let end = t.firstIndex(of: "]") { return String(t[t.index(after: t.startIndex)..<end]) }
        if t.filter({ $0 == ":" }).count == 1, let c = t.lastIndex(of: ":"), Int(t[t.index(after: c)...]) != nil {
            return String(t[..<c]).trimmingCharacters(in: CharacterSet(charactersIn: "."))
        }
        return t.trimmingCharacters(in: CharacterSet(charactersIn: "."))
    }

    private static func ipv4(_ s: String) -> UInt32? {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        let p = parts.compactMap { UInt32($0) }
        guard p.count == 4, p.allSatisfy({ $0 < 256 }) else { return nil }
        return p.reduce(0) { $0 << 8 | $1 }
    }

    private static func cidr(_ s: String) -> (UInt32, UInt32)? {
        let parts = s.split(separator: "/")
        guard parts.count == 2, let ip = ipv4(String(parts[0])), let bits = UInt32(parts[1]) else { return nil }
        return (ip, bits)
    }
}

// MARK: logs

struct LogsView: View {
    @EnvironmentObject var core: Core
    @State private var filter = ""
    @State private var follow = true
    @State private var problemsOnly = false

    var body: some View {
        let problems = core.logs.filter { $0.level == "WARN" || $0.level == "ERROR" }.count
        let lines = core.logs.filter {
            (!problemsOnly || $0.level == "WARN" || $0.level == "ERROR")
                && (filter.isEmpty || $0.message.localizedCaseInsensitiveContains(filter) || $0.level.localizedCaseInsensitiveContains(filter))
        }
        VStack(spacing: 0) {
            PaneHeader(title: "日志", subtitle: problems == 0 ? "内核输出 · 没有警告" : "内核输出 · \(problems) 条警告或错误") {
                GlassSegmented(options: [(false, "全部", nil), (true, "问题", "exclamationmark.triangle")], selection: $problemsOnly)
                    .frame(width: 170)
                SearchField(prompt: "搜索", text: $filter)
                Toggle(isOn: $follow) { Label("跟随最新", systemImage: "arrow.down.to.line") }.toggleStyle(.button)
                    .labelStyle(.iconOnly).help(follow ? "正在跟随最新日志" : "跟随最新日志")
                Button { exportLogs(lines) } label: { Label("导出", systemImage: "square.and.arrow.up") }
                    .labelStyle(.iconOnly).help("导出当前筛选的日志").disabled(lines.isEmpty)
                Button { core.clearLogs() } label: { Label("清除日志", systemImage: "trash") }
                    .labelStyle(.iconOnly).help("清除日志")
            }
            ScrollViewReader { proxy in
                List(lines) { l in
                    HStack(alignment: .firstTextBaseline, spacing: 10) {
                        Text(l.time).foregroundStyle(DS.ink3).lineLimit(1).fixedSize()
                        Text(l.level).font(DS.caption.monospaced()).foregroundStyle(color(l.level))
                            .frame(width: 40, alignment: .leading)
                        Text(l.message).textSelection(.enabled)
                            .foregroundStyle(l.level == "ERROR" ? DS.fail : Color.primary)
                    }
                    .font(DS.code)
                    .listRowInsets(EdgeInsets(top: 6, leading: 14, bottom: 6, trailing: 14))
                    .listRowBackground(
                        (l.level == "ERROR" || l.level == "WARN")
                            ? RoundedRectangle(cornerRadius: 6, style: .continuous).fill(color(l.level).opacity(0.08)).padding(.horizontal, 6)
                            : nil)
                    .id(l.id)
                }
                .onChange(of: lines.last?.id) {
                    if follow, let last = lines.last { proxy.scrollTo(last.id, anchor: .bottom) }
                }
                .onChange(of: follow) { if follow, let last = lines.last { proxy.scrollTo(last.id, anchor: .bottom) } }
                .onAppear { if follow, let last = lines.last { proxy.scrollTo(last.id, anchor: .bottom) } }
                .overlay {
                    if lines.isEmpty {
                        EmptyState(icon: "doc.text.magnifyingglass", title: core.logs.isEmpty ? "还没有日志" : "没有匹配的日志",
                                   detail: core.logs.isEmpty ? "内核输出和应用操作会显示在这里。" : "调整搜索或关闭问题筛选查看其他日志。",
                                   action: core.logs.isEmpty ? nil : ("清除筛选", { filter = ""; problemsOnly = false }))
                    }
                }
                .glassPanel()
            }
            HStack {
                Text("显示 \(lines.count) / \(core.logs.count) 条 · 最多保留 2000 条")
                Spacer()
                Text(follow ? "跟随最新" : "自由浏览")
            }.font(DS.caption).foregroundStyle(DS.ink2).padding(.horizontal, DS.gutter).padding(.bottom, 12)
        }
    }

    private func exportLogs(_ lines: [LogLine]) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "Sluice.log"
        panel.message = "导出当前显示的 \(lines.count) 条日志"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try lines.map { "[\($0.time)] \($0.level) \($0.message)" }.joined(separator: "\n").write(to: url, atomically: true, encoding: .utf8)
        } catch { core.lastActionError = "日志导出失败：\(error.localizedDescription)" }
    }

    private func color(_ level: String) -> Color {
        switch level {
        case "ERROR": .red
        case "WARN": .orange
        case "APP": DS.accent
        default: .secondary
        }
    }
}

// MARK: profile

struct ConfigView: View {
    @EnvironmentObject var core: Core
    @ObservedObject var draft: ConfigDraft
    @State private var confirmRestore = false
    @State private var pendingSwitch: String?
    @State private var pendingDelete: String?
    @State private var profileEdit: ProfileEdit?
    @State private var editorMode = E2ELaunch.current?.editorMode ?? "文本"

    var body: some View {
        VStack(spacing: 0) {
            let name = URL(fileURLWithPath: core.configPath).lastPathComponent
            PaneHeader(title: "配置", subtitle: draft.text == draft.saved ? "\(name) · 已保存" : "\(name) · 有未保存的修改") {
                Button("从当前新建…") { profileEdit = .create }.disabled(draft.busy)
                Button("在 Finder 中显示") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: core.configPath)]) }
            }
            if draft.changedOnDisk {
                Notice(tone: DS.warn, icon: "doc.badge.ellipsis", title: "磁盘上的配置已更新", detail: "当前草稿已保留。载入磁盘版本前，可以复制草稿保留修改。") {
                    Button("复制草稿") { copyText(draft.text) }.glassButton()
                    Button("载入磁盘版本") { confirmRestore = true }.glassButton(prominent: true)
                }.padding(.horizontal, DS.gutter).padding(.bottom, 12)
            }
            Picker("编辑方式", selection: $editorMode) {
                Text("文本").tag("文本")
                Text("规则").tag("规则")
                Text("策略组").tag("策略组")
            }
            .pickerStyle(.segmented).labelsHidden().frame(maxWidth: 360)
            .padding(.horizontal, DS.gutter).padding(.bottom, 12)
            HStack(alignment: .top, spacing: DS.gap) {
                ConfigProfileList(busy: draft.busy, switchProfile: requestSwitch,
                                  edit: { profileEdit = $0 }, delete: { pendingDelete = $0 })
                Group {
                    if editorMode == "文本" {
                        ConfigEditor(text: $draft.text, errorLine: draft.message.flatMap { $0.1 ? nil : Core.errorLine(in: $0.0) })
                            .clipShape(RoundedRectangle(cornerRadius: DS.radius, style: .continuous))
                            .glass()
                    } else {
                        StructuredConfigEditors(text: $draft.text, section: editorMode == "规则" ? "Rule" : "Proxy Group")
                            .disabled(draft.busy)
                    }
                }
            }
            .padding(.horizontal, DS.gutter).padding(.bottom, 16)
            HStack {
                if let (msg, ok) = draft.message {
                    if ok {
                        Label(msg, systemImage: "checkmark.circle.fill").font(DS.small.weight(.medium)).foregroundStyle(DS.ok)
                    } else {
                        ErrorText(raw: msg)
                    }
                }
                if draft.message == nil && draft.text != draft.saved {
                    Label("有未保存的修改", systemImage: "circle.fill").font(DS.small.weight(.medium)).foregroundStyle(DS.warn)
                        .labelStyle(DotLabelStyle())
                }
                Spacer()
                Button("还原") { confirmRestore = true }.disabled(draft.busy || (!draft.hasChanges && !draft.changedOnDisk)).help(draft.text == draft.saved ? "没有修改可还原" : "放弃修改，恢复到磁盘上的版本")
                Button(draft.busy ? "检查中…" : "检查") { run(save: false) }.disabled(draft.busy)
                Button(draft.busy ? "处理中…" : core.state == .running ? "保存并应用" : "保存") { run(save: true) }.keyboardShortcut("s").disabled(draft.busy || !core.canChangeProfile || draft.text == draft.saved || draft.changedOnDisk)
                    .help(draft.text == draft.saved ? "没有修改需要保存" : "检查通过后保存，并让运行中的内核重新加载 (⌘S)")
                    .glassButton(prominent: true)
            }
            .glassButton()
            .padding(.horizontal, DS.gutter).padding(.bottom, DS.gutter)
        }
        .onAppear { core.refreshProfiles(); load() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            core.refreshProfiles()
            if !draft.busy { load() }
        }
        // Validation feedback belongs to the submitted version of the text.
        .onChange(of: draft.text) { if !draft.busy { draft.message = nil } }
        .confirmationDialog("放弃当前未保存的修改？", isPresented: $confirmRestore) {
            Button("载入磁盘版本", role: .destructive) { draft.restore(core.readConfig()) }
        }
        .confirmationDialog("切换配置会放弃当前未保存的修改", isPresented: Binding(
            get: { pendingSwitch != nil }, set: { if !$0 { pendingSwitch = nil } })) {
            if let name = pendingSwitch {
                Button("放弃修改并切换到「\(name)」", role: .destructive) { switchProfile(name) }
                Button("复制草稿并切换") { copyText(draft.text); switchProfile(name) }
            }
        }
        .confirmationDialog("删除「\(pendingDelete ?? "")」？", isPresented: Binding(
            get: { pendingDelete != nil }, set: { if !$0 { pendingDelete = nil } })) {
            if let name = pendingDelete {
                Button("删除配置", role: .destructive) {
                    do { try core.deleteProfile(name) }
                    catch { core.lastActionError = error.localizedDescription }
                    pendingDelete = nil
                }
            }
        } message: {
            Text("配置文件将从本地永久删除。")
        }
        .sheet(item: $profileEdit) { action in
            ProfileNameSheet(action: action) { name in
                switch action {
                case .create:
                    try core.createProfile(name: name, contents: draft.text)
                case .duplicate(let source):
                    try core.duplicateProfile(source, as: name)
                case .rename(let source):
                    let active = core.activeProfileName == source
                    try await core.renameProfile(source, to: name)
                    // Renaming the active file preserves its unsaved editor contents.
                    if active { draft.path = core.configPath }
                }
            }
        }
    }

    private func load() {
        draft.refresh(path: core.configPath, disk: core.readConfig())
    }

    private func run(save: Bool) {
        guard !draft.busy else { return }
        let submitted = draft.text
        let expected = draft.saved
        draft.busy = true
        draft.message = nil
        Task {
            defer { draft.busy = false }
            if save {
                let error = await core.saveConfig(submitted, expected: expected)
                let disk = core.readConfig()
                if disk == submitted { draft.saved = submitted }
                draft.changedOnDisk = disk != draft.saved
                draft.message = error.map { ($0, false) } ?? (draft.text == submitted
                    ? (core.state == .running ? "已保存并应用" : "已保存") : "已保存提交的版本，仍有新的修改", true)
            } else {
                let error = await core.validate(submitted)
                if draft.text == submitted { draft.message = error.map { ($0, false) } ?? ("配置有效", true) }
            }
        }
    }

    private func requestSwitch(_ name: String) {
        guard name != core.activeProfileName else { return }
        if draft.hasChanges { pendingSwitch = name } else { switchProfile(name) }
    }

    private func switchProfile(_ name: String) {
        pendingSwitch = nil
        draft.busy = true
        Task {
            defer { draft.busy = false }
            do {
                try await core.switchProfile(to: name)
                draft.message = nil
                load()
            } catch {
                draft.message = (error.localizedDescription, false)
                core.lastActionError = error.localizedDescription
            }
        }
    }
}

/// A small coloured dot before a label, for states such as "unsaved".
struct DotLabelStyle: LabelStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 6) { configuration.icon.font(.system(size: 6)); configuration.title }
    }
}

/// Line numbers in the editor's gutter.
final class LineNumberRuler: NSRulerView {
    var errorLine: Int?
    private let font = NSFont.monospacedDigitSystemFont(ofSize: 10.5, weight: .regular)
    init(textView: NSTextView) {
        super.init(scrollView: textView.enclosingScrollView, orientation: .verticalRuler)
        clientView = textView
        ruleThickness = 40
        NotificationCenter.default.addObserver(forName: NSText.didChangeNotification, object: textView, queue: .main) { [weak self] _ in
            self?.needsDisplay = true
        }
    }
    required init(coder: NSCoder) { fatalError() }

    override var isFlipped: Bool { true }

    /// TextKit lays out visual fragments, while numbers belong to logical lines.
    /// Start at each logical line's UTF-16 offset and use only its first fragment.
    static func markers(in tv: NSTextView) -> [(number: Int, rect: NSRect)] {
        guard let lm = tv.layoutManager, let tc = tv.textContainer else { return [] }
        lm.ensureLayout(for: tc)
        let text = tv.string as NSString
        var markers: [(number: Int, rect: NSRect)] = []
        var index = 0
        while index < text.length {
            let glyph = lm.glyphIndexForCharacter(at: index)
            let fragment = lm.lineFragmentRect(forGlyphAt: glyph, effectiveRange: nil)
            markers.append((markers.count + 1, fragment.offsetBy(dx: tv.textContainerOrigin.x, dy: tv.textContainerOrigin.y)))
            index = NSMaxRange(text.lineRange(for: NSRange(location: index, length: 0)))
        }
        if text.length == 0 || text.hasSuffix("\n") || text.hasSuffix("\r") {
            markers.append((markers.count + 1, lm.extraLineFragmentRect.offsetBy(dx: tv.textContainerOrigin.x, dy: tv.textContainerOrigin.y)))
        }
        return markers
    }

    override func drawHashMarksAndLabels(in rect: NSRect) {
        guard let tv = clientView as? NSTextView else { return }
        let attrs: [NSAttributedString.Key: Any] = [.font: font, .foregroundColor: NSColor(DS.ink3)]
        for marker in Self.markers(in: tv) where marker.rect.intersects(tv.visibleRect) {
            // Convert the whole fragment, including the text inset and scroll offset.
            let fragment = convert(marker.rect, from: tv)
            let label = "\(marker.number)" as NSString
            var a = attrs
            if marker.number == errorLine {
                a[.foregroundColor] = NSColor.systemRed
                a[.font] = NSFont.monospacedDigitSystemFont(ofSize: 10.5, weight: .bold)
            }
            let size = label.size(withAttributes: a)
            label.draw(at: NSPoint(x: ruleThickness - size.width - 8,
                                   y: fragment.minY + (fragment.height - size.height) / 2), withAttributes: a)
        }
    }
}

/// Config text editor with quiet syntax colouring: section headers in the accent,
/// keys and rule types in emphasis, values in secondary ink, comments faded.
struct ConfigEditor: NSViewRepresentable {
    @Binding var text: String
    /// A line `sluice check` rejected: tinted red, numbered red in the gutter, and scrolled into view.
    var errorLine: Int?

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSTextView.scrollableTextView()
        scroll.drawsBackground = false
        let tv = scroll.documentView as! NSTextView
        tv.delegate = context.coordinator
        tv.isRichText = false
        tv.allowsUndo = true
        tv.isAutomaticQuoteSubstitutionEnabled = false
        tv.isAutomaticDashSubstitutionEnabled = false
        tv.isAutomaticTextReplacementEnabled = false
        tv.isContinuousSpellCheckingEnabled = false
        tv.drawsBackground = false
        tv.textContainerInset = NSSize(width: 6, height: 12)
        tv.string = text
        Coordinator.highlight(tv)
        let ruler = LineNumberRuler(textView: tv)
        scroll.verticalRulerView = ruler
        scroll.hasVerticalRuler = true
        scroll.rulersVisible = true
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        context.coordinator.parent = self
        let tv = scroll.documentView as! NSTextView
        if tv.string != text {
            tv.string = text
            Coordinator.highlight(tv)
            scroll.verticalRulerView?.needsDisplay = true
        }
        if context.coordinator.shownError != errorLine {
            context.coordinator.shownError = errorLine
            Coordinator.markError(errorLine, in: tv)
            (scroll.verticalRulerView as? LineNumberRuler)?.errorLine = errorLine
            scroll.verticalRulerView?.needsDisplay = true
        }
    }

    final class Coordinator: NSObject, NSTextViewDelegate {
        var parent: ConfigEditor
        var shownError: Int?
        init(_ parent: ConfigEditor) { self.parent = parent }

        static func markError(_ line: Int?, in tv: NSTextView) {
            guard let lm = tv.layoutManager else { return }
            let s = tv.string as NSString
            lm.removeTemporaryAttribute(.backgroundColor, forCharacterRange: NSRange(location: 0, length: s.length))
            guard let line, line >= 1 else { return }
            var n = 1, location = 0
            while n < line && location < s.length {
                location = NSMaxRange(s.lineRange(for: NSRange(location: location, length: 0)))
                n += 1
            }
            guard n == line, location <= s.length else { return }
            let range = s.lineRange(for: NSRange(location: location, length: 0))
            lm.addTemporaryAttribute(.backgroundColor, value: NSColor.systemRed.withAlphaComponent(0.16), forCharacterRange: range)
            tv.setSelectedRange(NSRange(location: range.location, length: 0))
            tv.scrollRangeToVisible(range)
        }

        func textDidChange(_ note: Notification) {
            guard let tv = note.object as? NSTextView else { return }
            parent.text = tv.string
            Coordinator.highlight(tv)
        }

        static let body = NSFont.monospacedSystemFont(ofSize: 12.5, weight: .regular)
        static let strong = NSFont.monospacedSystemFont(ofSize: 12.5, weight: .semibold)
        static let header = NSFont.monospacedSystemFont(ofSize: 12.5, weight: .bold)

        static func highlight(_ tv: NSTextView) {
            guard let storage = tv.textStorage else { return }
            let s = storage.string as NSString
            let all = NSRange(location: 0, length: s.length)
            // Dynamic system colours, so the editor stays legible in both appearances.
            let ink = NSColor.labelColor, soft = NSColor(DS.ink2)
            storage.beginEditing()
            storage.setAttributes([.font: body, .foregroundColor: ink], range: all)
            s.enumerateSubstrings(in: all, options: .byLines) { line, range, _, _ in
                guard let line else { return }
                let t = line.trimmingCharacters(in: .whitespaces)
                let l = line as NSString
                if t.hasPrefix("#") || t.hasPrefix(";") || t.hasPrefix("//") {
                    storage.addAttribute(.foregroundColor, value: NSColor(DS.ink3), range: range)
                } else if t.hasPrefix("["), t.hasSuffix("]") {
                    storage.addAttributes([.font: header, .foregroundColor: NSColor(DS.accent)], range: range)
                } else if case let eq = l.range(of: "=").location, eq != NSNotFound {
                    storage.addAttributes([.font: strong], range: NSRange(location: range.location, length: eq))
                    storage.addAttribute(.foregroundColor, value: soft, range: NSRange(location: range.location + eq, length: range.length - eq))
                } else if case let comma = l.range(of: ",").location, comma != NSNotFound {
                    // Rule lines: TYPE,value,POLICY. The type leads, the rest is detail.
                    storage.addAttributes([.font: strong], range: NSRange(location: range.location, length: comma))
                    storage.addAttribute(.foregroundColor, value: soft, range: NSRange(location: range.location + comma, length: range.length - comma))
                }
            }
            storage.endEditing()
            tv.typingAttributes = [.font: body, .foregroundColor: ink]
        }
    }
}
