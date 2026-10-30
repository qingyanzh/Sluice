import AppKit
import Charts
import ServiceManagement
import SwiftUI

enum Pane: String, CaseIterable, Identifiable {
    case activity, overview, requests, policy, nodes, rule, logs, profile
    var id: String { rawValue }

    var title: String {
        switch self {
        case .activity: "活动"
        case .overview: "概览"
        case .requests: "请求"
        case .policy: "策略"
        case .nodes: "节点"
        case .rule: "规则"
        case .logs: "日志"
        case .profile: "配置"
        }
    }

    var icon: String {
        switch self {
        case .activity: "gauge.with.needle"
        case .overview: "square.grid.2x2"
        case .requests: "arrow.up.arrow.down.circle"
        case .policy: "signpost.right"
        case .nodes: "globe.asia.australia"
        case .rule: "line.3.horizontal.decrease.circle"
        case .logs: "doc.text"
        case .profile: "curlybraces.square"
        }
    }

    /// One line under the pane title saying what the pane is for.
    var subtitle: String {
        switch self {
        case .activity: "运行状态与实时流量"
        case .overview: "接管方式、代理服务与启动选项"
        case .requests: ""
        case .policy: "出站模式与策略组"
        case .nodes: "配置中的节点和订阅"
        case .rule: "规则自上而下匹配，命中即停止"
        case .logs: "内核输出"
        case .profile: ""
        }
    }

    /// Sidebar sections, Surge-style: an untitled top group, then titled groups.
    static let sections: [(String?, [Pane])] = [
        (nil, [.activity, .overview]),
        ("代理", [.requests, .policy, .nodes, .rule]),
        ("工具", [.logs, .profile]),
    ]
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
                VStack(alignment: .leading, spacing: 18) {
                    ForEach(Pane.sections, id: \.1) { title, panes in
                        VStack(alignment: .leading, spacing: 2) {
                            if let title {
                                Text(title).font(DS.caption).foregroundStyle(DS.ink3)
                                    .padding(.leading, 12).padding(.bottom, 4)
                            }
                            ForEach(panes) { row($0) }
                        }
                    }
                }
                .padding(.horizontal, 12).padding(.top, 52).padding(.bottom, 12)
            }
            .scrollIndicators(.never)
            StatusFooter().padding(12)
        }
        .frame(width: 200)
    }

    @State private var hovered: Pane?

    private func row(_ p: Pane) -> some View {
        let on = pane == p
        return Button {
            withAnimation(DS.spring) { pane = p }
        } label: {
            HStack(spacing: 10) {
                IconTile(symbol: p.icon, on: on, size: 22)
                    .symbolEffect(.bounce, value: on)
                Text(p.title).font(.system(size: 13, weight: on ? .semibold : .medium))
                Spacer()
            }
            .foregroundStyle(on ? Color.primary : DS.ink2)
            .padding(.leading, 6).padding(.trailing, 12).frame(height: 32)
            .background {
                if on {
                    RoundedRectangle(cornerRadius: 9, style: .continuous).fill(DS.surface)
                        .shadow(color: .black.opacity(0.06), radius: 3, y: 1)
                        .matchedGeometryEffect(id: "selection", in: ns)
                } else if hovered == p {
                    RoundedRectangle(cornerRadius: 9, style: .continuous).fill(Color.primary.opacity(0.045))
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(PressableStyle())
        .help("\(p.title)  ⌘\((Pane.sections.flatMap(\.1).firstIndex(of: p) ?? 0) + 1)")
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

struct MainView: View {
    @EnvironmentObject var core: Core
    @State private var pane: Pane? = .activity
    @AppStorage("appearance") private var appearance = Appearance.system

    var body: some View {
        HStack(spacing: 0) {
            Sidebar(pane: $pane)
                .background {
                    // ⌘1…⌘8 jump to panes in sidebar order.
                    ForEach(Array(Pane.sections.flatMap(\.1).enumerated()), id: \.element) { i, p in
                        Button("") { withAnimation(DS.spring) { pane = p } }
                            .keyboardShortcut(KeyEquivalent(Character("\(i + 1)")), modifiers: .command)
                            .opacity(0).frame(width: 0, height: 0).accessibilityHidden(true)
                    }
                }
            VStack(spacing: 0) {
                if let err = core.lastActionError {
                    ErrorBanner(message: err) { core.lastActionError = nil }
                }
                Group {
                switch pane ?? .activity {
                case .activity: ActivityView(pane: $pane)
                case .overview: OverviewView()
                case .requests: RequestsView()
                case .policy: PolicyView()
                case .nodes: NodesView()
                case .rule: RuleView()
                case .logs: LogsView()
                case .profile: ConfigView()
                }
                }
                .id(pane)
                .transition(.asymmetric(insertion: .opacity.combined(with: .offset(y: 8)), removal: .opacity))
            }
            .animation(.smooth(duration: 0.25), value: pane)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            .padding(.top, 40)
            .background(Backdrop())
            .toolbarBackground(.hidden, for: .windowToolbar)
            .toolbar {
                ToolbarItemGroup(placement: .primaryAction) {
                    TogglePill(title: "系统代理", on: core.systemProxyOn) { core.setSystemProxy(!core.systemProxyOn) }
                        .disabled(core.summary.httpListen == nil && core.summary.socksListen == nil)
                        .help("把系统的 HTTP/HTTPS/SOCKS 代理指向 Sluice")
                    EnhancedModePill()
                }
            }
        }
        .background(Backdrop())
        .ignoresSafeArea(.container, edges: .top)
        .navigationTitle("")
        .preferredColorScheme(appearance.scheme)
        .frame(minWidth: 860, minHeight: 560)
        .onAppear {
            core.refreshSystemProxy()
            core.startIfAutoStart()
        }
    }
}

// MARK: shared bits

struct StatusDot: View {
    let state: Core.State
    var color: Color {
        switch state {
        case .running: .green
        case .starting: .orange
        case .stopped: .secondary
        case .failed: .red
        }
    }
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

/// The hero status mark: a soft tinted disc holding a symbol, with a breathing
/// ring while running.
struct StatusOrb: View {
    let state: Core.State
    private var color: Color {
        switch state {
        case .running: .green
        case .starting: .orange
        case .stopped: .secondary
        case .failed: .red
        }
    }
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
    var body: some View {
        RoundedRectangle(cornerRadius: size * 0.3, style: .continuous)
            .fill(on ? AnyShapeStyle(DS.accent.gradient) : AnyShapeStyle(Color.primary.opacity(0.075)))
            .overlay(RoundedRectangle(cornerRadius: size * 0.3, style: .continuous)
                .strokeBorder(Color.white.opacity(on ? 0.25 : 0), lineWidth: 0.5))
            .shadow(color: DS.accent.opacity(on ? 0.30 : 0), radius: 3, y: 1)
            .overlay {
                Image(systemName: symbol)
                    .symbolVariant(on ? .fill : .none)
                    .font(.system(size: size * 0.5, weight: .medium))
                    .foregroundStyle(on ? Color.white : Color.primary.opacity(0.72))
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
        .foregroundStyle(tone == .secondary ? Color.secondary : tone)
        .padding(.horizontal, 8).padding(.vertical, 3)
        .background(tone.opacity(tone == .secondary ? 0.08 : 0.10), in: Capsule())
    }
}

/// Toolbar capsule with a status dot, like Surge's System Proxy / Enhanced Mode buttons.
struct TogglePill: View {
    let title: String
    let on: Bool
    let action: () -> Void
    var body: some View {
        Button(action: action) {
            HStack(spacing: 6) {
                Circle().fill(on ? Color.green : Color.secondary.opacity(0.5)).frame(width: 7, height: 7)
                    .shadow(color: on ? .green.opacity(0.6) : .clear, radius: 3)
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
                .buttonStyle(RoundIconStyle(prominent: !core.isActive))
        }
        .padding(8)
        .liquidGlass(in: RoundedRectangle(cornerRadius: 12, style: .continuous))
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
    guard let ms = latency else { return ("点击测试", .secondary) }
    if ms < 0 { return ("失败", .red) }
    return ("\(ms) ms", ms < 200 ? .green : ms < 500 ? .orange : .red)
}

struct LatencyBadge: View {
    let latency: Int?
    var body: some View {
        let (text, color) = latencyStyle(latency)
        StatusBadge(text: latency == nil ? "未测试" : text, tone: latency == nil ? .secondary : color)
            .monospacedDigit()
    }
}

/// "Sluice Flow", the app's design language (see docs/design-language.md):
/// calm off-white page and white content cards; Liquid Glass only on controls;
/// capsule geometry for everything interactive; a single accent that means
/// "active", marked by the flow mark; one spring for all motion; one type scale.
/// These tokens are the only source of spacing, radii, colours, type and motion.
enum DS {
    static let gutter: CGFloat = 24
    static let gap: CGFloat = 12
    static let radius: CGFloat = 14
    static let smallRadius: CGFloat = 10
    static let spring = Animation.spring(response: 0.32, dampingFraction: 0.82)
    /// Entrance: cards rise into place one after another.
    static let entrance = Animation.spring(response: 0.5, dampingFraction: 0.86)

    /// Brand accent, the blue-violet of the app icon. The only colour that means "active".
    static let accent = Color(nsColor: NSColor(name: nil) { a in
        a.bestMatch(from: [.darkAqua]) == .darkAqua
            ? NSColor(red: 0.42, green: 0.52, blue: 1.0, alpha: 1)
            : NSColor(red: 0.24, green: 0.36, blue: 0.98, alpha: 1)
    })
    /// Text inks, darker than the system secondary/tertiary so supporting text stays legible.
    static let ink2 = Color.primary.opacity(0.66)
    static let ink3 = Color.primary.opacity(0.46)

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
    static let title = Font.system(size: 26, weight: .bold)
    static let display = Font.system(size: 22, weight: .semibold)
    static let heading = Font.system(size: 14, weight: .semibold)
    static let label = Font.system(size: 13)
    static let small = Font.system(size: 12)
    static let caption = Font.system(size: 11, weight: .semibold)
    static func figure(_ size: CGFloat) -> Font { .system(size: size, weight: .semibold).monospacedDigit() }
}

/// Solid page colour: a quiet off-white in light mode, deep graphite in dark mode.
struct Backdrop: View {
    var body: some View { DS.page.ignoresSafeArea() }
}

/// A search field shaped like the other glass controls.
struct SearchField: View {
    let prompt: String
    @Binding var text: String
    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass").foregroundStyle(DS.ink2)
            TextField(prompt, text: $text).textFieldStyle(.plain)
            if !text.isEmpty {
                Button { text = "" } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(DS.ink3) }
                    .buttonStyle(.plain)
            }
        }
        .font(DS.label)
        .padding(.horizontal, 12).padding(.vertical, 6)
        .frame(width: 220)
        .liquidGlass(in: Capsule())
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
                    .font(.system(size: 13, weight: on ? .semibold : .medium))
                    .foregroundStyle(on ? Color.primary : DS.ink2)
                    .frame(maxWidth: .infinity).padding(.vertical, 7)
                    .background {
                        if on {
                            Capsule().fill(DS.surface)
                                .shadow(color: .black.opacity(0.10), radius: 3, y: 1)
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
                .strokeBorder(highlighted ? DS.accent.opacity(0.8) : Color.primary.opacity(0.09),
                              lineWidth: highlighted ? 1.5 : 0.5))
            .shadow(color: .black.opacity(0.05), radius: 1, y: 0.5)
            .shadow(color: .black.opacity(0.06), radius: 12, y: 5)
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
            if prominent { buttonStyle(PrimaryCapsuleStyle()) } else { buttonStyle(.glass).buttonBorderShape(.capsule) }
        } else {
            if prominent { buttonStyle(PrimaryCapsuleStyle()) } else { buttonStyle(.bordered).buttonBorderShape(.capsule) }
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
            .font(.system(size: 10, weight: .bold))
            .foregroundStyle(prominent ? Color.white : Color.primary.opacity(0.75))
            .frame(width: 26, height: 26)
            .background(prominent ? AnyShapeStyle(DS.accent.gradient) : AnyShapeStyle(Color.primary.opacity(hovering ? 0.12 : 0.07)), in: Circle())
            .shadow(color: prominent ? DS.accent.opacity(0.35) : .clear, radius: 4, y: 1)
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
    @Environment(\.isEnabled) private var enabled
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(DS.small.weight(.medium))
            .lineLimit(1).fixedSize()
            .foregroundStyle(.white)
            .padding(.horizontal, 12).padding(.vertical, 4)
            .background(DS.accent.opacity(enabled ? 1 : 0.4), in: Capsule())
            .shadow(color: DS.accent.opacity(0.25), radius: 4, y: 1)
            .opacity(configuration.isPressed ? 0.8 : 1)
            .scaleEffect(configuration.isPressed ? 0.97 : 1)
            .animation(DS.spring, value: configuration.isPressed)
    }
}

/// Big pane title with optional trailing controls, as at the top of every Surge pane.
struct PaneHeader<Trailing: View>: View {
    let title: String
    var subtitle: String?
    @ViewBuilder var trailing: Trailing
    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(DS.title).tracking(-0.3)
                if let subtitle, !subtitle.isEmpty {
                    Text(subtitle).font(DS.small).foregroundStyle(DS.ink2).lineLimit(1).truncationMode(.middle)
                }
            }
            Spacer()
            HStack(spacing: 8) { trailing }.glassButton()
        }
        .padding(.horizontal, DS.gutter).padding(.top, 14).padding(.bottom, 14)
    }
}

extension PaneHeader where Trailing == EmptyView {
    init(title: String, subtitle: String? = nil) { self.init(title: title, subtitle: subtitle) { EmptyView() } }
}

/// Rounded card on the pane background.
struct CardModifier: ViewModifier {
    func body(content: Content) -> some View {
        content
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .topLeading)
            .glass()
    }
}

extension View {
    /// The shared surface for cards and tiles: raised, borderless, soft shadow.
    func tileBackground(radius: CGFloat = DS.smallRadius + 2, highlighted: Bool = false) -> some View {
        glass(radius: radius, highlighted: highlighted)
    }
}

extension View {
    func card() -> some View { modifier(CardModifier()) }
    func hoverLift() -> some View { modifier(HoverLift()) }
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

/// Clickable tiles rise slightly under the pointer.
struct HoverLift: ViewModifier {
    @State private var hovering = false
    func body(content: Content) -> some View {
        content
            .scaleEffect(hovering ? 1.02 : 1)
            .shadow(color: .black.opacity(hovering ? 0.10 : 0), radius: 10, y: 4)
            .animation(.spring(response: 0.3, dampingFraction: 0.75), value: hovering)
            .onHover { hovering = $0 }
    }
}

/// Card caption with a tinted symbol, e.g. "↑ 上传".
struct CardTitle: View {
    let text: String
    let icon: String
    var body: some View {
        Label {
            Text(text).font(DS.caption).foregroundStyle(DS.ink2)
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
        Text(text).font(.system(size: 13, weight: .semibold)).foregroundStyle(DS.ink2)
            .padding(.top, 10).padding(.leading, 2)
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

struct ActivityView: View {
    @EnvironmentObject var core: Core
    @Binding var pane: Pane?
    @State private var topBy = 0

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: DS.gap) {
                hero.entrance(0)
                HStack(alignment: .top, spacing: DS.gap) {
                    TrafficCard(up: core.upRate, down: core.downRate, history: core.rateHistory)
                        .frame(maxWidth: .infinity)
                        .layoutPriority(1)
                    connectionsCard.frame(width: 260)
                }
                .fixedSize(horizontal: false, vertical: true)
                .entrance(1)
                HStack(alignment: .top, spacing: DS.gap) {
                    totalCard.frame(maxWidth: .infinity)
                    topCard.frame(maxWidth: .infinity)
                }
                .entrance(2)
            }
            .padding(.horizontal, DS.gutter).padding(.bottom, DS.gutter)
        }
        .paneHeader { PaneHeader(title: "活动", subtitle: Pane.activity.subtitle) }
    }

    private func port(_ listen: String) -> String { String(listen.split(separator: ":").last ?? "") }

    /// The group most people care about: the first manual group (usually "Proxy").
    private var mainGroup: PolicyGroup? { core.groups.first(where: \.isSelectable) ?? core.groups.first }

    /// The one card that answers "is it working, and how is traffic going out?"
    private var hero: some View {
        let subline: String = {
            if case .failed(let why) = core.state { return why }
            if core.state == .stopped { return "点击「启动」开始接管流量 · \(URL(fileURLWithPath: core.configPath).deletingPathExtension().lastPathComponent)" }
            let ports = [core.summary.httpListen.map { "HTTP \(port($0))" }, core.summary.socksListen.map { "SOCKS5 \(port($0))" }]
                .compactMap { $0 }.joined(separator: " · ")
            let profile = URL(fileURLWithPath: core.configPath).deletingPathExtension().lastPathComponent
            return [profile, ports, core.privileged ? "增强模式" : nil].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " · ")
        }()
        // Two tiers: the state and its controls, then the three facts that describe how traffic leaves.
        return VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .center, spacing: 14) {
                StatusOrb(state: core.state)
                VStack(alignment: .leading, spacing: 3) {
                    Text(core.state.label).font(DS.title).tracking(-0.3)
                        .contentTransition(.opacity).animation(DS.spring, value: core.state.label)
                    Text(subline).font(DS.small).foregroundStyle(core.state.isFailed ? Color.red : Color.secondary)
                        .lineLimit(2).textSelection(.enabled)
                }
                Spacer(minLength: 12)
                HStack(spacing: 8) {
                    Button { core.reload() } label: { Image(systemName: "arrow.triangle.2.circlepath") }
                        .help("重载配置").accessibilityLabel("重载配置").disabled(core.state != .running)
                    Button { core.restart() } label: { Image(systemName: "arrow.clockwise") }
                        .help("重启内核").accessibilityLabel("重启内核").disabled(!core.isActive)
                    StartStopButton().glassButton(prominent: true)
                        .background {
                            // While stopped, a soft halo invites the one action that matters.
                            if core.state == .stopped {
                                Capsule().fill(DS.accent.opacity(0.35))
                                    .phaseAnimator([0.0, 1.0]) { v, k in v.scaleEffect(1 + 0.25 * k).opacity(0.8 - 0.8 * k) }
                                        animation: { _ in .easeOut(duration: 1.6) }
                            }
                        }
                }
                .glassButton()
            }
            Divider().opacity(0.6)
            HStack(spacing: 0) {
                fact("出站模式", OutboundMode(rawValue: core.mode)?.title ?? core.mode,
                     icon: OutboundMode(rawValue: core.mode)?.icon ?? "arrow.triangle.branch", accent: core.state == .running)
                Divider().frame(height: 28).padding(.horizontal, 12)
                fact("当前节点", mainGroup?.selected ?? "–", icon: "globe.asia.australia")
                Divider().frame(height: 28).padding(.horizontal, 12)
                fact("系统代理", core.systemProxyOn ? "已接管" : "未接管", icon: "network", accent: core.systemProxyOn)
            }
        }
        .card()
    }

    private func fact(_ label: String, _ value: String, icon: String, accent: Bool = false) -> some View {
        HStack(spacing: 9) {
            IconTile(symbol: icon, on: accent, size: 28)
            VStack(alignment: .leading, spacing: 1) {
                Text(label).font(DS.caption).foregroundStyle(DS.ink2)
                Text(value).font(DS.heading)
                    .lineLimit(1).truncationMode(.middle)
                    .contentTransition(.opacity).animation(DS.spring, value: value)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var connectionsCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                CardTitle(text: "活动连接", icon: "point.3.connected.trianglepath.dotted")
                Spacer()
            }
            BigNumber(value: "\(core.traffic?.active ?? 0)")
            Divider()
            HStack {
                stat("\(core.connections.count)", "请求")
                Divider().frame(height: 30)
                stat("\(core.connections.filter { $0.outbound == "REJECT" }.count)", "已拒绝")
                Divider().frame(height: 30)
                stat("\(core.groups.count)", "策略组")
            }
        }
        .card()
    }

    private func stat(_ value: String, _ label: String) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(value).font(DS.figure(18))
                .contentTransition(.numericText())
                .animation(.smooth, value: value)
            Text(label).font(DS.small).foregroundStyle(DS.ink2)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var totalCard: some View {
        let up = Double(core.traffic?.up ?? 0), down = Double(core.traffic?.down ?? 0)
        let (n, u) = splitBytes(up + down)
        return VStack(alignment: .leading, spacing: 8) {
            CardTitle(text: "总计", icon: "chart.bar.fill")
            BigNumber(value: n, unit: u)
            HStack {
                VStack(alignment: .leading) {
                    Text("上传").font(DS.caption).foregroundStyle(DS.ink2)
                    Text(formatBytes(up)).font(DS.label.monospacedDigit())
                }
                Spacer()
                VStack(alignment: .trailing) {
                    Text("下载").font(DS.caption).foregroundStyle(DS.ink2)
                    Text(formatBytes(down)).font(DS.label.monospacedDigit())
                }
            }
            GeometryReader { geo in
                let total = max(up + down, 1)
                HStack(spacing: 3) {
                    Capsule().fill(Color.primary.opacity(0.15)).frame(width: max(4, (geo.size.width - 3) * up / total))
                    Capsule().fill(DS.accent)
                }
            }
            .frame(height: 8)
            .opacity(up + down == 0 ? 0.3 : 1)
        }
        .card()
    }

    private var topCard: some View {
        let key: (Connection) -> String = topBy == 0
            ? { $0.target.split(separator: ":").dropLast().joined(separator: ":").ifEmpty($0.target) }
            : { $0.policy }
        let counts = Dictionary(grouping: core.connections, by: key).mapValues(\.count)
        let top = counts.sorted { $0.value == $1.value ? $0.key < $1.key : $0.value > $1.value }.prefix(8)
        let maxCount = top.first?.value ?? 1
        return VStack(alignment: .leading, spacing: 10) {
            HStack {
                CardTitle(text: "请求排行", icon: "list.bullet")
                Spacer()
                Button("查看全部") { pane = .requests }.buttonStyle(.link).font(DS.small.weight(.medium)).tint(DS.accent)
            }
            GlassSegmented(options: [(0, "域名", nil), (1, "策略", nil)], selection: $topBy)
            if top.isEmpty {
                Text("还没有请求").foregroundStyle(DS.ink2).frame(maxWidth: .infinity, minHeight: 120)
            }
            ForEach(Array(top), id: \.key) { name, count in
                VStack(alignment: .leading, spacing: 3) {
                    let leader = name == top.first?.key
                    HStack {
                        Text(name).font(DS.label.weight(leader ? .semibold : .regular)).lineLimit(1).truncationMode(.middle)
                        Spacer()
                        Text("\(count)").font(DS.label.weight(.semibold)).monospacedDigit()
                            .foregroundStyle(leader ? DS.accent : DS.ink2)
                            .contentTransition(.numericText()).animation(.smooth, value: count)
                    }
                    GeometryReader { geo in
                        ZStack(alignment: .leading) {
                            Capsule().fill(Color.primary.opacity(0.06))
                            Capsule().fill(leader ? AnyShapeStyle(DS.accent.gradient) : AnyShapeStyle(Color.primary.opacity(0.22)))
                                .frame(width: max(5, geo.size.width * CGFloat(count) / CGFloat(maxCount)))
                                .animation(DS.spring, value: count)
                        }
                    }
                    .frame(height: 5)
                }
            }
            Spacer(minLength: 0)
        }
        .frame(maxHeight: .infinity, alignment: .top)
        .card()
    }
}

/// Upload and download together: two large figures with a legend, and one chart
/// drawing both series (upload graphite, download accent).
struct TrafficCard: View {
    let up: Double
    let down: Double
    let history: [(up: Double, down: Double)]

    var body: some View {
        let peak = history.map { max($0.up, $0.down) }.max() ?? 0
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                CardTitle(text: "实时流量", icon: "waveform.path")
                Spacer()
                Text("峰值 \(formatBytes(peak))/s").font(DS.caption).foregroundStyle(DS.ink3)
            }
            HStack(alignment: .firstTextBaseline, spacing: 28) {
                figure("下载", down, color: DS.accent, symbol: "arrow.down")
                figure("上传", up, color: .secondary, symbol: "arrow.up")
                Spacer()
            }
            Chart {
                ForEach(Array(history.enumerated()), id: \.offset) { n, v in
                    let i = 60 - history.count + n
                    AreaMark(x: .value("t", i), y: .value("rate", v.down), series: .value("s", "down"))
                        .foregroundStyle(LinearGradient(colors: [DS.accent.opacity(0.22), DS.accent.opacity(0.0)], startPoint: .top, endPoint: .bottom))
                        .interpolationMethod(.monotone)
                    LineMark(x: .value("t", i), y: .value("rate", v.down), series: .value("s", "down"))
                        .foregroundStyle(DS.accent).lineStyle(StrokeStyle(lineWidth: 2))
                        .interpolationMethod(.monotone)
                    LineMark(x: .value("t", i), y: .value("rate", v.up), series: .value("s", "up"))
                        .foregroundStyle(Color.secondary.opacity(0.7)).lineStyle(StrokeStyle(lineWidth: 1.5))
                        .interpolationMethod(.monotone)
                }
            }
            .chartBackground { _ in
                VStack(spacing: 0) {
                    ForEach(0..<3) { _ in
                        Spacer()
                        Rectangle().fill(Color.primary.opacity(0.07)).frame(height: 1)
                            .mask(HStack(spacing: 3) { ForEach(0..<120, id: \.self) { _ in Rectangle().frame(width: 3) } })
                    }
                }
            }
            .overlay {
                if peak == 0 {
                    Text("等待流量…").font(DS.small).foregroundStyle(DS.ink3)
                }
            }
            .chartXScale(domain: 0...59)
            .chartYScale(domain: 0...max(peak * 1.2, 1024))
            .chartXAxis(.hidden)
            .chartYAxis(.hidden)
            .animation(.smooth(duration: 0.6), value: history.last?.down)
            .frame(height: 84)
        }
        .card()
    }

    private func figure(_ label: String, _ rate: Double, color: Color, symbol: String) -> some View {
        let (n, u) = splitRate(rate)
        return VStack(alignment: .leading, spacing: 2) {
            Label {
                Text(label).font(DS.caption).foregroundStyle(DS.ink2)
            } icon: {
                Image(systemName: symbol).font(.system(size: 9, weight: .bold)).foregroundStyle(color)
            }
            .labelStyle(BadgeLabelStyle())
            BigNumber(value: n, unit: u)
        }
    }
}

extension String {
    func ifEmpty(_ fallback: String) -> String { isEmpty ? fallback : self }
}

// MARK: overview

struct OverviewView: View {
    @EnvironmentObject var core: Core
    @State private var enhancedBusy = false

    private let columns = [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 10) {
                SectionTitle(text: "网络接管")
                LazyVGrid(columns: columns, spacing: DS.gap) {
                    FeatureCard(icon: "network", title: "系统代理",
                                detail: "大多数应用的流量可以通过将 Sluice 设置为系统代理接管。具有最佳的兼容性和性能。",
                                isOn: Binding(get: { core.systemProxyOn }, set: { core.setSystemProxy($0) }),
                                status: core.systemProxyOn ? "Sluice 当前被设置为系统代理" : "未设置为系统代理",
                                statusOn: core.systemProxyOn)
                        .disabled(core.summary.httpListen == nil && core.summary.socksListen == nil)
                    FeatureCard(icon: "shield.lefthalf.filled", title: "增强模式",
                                detail: "部分应用可能不遵循系统代理设置。增强模式以 root 运行内核，接管所有应用的流量（需要管理员密码）。",
                                isOn: Binding(get: { core.summary.enhancedMode }, set: { on in
                                    enhancedBusy = true
                                    Task {
                                        if let err = await core.setEnhancedMode(on) { core.lastActionError = "增强模式: \(err)" }
                                        enhancedBusy = false
                                    }
                                }),
                                status: core.privileged ? "增强模式已激活" : core.summary.enhancedMode ? "已启用，启动后生效" : "已禁用",
                                statusOn: core.privileged)
                        .disabled(enhancedBusy)
                }.entrance(0)
                SectionTitle(text: "代理服务")
                LazyVGrid(columns: columns, spacing: DS.gap) {
                    FeatureCard(icon: "server.rack", title: "HTTP & SOCKS5 代理",
                                detail: "Sluice 在本机提供 HTTP 和 SOCKS5 代理服务，可以手动配置给其他应用使用。",
                                status: [core.summary.httpListen.map { "HTTP \($0)" }, core.summary.socksListen.map { "SOCKS5 \($0)" }]
                                    .compactMap { $0 }.joined(separator: "  ").ifEmpty("已禁用"),
                                statusOn: core.state == .running && (core.summary.httpListen != nil || core.summary.socksListen != nil))
                    FeatureCard(icon: "terminal", title: "控制 API",
                                detail: "本应用通过控制 API 切换策略、读取流量和测试规则。",
                                status: core.summary.apiPort.map { "127.0.0.1:\($0)" } ?? "未配置（应用需要它）",
                                statusOn: core.state == .running && core.summary.apiPort != nil)
                }.entrance(1)
                SectionTitle(text: "通用")
                LazyVGrid(columns: columns, spacing: DS.gap) {
                    FeatureCard(icon: "power", title: "打开应用时启动",
                                detail: "打开 Sluice 时自动启动代理内核。",
                                isOn: $core.autoStart,
                                status: core.autoStart ? "已启用" : "已禁用", statusOn: core.autoStart)
                    LoginItemCard()
                }.entrance(2)
                AppearanceCard().entrance(3)
            }
            .padding(.horizontal, DS.gutter).padding(.bottom, DS.gutter)
        }
        .paneHeader { PaneHeader(title: "概览", subtitle: Pane.overview.subtitle) }
    }
}

struct FeatureCard: View {
    var icon: String = "circle"
    let title: String
    let detail: String
    var isOn: Binding<Bool>?
    let status: String
    let statusOn: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                IconTile(symbol: icon, on: statusOn, size: 30)
                Text(title).font(DS.heading)
                Spacer()
                if let isOn { Toggle("", isOn: isOn).toggleStyle(.switch).labelsHidden().controlSize(.small).tint(DS.accent) }
            }
            Text(detail).font(DS.small).foregroundStyle(DS.ink2).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 4)
            StatusBadge(text: status, tone: statusOn ? .green : .secondary)
        }
        .frame(minHeight: 110, alignment: .topLeading)
        .card()
    }
}

struct AppearanceCard: View {
    @AppStorage("appearance") private var appearance = Appearance.system
    var body: some View {
        HStack(spacing: 10) {
            IconTile(symbol: appearance.icon, on: true, size: 30)
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

/// "Open at login" via SMAppService; only works for the bundled app (dist/Sluice.app).
struct LoginItemCard: View {
    @State private var enabled = SMAppService.mainApp.status == .enabled
    @State private var error: String?
    var body: some View {
        FeatureCard(icon: "person.crop.circle", title: "登录时打开",
                    detail: SMAppService.mainApp.status == .requiresApproval
                        ? "请在 系统设置 › 通用 › 登录项 中允许 Sluice。" : "登录 macOS 时自动打开 Sluice。",
                    isOn: Binding(get: { enabled }, set: set),
                    status: error ?? (enabled ? "已启用" : "已禁用"), statusOn: enabled)
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

    var body: some View {
        let mode = OutboundMode(rawValue: core.mode) ?? .rule
        ScrollView {
            VStack(alignment: .leading, spacing: 10) {
                GlassSegmented(options: OutboundMode.allCases.map { ($0, $0.title, $0.icon) },
                               selection: Binding(get: { mode }, set: { core.setMode($0.rawValue) }))
                .disabled(core.state != .running)
                Text(mode.explanation).font(DS.small).foregroundStyle(DS.ink2)

                HStack {
                    SectionTitle(text: "策略组")
                    Spacer()
                    Button("测试全部") { core.testAll() }
                        .glassButton()
                        .controlSize(.small)
                        .disabled(core.groups.allSatisfy(\.isSelectable))
                }
                if core.groups.isEmpty {
                    EmptyState(icon: "signpost.right",
                               title: core.state == .running ? "没有策略组" : "Sluice 未运行",
                               detail: core.state == .running ? "在配置的 [Proxy Group] 中添加策略组。" : "启动 Sluice 后可以查看和切换策略组。")
                        .frame(minHeight: 260)
                } else {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 190), spacing: DS.gap)], spacing: 10) {
                        ForEach(Array(core.groups.enumerated()), id: \.element.id) { i, g in GroupCard(group: g).entrance(i) }
                    }
                }
            }
            .padding(.horizontal, DS.gutter).padding(.bottom, DS.gutter)
        }
        .paneHeader { PaneHeader(title: "策略", subtitle: Pane.policy.subtitle) }
    }
}

/// A policy group as a tile; clicking opens its options.
struct GroupCard: View {
    @EnvironmentObject var core: Core
    let group: PolicyGroup
    @State private var showing = false

    private var kindLabel: String { Self.kindLabel(group.type) }

    static func kindLabel(_ type: String) -> String {
        switch type {
        case "select": "手动选择策略组"
        case "url-test": "自动测试策略组"
        case "fallback": "故障转移策略组"
        case "load-balance": "负载均衡策略组"
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
        let latency = group.options.first { $0.name == group.selected }?.latencyMs
        Button { showing = true } label: {
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 10) {
                    IconTile(symbol: kindIcon, on: showing, size: 28)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(group.group).font(DS.heading).lineLimit(1)
                        Text(kindLabel).font(DS.caption).foregroundStyle(DS.ink2).lineLimit(1)
                    }
                }
                Spacer(minLength: 10)
                HStack {
                    Text(group.selected).font(DS.label.weight(.medium)).lineLimit(1)
                    Spacer()
                    if latency != nil {
                        LatencyBadge(latency: latency)
                    }
                }
            }
            .frame(maxWidth: .infinity, minHeight: 78, alignment: .topLeading)
            .padding(12)
            .tileBackground(highlighted: showing)
            .contentShape(Rectangle())
        }
        .buttonStyle(PressableStyle())
        .hoverLift()
        .popover(isPresented: $showing, arrowEdge: .bottom) { GroupOptions(group: group) }
    }
}

struct GroupOptions: View {
    @EnvironmentObject var core: Core
    let group: PolicyGroup

    var body: some View {
        // Re-read the group so selection and latencies update while open.
        let g = core.groups.first { $0.group == group.group } ?? group
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 1) {
                    Text(g.group).font(DS.heading)
                    Text(GroupCard.kindLabel(g.type)).font(DS.caption).foregroundStyle(DS.ink2)
                }
                Spacer()
                if !g.isSelectable {
                    Button("测试") { core.test(group: g.group) }.glassButton().controlSize(.small)
                }
            }
            .padding(.horizontal, 14).padding(.vertical, 12)
            Divider()
            ScrollView {
                VStack(spacing: 0) {
                    ForEach(g.options, id: \.name) { o in OptionRow(group: g, option: o) }
                }
                .padding(.vertical, 4)
            }
            .frame(maxHeight: 360)
        }
        .frame(width: 300)
    }
}

struct OptionRow: View {
    @EnvironmentObject var core: Core
    let group: PolicyGroup
    let option: GroupOption

    var body: some View {
        let chosen = group.selected == option.name
        Button {
            if !chosen { core.select(group: group.group, option: option.name) }
        } label: {
            HStack {
                Image(systemName: "checkmark").font(.system(size: 11, weight: .bold))
                    .opacity(chosen ? 1 : 0).scaleEffect(chosen ? 1 : 0.5)
                    .foregroundStyle(DS.accent).frame(width: 14).animation(DS.spring, value: chosen)
                Text(option.name).font(DS.label.weight(chosen ? .semibold : .regular))
                Spacer()
                LatencyBadge(latency: option.latencyMs)
            }
            .padding(.horizontal, 10).padding(.vertical, 7)
            .background(chosen ? DS.accent.opacity(0.10) : .clear, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            .padding(.horizontal, 4)
            .contentShape(Rectangle())
        }
        .buttonStyle(PressableStyle())
        .disabled(!group.isSelectable)
        .help(group.isSelectable ? "使用 \(option.name)" : "\(group.type) 自动选择")
    }
}

// MARK: nodes

struct NodesView: View {
    @EnvironmentObject var core: Core
    @State private var showAddNode = false
    @State private var showAddSub = false
    @State private var text = ""

    private let columns = [GridItem(.adaptive(minimum: 190), spacing: DS.gap)]

    var body: some View {
        let proxies = ConfigText.lines(of: "Proxy", in: text)
        let subs = ConfigText.lines(of: "Proxy Group", in: text).filter { $0.contains("policy-path=") }
        ScrollView {
            VStack(alignment: .leading, spacing: 10) {
                SectionTitle(text: "代理 (\(proxies.count))")
                LazyVGrid(columns: columns, spacing: 10) {
                    ForEach(Array(proxies.enumerated()), id: \.element) { i, l in NodeCard(line: l).entrance(i) }
                    AddCard(title: "添加节点") { showAddNode = true }
                }
                SectionTitle(text: "订阅 (\(subs.count))")
                LazyVGrid(columns: columns, spacing: 10) {
                    ForEach(subs, id: \.self) { NodeCard(line: $0) }
                    AddCard(title: "添加订阅") { showAddSub = true }
                }
            }
            .padding(.horizontal, DS.gutter).padding(.bottom, DS.gutter)
        }
        .paneHeader {
            PaneHeader(title: "节点", subtitle: Pane.nodes.subtitle) {
                Button { showAddNode = true } label: { Label("添加节点", systemImage: "plus") }
                Button { showAddSub = true } label: { Label("添加订阅", systemImage: "link.badge.plus") }
            }
        }
        .sheet(isPresented: $showAddNode, onDismiss: refresh) { AddNodeSheet() }
        .sheet(isPresented: $showAddSub, onDismiss: refresh) { AddSubscriptionSheet() }
        .onAppear(perform: refresh)
    }

    private func refresh() { text = core.readConfig() }
}

struct NodeCard: View {
    @EnvironmentObject var core: Core
    let line: String
    var body: some View {
        let (name, rest) = line.firstIndex(of: "=").map {
            (line[..<$0].trimmingCharacters(in: .whitespaces), line[line.index(after: $0)...].trimmingCharacters(in: .whitespaces))
        } ?? (line, "")
        let parts = rest.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        // A node's latency, if any group has tested it.
        let latency = core.groups.lazy.flatMap(\.options).first { $0.name == name && $0.latencyMs != nil }?.latencyMs
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 10) {
                IconTile(symbol: line.contains("policy-path=") ? "link" : "server.rack", size: 28)
                VStack(alignment: .leading, spacing: 1) {
                    Text(name).font(DS.heading).lineLimit(1)
                    Text((parts.first ?? "").uppercased()).font(DS.caption).foregroundStyle(DS.ink2)
                }
            }
            Spacer(minLength: 10)
            HStack {
                // Server and port only; credentials stay out of the list.
                Text(parts.dropFirst().prefix(2).filter { !$0.contains("=") }.joined(separator: ":"))
                    .font(.system(size: 11).monospaced()).foregroundStyle(DS.ink2).lineLimit(1).truncationMode(.middle)
                Spacer()
                if latency != nil {
                    LatencyBadge(latency: latency)
                }
            }
        }
        .frame(maxWidth: .infinity, minHeight: 78, alignment: .topLeading)
        .padding(12)
        .tileBackground()
        .hoverLift()
        .help(name)
    }
}

struct AddCard: View {
    let title: String
    let action: () -> Void
    var body: some View {
        Button(action: action) {
            VStack(spacing: 6) {
                Image(systemName: "plus").font(.system(size: 16, weight: .medium))
                Text(title).font(DS.small.weight(.medium))
            }
            .foregroundStyle(DS.ink2)
                .frame(maxWidth: .infinity, minHeight: 102)
                .overlay(RoundedRectangle(cornerRadius: DS.smallRadius + 2, style: .continuous).strokeBorder(style: StrokeStyle(lineWidth: 1, dash: [5])).foregroundStyle(.separator))
                .contentShape(Rectangle())
        }
        .buttonStyle(PressableStyle())
        .hoverLift()
    }
}

/// Header shared by every sheet: an accent tile, a title and one line on what to do.
struct SheetHeader: View {
    let icon: String
    let title: String
    let detail: String
    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            IconTile(symbol: icon, on: true, size: 36)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.system(size: 17, weight: .bold))
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
                    TextField(prompt, text: $text, axis: .vertical).lineLimit(4...8)
                        .font(.system(size: 12.5, design: .monospaced))
                } else {
                    TextField(prompt, text: $text)
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
    let primary: String
    let enabled: Bool
    let cancel: () -> Void
    let action: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(DS.small).foregroundStyle(.red).textSelection(.enabled)
            }
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
            SheetFooter(error: error, primary: busy ? "检查中…" : "添加", enabled: !busy && !input.isEmpty, cancel: { dismiss() }) {
                busy = true
                Task {
                    error = await core.addNode(input)
                    busy = false
                    if error == nil { dismiss() }
                }
            }
        }
        .padding(22).frame(width: 520)
    }
}

struct AddSubscriptionSheet: View {
    @EnvironmentObject var core: Core
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var url = ""
    @State private var filter = ""
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
            SheetFooter(error: error, primary: busy ? "下载中…" : "添加", enabled: !busy && !url.isEmpty, cancel: { dismiss() }) {
                busy = true
                Task {
                    error = await core.addSubscription(name: name, url: url, filter: filter)
                    busy = false
                    if error == nil { dismiss() }
                }
            }
        }
        .padding(22).frame(width: 520)
    }
}

// MARK: requests

struct RequestsView: View {
    @EnvironmentObject var core: Core
    @State private var filter = ""
    @State private var selection: Connection.ID?

    var body: some View {
        let rows = core.connections.reversed().filter {
            filter.isEmpty || $0.target.localizedCaseInsensitiveContains(filter) || $0.outbound.localizedCaseInsensitiveContains(filter)
                || $0.policy.localizedCaseInsensitiveContains(filter)
        }
        VStack(spacing: 0) {
            PaneHeader(title: "请求", subtitle: "\(core.connections.count) 个请求") {
                SearchField(prompt: "搜索", text: $filter)
                Button { core.clearConnections() } label: { Label("清除", systemImage: "trash") }
            }
            HStack(spacing: DS.gap) {
                ScrollView {
                    LazyVStack(spacing: 2) {
                        ForEach(Array(rows)) { c in
                            RequestRow(connection: c, selected: c.id == selection) {
                                withAnimation(DS.spring) { selection = c.id }
                            }
                        }
                    }
                    .padding(6)
                }
                .overlay {
                    if rows.isEmpty {
                        EmptyState(icon: "arrow.up.arrow.down", title: core.connections.isEmpty ? "还没有请求" : "没有匹配的请求",
                                   detail: "经过 Sluice 的连接会实时显示在这里。")
                    }
                }
                .frame(minWidth: 420, maxWidth: .infinity, maxHeight: .infinity)
                .glass().entrance(0)
                RequestDetail(connection: core.connections.first { $0.id == selection })
                    .frame(width: 280)
                    .frame(maxHeight: .infinity, alignment: .top)
                    .glass().entrance(1)
            }
            .padding(.horizontal, DS.gutter).padding(.bottom, DS.gutter)
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

/// One request: a monogram, the host in emphasis, its route beneath, and the outbound and time at the end.
struct RequestRow: View {
    let connection: Connection
    let selected: Bool
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        let host = connection.target.split(separator: ":").dropLast().joined(separator: ":").ifEmpty(connection.target)
        Button(action: action) {
            HStack(spacing: 12) {
                Monogram(text: host, outbound: connection.outbound)
                VStack(alignment: .leading, spacing: 2) {
                    Text(host).font(DS.label.weight(.medium)).lineLimit(1).truncationMode(.middle)
                    Text("\(connection.proto) · \(connection.policy) · \(connection.rule)")
                        .font(DS.caption).foregroundStyle(DS.ink2).lineLimit(1).truncationMode(.tail)
                }
                Spacer(minLength: 8)
                OutboundTag(name: connection.outbound)
                Text(connection.time).font(DS.caption.monospacedDigit()).foregroundStyle(DS.ink3)
                    .lineLimit(1).fixedSize()
                    .frame(minWidth: 76, alignment: .trailing)
            }
            .padding(.horizontal, 10).padding(.vertical, 7)
            .background {
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .fill(selected ? DS.accent.opacity(0.09) : hovering ? Color.primary.opacity(0.04) : .clear)
            }
            .overlay(alignment: .leading) { if selected { FlowMark().padding(.leading, 1) } }
            .contentShape(Rectangle())
        }
        .buttonStyle(PressableStyle())
        .onHover { hovering = $0 }
    }
}

/// A quiet initial in a grey tile standing in for a site's icon.
struct Monogram: View {
    let text: String
    var outbound = "DIRECT"
    var body: some View {
        let tone: Color? = outbound == "REJECT" ? .red : outbound == "DIRECT" ? nil : DS.accent
        let parts = text.split(separator: ".")
        let core = parts.count >= 2 ? parts[parts.count - 2] : Substring(text)
        Text(String(core.prefix(1)).uppercased())
            .font(.system(size: 12, weight: .bold))
            .foregroundStyle(tone ?? DS.ink2)
            .frame(width: 28, height: 28)
            .background((tone ?? .primary).opacity(tone == nil ? 0.07 : 0.12), in: RoundedRectangle(cornerRadius: 8.4, style: .continuous))
    }
}

/// Centered placeholder used by every empty list.
struct EmptyState: View {
    let icon: String
    let title: String
    var detail: String = ""
    var body: some View {
        VStack(spacing: 8) {
            IconTile(symbol: icon, size: 48).padding(.bottom, 4)
            Text(title).font(DS.heading).foregroundStyle(DS.ink2)
            if !detail.isEmpty { Text(detail).font(DS.small).foregroundStyle(DS.ink3) }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct RequestDetail: View {
    let connection: Connection?
    var body: some View {
        if let c = connection {
            let host = c.target.split(separator: ":").dropLast().joined(separator: ":").ifEmpty(c.target)
            let port = c.target.split(separator: ":").last.map(String.init) ?? ""
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    HStack(spacing: 12) {
                        Monogram(text: host, outbound: c.outbound)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(host).font(DS.heading).lineLimit(2).textSelection(.enabled)
                            Text("\(c.proto) · 端口 \(port)").font(DS.caption).foregroundStyle(DS.ink2)
                        }
                    }
                    detailGroup("路由", [("规则", AnyView(Text(c.rule).textSelection(.enabled))),
                                         ("策略", AnyView(Text(c.policy))),
                                         ("出站", AnyView(OutboundTag(name: c.outbound)))])
                    detailGroup("请求", [("时间", AnyView(Text(c.time).monospacedDigit())),
                                         ("目标", AnyView(Text(c.target).textSelection(.enabled)))])
                }
                .padding(16)
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
                        row.1.font(DS.small).lineLimit(2).multilineTextAlignment(.trailing)
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
    let policy: String
    let options: String
}

struct RuleView: View {
    @EnvironmentObject var core: Core
    @State private var rules: [RuleRow] = []
    @State private var filter = ""
    @State private var target = "www.google.com"
    @State private var result: RouteResult?
    @State private var error: String?

    var body: some View {
        let rows = rules.filter {
            filter.isEmpty || $0.value.localizedCaseInsensitiveContains(filter) || $0.policy.localizedCaseInsensitiveContains(filter)
                || $0.type.localizedCaseInsensitiveContains(filter)
        }
        VStack(spacing: 0) {
            PaneHeader(title: "规则", subtitle: Pane.rule.subtitle) {
                SearchField(prompt: "搜索", text: $filter)
            }
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(rows) { rule in
                        HStack(spacing: 12) {
                            Text("\(rule.id)").font(DS.caption.monospacedDigit()).foregroundStyle(DS.ink3)
                                .frame(width: 24, alignment: .trailing)
                            Text(rule.type.uppercased()).font(.system(size: 10, weight: .semibold).monospaced())
                                .foregroundStyle(DS.ink2)
                                .padding(.horizontal, 7).padding(.vertical, 3)
                                .background(Color.primary.opacity(0.05), in: Capsule())
                                .frame(width: 150, alignment: .leading)
                            Text(rule.value.ifEmpty("其余所有请求")).font(DS.label)
                                .foregroundStyle(rule.value.isEmpty ? Color.secondary : Color.primary)
                                .lineLimit(1).truncationMode(.middle)
                            if !rule.options.isEmpty {
                                Text(rule.options).font(DS.caption).foregroundStyle(DS.ink3)
                            }
                            Spacer(minLength: 8)
                            OutboundTag(name: rule.policy)
                        }
                        .padding(.horizontal, 14).padding(.vertical, 9)
                        if rule.id != rows.last?.id { Divider().padding(.leading, 50).opacity(0.5) }
                    }
                }
                .padding(.vertical, 4)
            }
            .overlay { if rows.isEmpty { EmptyState(icon: "list.bullet.rectangle", title: "没有规则") } }
            .glassPanel()
            routeTest.padding(.horizontal, DS.gutter).padding(.bottom, DS.gutter)
        }
        .onAppear(perform: load)
        .onChange(of: core.state) { load() }
    }

    private var routeTest: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("规则测试").font(DS.heading)
            HStack {
                TextField("主机或 主机:端口", text: $target).textFieldStyle(.plain).font(DS.label).onSubmit(check)
                    .padding(.horizontal, 12).padding(.vertical, 6)
                    .background(Color.primary.opacity(0.05), in: Capsule())
                Button("测试", action: check).glassButton(prominent: true).disabled(target.isEmpty)
            }
            if let result {
                HStack(spacing: 16) {
                    LabeledContent("规则", value: result.rule)
                    LabeledContent("策略", value: result.policy)
                    LabeledContent("出站") { OutboundTag(name: result.outbound) }
                }
                .font(DS.label)
            } else if let error {
                Text(error).foregroundStyle(.red).font(DS.label)
            } else {
                Text("查看目标会匹配哪条规则、使用哪个出站，不会真正建立连接。").font(DS.small).foregroundStyle(DS.ink2)
            }
        }
        .card()
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
        Task {
            do {
                result = try await core.route(target)
                error = nil
            } catch {
                result = nil
                self.error = error.localizedDescription
            }
        }
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
                Button { core.clearLogs() } label: { Label("清除日志", systemImage: "trash") }
                    .labelStyle(.iconOnly).help("清除日志")
            }
            ScrollViewReader { proxy in
                List(lines) { l in
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Text(l.time).foregroundStyle(DS.ink2)
                        Text(l.level).font(.system(size: 9, weight: .bold)).foregroundStyle(color(l.level))
                            .padding(.horizontal, 5).padding(.vertical, 2)
                            .background(color(l.level).opacity(0.10), in: Capsule())
                            .frame(width: 52, alignment: .leading)
                        Text(l.message).textSelection(.enabled)
                            .foregroundStyle(l.level == "ERROR" ? Color.red : Color.primary)
                    }
                    .font(.system(.callout, design: .monospaced))
                    .listRowBackground(
                        (l.level == "ERROR" || l.level == "WARN")
                            ? RoundedRectangle(cornerRadius: 6, style: .continuous).fill(color(l.level).opacity(0.08)).padding(.horizontal, 6)
                            : nil)
                    .id(l.id)
                }
                .onChange(of: core.logs.count) {
                    if follow, let last = lines.last { proxy.scrollTo(last.id, anchor: .bottom) }
                }
                .glassPanel()
            }
        }
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
    @State private var text = ""
    @State private var saved = ""
    @State private var message: (String, Bool)?
    @State private var busy = false

    var body: some View {
        VStack(spacing: 0) {
            PaneHeader(title: "配置", subtitle: URL(fileURLWithPath: core.configPath).lastPathComponent) {
                Button("选取…", action: choose)
                Button("在 Finder 中显示") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: core.configPath)]) }
            }
            ConfigEditor(text: $text)
                .glassPanel()
            HStack {
                if let (msg, ok) = message {
                    Image(systemName: ok ? "checkmark.circle.fill" : "xmark.octagon.fill").foregroundStyle(ok ? .green : .red)
                    Text(msg).textSelection(.enabled).lineLimit(3)
                }
                Spacer()
                Button("还原") { load() }.disabled(text == saved)
                Button(busy ? "检查中…" : "检查") { run(save: false) }.disabled(busy)
                Button("保存并应用") { run(save: true) }.keyboardShortcut("s").disabled(busy || text == saved)
                    .glassButton(prominent: true)
            }
            .glassButton()
            .padding(.horizontal, DS.gutter).padding(.bottom, DS.gutter)
        }
        .onAppear(perform: load)
    }

    private func load() {
        text = core.readConfig()
        saved = text
        message = nil
    }

    private func run(save: Bool) {
        busy = true
        Task {
            if save {
                if let err = await core.saveConfig(text) {
                    message = (err, false)
                } else {
                    saved = text
                    message = (core.state == .running ? "已保存并应用" : "已保存", true)
                }
            } else {
                let err = await core.validate(text)
                message = err.map { ($0, false) } ?? ("配置有效", true)
            }
            busy = false
        }
    }

    private func choose() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.message = "选择 Sluice 配置文件"
        if panel.runModal() == .OK, let url = panel.url {
            core.configPath = url.path
            core.refreshSummary()
            load()
        }
    }
}

/// Config text editor with quiet syntax colouring: section headers in the accent,
/// keys and rule types in emphasis, values in secondary ink, comments faded.
struct ConfigEditor: NSViewRepresentable {
    @Binding var text: String

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
        tv.textContainerInset = NSSize(width: 10, height: 12)
        tv.string = text
        Coordinator.highlight(tv)
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        context.coordinator.parent = self
        let tv = scroll.documentView as! NSTextView
        if tv.string != text {
            tv.string = text
            Coordinator.highlight(tv)
        }
    }

    final class Coordinator: NSObject, NSTextViewDelegate {
        var parent: ConfigEditor
        init(_ parent: ConfigEditor) { self.parent = parent }

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
            let ink = NSColor.labelColor, soft = NSColor.secondaryLabelColor
            storage.beginEditing()
            storage.setAttributes([.font: body, .foregroundColor: ink], range: all)
            s.enumerateSubstrings(in: all, options: .byLines) { line, range, _, _ in
                guard let line else { return }
                let t = line.trimmingCharacters(in: .whitespaces)
                let l = line as NSString
                if t.hasPrefix("#") || t.hasPrefix(";") || t.hasPrefix("//") {
                    storage.addAttribute(.foregroundColor, value: NSColor.tertiaryLabelColor, range: range)
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
