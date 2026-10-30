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
        case .activity: "waveform.path.ecg.rectangle"
        case .overview: "square.grid.2x2"
        case .requests: "list.bullet.rectangle"
        case .policy: "arrow.triangle.branch"
        case .nodes: "server.rack"
        case .rule: "list.number"
        case .logs: "text.alignleft"
        case .profile: "doc.text"
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
                                Text(title).font(DS.caption).foregroundStyle(.tertiary)
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

    private func row(_ p: Pane) -> some View {
        let on = pane == p
        return Button {
            withAnimation(DS.spring) { pane = p }
        } label: {
            HStack(spacing: 10) {
                Image(systemName: p.icon).font(.system(size: 13, weight: on ? .semibold : .regular))
                    .frame(width: 18)
                Text(p.title).font(.system(size: 13, weight: on ? .semibold : .regular))
                Spacer()
            }
            .foregroundStyle(on ? Color.primary : Color.secondary)
            .padding(.horizontal, 12).frame(height: 32)
            .background {
                if on {
                    RoundedRectangle(cornerRadius: 9, style: .continuous).fill(DS.surface)
                        .shadow(color: .black.opacity(0.06), radius: 3, y: 1)
                        .matchedGeometryEffect(id: "selection", in: ns)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

struct MainView: View {
    @EnvironmentObject var core: Core
    @State private var pane: Pane? = .activity

    var body: some View {
        HStack(spacing: 0) {
            Sidebar(pane: $pane)
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
                Text(title).font(DS.small.weight(.medium))
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
                    Text(core.privileged ? "\(core.state.label) · root" : core.state.label).font(DS.caption).foregroundStyle(.secondary)
                }
            }
            Spacer()
            StartStopButton(compact: true).buttonStyle(.borderless).font(.system(size: 13, weight: .medium)).foregroundStyle(.secondary)
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
            Button { core.stop() } label: { Label("停止", systemImage: "stop.fill") }
                .labelStyle(compact ? AnyLabelStyle(.iconOnly) : AnyLabelStyle(.titleAndIcon))
                .help("停止 Sluice")
        } else {
            Button { core.start() } label: { Label("启动", systemImage: "play.fill") }
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
        HStack(alignment: .top) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red)
            Text(message).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
            Button(action: dismiss) { Image(systemName: "xmark") }.buttonStyle(.borderless)
        }
        .padding(10)
        .background(.red.opacity(0.1))
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
        Text(latency == nil ? "–" : text).font(DS.caption.monospacedDigit()).foregroundStyle(color)
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(color.opacity(0.12), in: Capsule())
    }
}

/// Design tokens: one gutter, one gap, two radii, shared everywhere.
enum DS {
    static let gutter: CGFloat = 24
    static let gap: CGFloat = 12
    static let radius: CGFloat = 14
    static let smallRadius: CGFloat = 10
    static let spring = Animation.spring(response: 0.32, dampingFraction: 0.82)

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
    static let display = Font.system(size: 22, weight: .semibold)
    static let heading = Font.system(size: 14, weight: .semibold)
    static let label = Font.system(size: 13)
    static let small = Font.system(size: 12)
    static let caption = Font.system(size: 11, weight: .medium)
    static func figure(_ size: CGFloat) -> Font { .system(size: size, weight: .medium).monospacedDigit() }
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
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
            TextField(prompt, text: $text).textFieldStyle(.plain)
            if !text.isEmpty {
                Button { text = "" } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(.tertiary) }
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
                    .foregroundStyle(on ? Color.primary : Color.secondary)
                    .frame(maxWidth: .infinity).padding(.vertical, 7)
                    .background {
                        if on {
                            Capsule().fill(DS.surface)
                                .shadow(color: .black.opacity(0.10), radius: 3, y: 1)
                                .matchedGeometryEffect(id: "thumb", in: ns)
                        }
                    }
                    .contentShape(Capsule())
                }
                .buttonStyle(.plain)
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
                .strokeBorder(highlighted ? Color.accentColor.opacity(0.8) : Color.primary.opacity(0.07),
                              lineWidth: highlighted ? 1.5 : 0.5))
            .shadow(color: .black.opacity(0.05), radius: 1, y: 0.5)
            .shadow(color: .black.opacity(0.05), radius: 10, y: 4)
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
            .padding(.horizontal, DS.gutter).padding(.bottom, DS.gutter)
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
            .background(Color.accentColor.opacity(enabled ? 1 : 0.4), in: Capsule())
            .shadow(color: Color.accentColor.opacity(0.25), radius: 4, y: 1)
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
                if let subtitle { Text(subtitle).font(DS.small).foregroundStyle(.secondary) }
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
            Text(text).font(DS.caption).foregroundStyle(.secondary)
        } icon: {
            Image(systemName: icon).font(.system(size: 11, weight: .medium)).foregroundStyle(.tertiary)
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
        Text(text).font(.system(size: 13, weight: .semibold)).foregroundStyle(.secondary)
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
                .animation(.smooth(duration: 0.4), value: value)
            if !unit.isEmpty { Text(unit).font(DS.label).foregroundStyle(.secondary).fixedSize() }
        }
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
                infoRow
                HStack(alignment: .top, spacing: DS.gap) {
                    statusCard.frame(maxWidth: .infinity)
                    RateCard(title: "上传", rate: core.upRate, series: core.rateHistory.map(\.up), color: .secondary)
                        .frame(maxWidth: .infinity)
                    RateCard(title: "下载", rate: core.downRate, series: core.rateHistory.map(\.down), color: .accentColor)
                        .frame(maxWidth: .infinity)
                }
                .fixedSize(horizontal: false, vertical: true)
                HStack(alignment: .top, spacing: DS.gap) {
                    VStack(spacing: DS.gap) {
                        connectionsCard
                        totalCard
                    }
                    .frame(maxWidth: .infinity)
                    topCard.frame(maxWidth: .infinity)
                }
            }
            .padding(.horizontal, DS.gutter).padding(.bottom, DS.gutter)
        }
        .paneHeader { PaneHeader(title: "活动") }
    }

    private var infoRow: some View {
        HStack(alignment: .top) {
            info("状态", core.state.label)
            info("配置", URL(fileURLWithPath: core.configPath).deletingPathExtension().lastPathComponent)
            info("出站模式", OutboundMode(rawValue: core.mode)?.title ?? core.mode)
            info("HTTP / SOCKS5 端口", [core.summary.httpListen, core.summary.socksListen].map { $0.map(port) ?? "–" }.joined(separator: " / "))
        }
    }

    private func port(_ listen: String) -> String { String(listen.split(separator: ":").last ?? "") }

    private func info(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(DS.small).foregroundStyle(.secondary)
            Text(value).font(DS.heading).lineLimit(1).truncationMode(.middle)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var statusCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                CardTitle(text: "SLUICE 内核", icon: "cpu")
                Spacer()
                StatusDot(state: core.state)
            }
            Text(core.state.label).font(DS.display)
            if case .failed(let why) = core.state {
                Text(why).font(DS.small).foregroundStyle(.red).lineLimit(3).textSelection(.enabled)
            } else if core.privileged {
                Text("增强模式 (root)").font(DS.small).foregroundStyle(.orange)
            }
            Spacer(minLength: 0)
            HStack {
                StartStopButton().glassButton(prominent: true)
                Button("重启") { core.restart() }.disabled(!core.isActive)
                Button("重载配置") { core.reload() }.disabled(core.state != .running)
            }
            .glassButton()
            .controlSize(.small)
        }
        .frame(minHeight: 130, alignment: .topLeading)
        .card()
    }

    private var connectionsCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                CardTitle(text: "活动连接", icon: "point.3.connected.trianglepath.dotted")
                Spacer()
                StatusDot(state: core.state)
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
            Text(label).font(DS.small).foregroundStyle(.secondary)
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
                    Text("上传").font(DS.caption).foregroundStyle(.secondary)
                    Text(formatBytes(up)).font(DS.label.monospacedDigit())
                }
                Spacer()
                VStack(alignment: .trailing) {
                    Text("下载").font(DS.caption).foregroundStyle(.secondary)
                    Text(formatBytes(down)).font(DS.label.monospacedDigit())
                }
            }
            GeometryReader { geo in
                let total = max(up + down, 1)
                HStack(spacing: 3) {
                    Capsule().fill(Color.primary.opacity(0.15)).frame(width: max(4, (geo.size.width - 3) * up / total))
                    Capsule().fill(Color.accentColor)
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
                Button("查看全部") { pane = .requests }.buttonStyle(.link).font(DS.small)
            }
            GlassSegmented(options: [(0, "域名", nil), (1, "策略", nil)], selection: $topBy)
            if top.isEmpty {
                Text("还没有请求").foregroundStyle(.secondary).frame(maxWidth: .infinity, minHeight: 120)
            }
            ForEach(Array(top), id: \.key) { name, count in
                VStack(alignment: .leading, spacing: 3) {
                    HStack {
                        Text(name).lineLimit(1).truncationMode(.middle)
                        Spacer()
                        Text("\(count)").monospacedDigit().foregroundStyle(.secondary)
                    }
                    GeometryReader { geo in
                        Capsule().fill(Color.primary.opacity(0.14))
                            .frame(width: geo.size.width * CGFloat(count) / CGFloat(maxCount))
                            .animation(.smooth, value: count)
                    }
                    .frame(height: 2)
                }
            }
            Spacer(minLength: 0)
        }
        .frame(maxHeight: .infinity, alignment: .top)
        .card()
    }
}

struct RateCard: View {
    let title: String
    let rate: Double
    let series: [Double]
    let color: Color

    var body: some View {
        let (n, u) = splitRate(rate)
        let peak = series.max() ?? 0
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                CardTitle(text: title, icon: title == "上传" ? "arrow.up" : "arrow.down")
                Spacer()
                Text("\(formatBytes(peak))/s").font(DS.caption).foregroundStyle(.tertiary)
            }
            BigNumber(value: n, unit: u)
            Chart {
                // Right-aligned: the newest sample is always at the right edge.
                ForEach(Array(series.enumerated()), id: \.offset) { n, v in
                    let i = 60 - series.count + n
                    AreaMark(x: .value("t", i), y: .value("rate", v))
                        .foregroundStyle(LinearGradient(colors: [color.opacity(0.3), color.opacity(0.02)], startPoint: .top, endPoint: .bottom))
                        .interpolationMethod(.monotone)
                    LineMark(x: .value("t", i), y: .value("rate", v))
                        .foregroundStyle(color)
                        .interpolationMethod(.monotone)
                }
            }
            .chartXScale(domain: 0...59)
            .chartYScale(domain: 0...max(peak * 1.2, 1024))
            .animation(.smooth(duration: 0.6), value: series.last)
            .chartXAxis(.hidden)
            .chartYAxis(.hidden)
            .frame(height: 56)
        }
        .frame(minHeight: 130, alignment: .topLeading)
        .card()
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
                    FeatureCard(title: "系统代理",
                                detail: "大多数应用的流量可以通过将 Sluice 设置为系统代理接管。具有最佳的兼容性和性能。",
                                isOn: Binding(get: { core.systemProxyOn }, set: { core.setSystemProxy($0) }),
                                status: core.systemProxyOn ? "Sluice 当前被设置为系统代理" : "未设置为系统代理",
                                statusOn: core.systemProxyOn)
                        .disabled(core.summary.httpListen == nil && core.summary.socksListen == nil)
                    FeatureCard(title: "增强模式",
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
                }
                SectionTitle(text: "代理服务")
                LazyVGrid(columns: columns, spacing: DS.gap) {
                    FeatureCard(title: "HTTP & SOCKS5 代理",
                                detail: "Sluice 在本机提供 HTTP 和 SOCKS5 代理服务，可以手动配置给其他应用使用。",
                                status: [core.summary.httpListen.map { "HTTP \($0)" }, core.summary.socksListen.map { "SOCKS5 \($0)" }]
                                    .compactMap { $0 }.joined(separator: "  ").ifEmpty("已禁用"),
                                statusOn: core.state == .running && (core.summary.httpListen != nil || core.summary.socksListen != nil))
                    FeatureCard(title: "控制 API",
                                detail: "本应用通过控制 API 切换策略、读取流量和测试规则。",
                                status: core.summary.apiPort.map { "127.0.0.1:\($0)" } ?? "未配置（应用需要它）",
                                statusOn: core.state == .running && core.summary.apiPort != nil)
                }
                SectionTitle(text: "通用")
                LazyVGrid(columns: columns, spacing: DS.gap) {
                    FeatureCard(title: "打开应用时启动",
                                detail: "打开 Sluice 时自动启动代理内核。",
                                isOn: $core.autoStart,
                                status: core.autoStart ? "已启用" : "已禁用", statusOn: core.autoStart)
                    LoginItemCard()
                }
            }
            .padding(.horizontal, DS.gutter).padding(.bottom, DS.gutter)
        }
        .paneHeader { PaneHeader(title: "概览") }
    }
}

struct FeatureCard: View {
    let title: String
    let detail: String
    var isOn: Binding<Bool>?
    let status: String
    let statusOn: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(title).font(DS.heading)
                Spacer()
                if let isOn { Toggle("", isOn: isOn).toggleStyle(.switch).labelsHidden().controlSize(.small) }
            }
            Text(detail).font(DS.small).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 4)
            HStack(spacing: 6) {
                Circle().fill(statusOn ? Color.green : Color.primary.opacity(0.2)).frame(width: 6, height: 6)
                Text(status).font(DS.small).lineLimit(1).truncationMode(.middle)
            }
        }
        .frame(minHeight: 110, alignment: .topLeading)
        .card()
    }
}

/// "Open at login" via SMAppService; only works for the bundled app (dist/Sluice.app).
struct LoginItemCard: View {
    @State private var enabled = SMAppService.mainApp.status == .enabled
    @State private var error: String?
    var body: some View {
        FeatureCard(title: "登录时打开",
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
                Text(mode.explanation).font(DS.small).foregroundStyle(.secondary)

                HStack {
                    SectionTitle(text: "策略组")
                    Spacer()
                    Button("测试全部") { core.testAll() }
                        .glassButton()
                        .controlSize(.small)
                        .disabled(core.groups.allSatisfy(\.isSelectable))
                }
                if core.groups.isEmpty {
                    ContentUnavailableView(core.state == .running ? "没有策略组" : "Sluice 未运行",
                                           systemImage: "arrow.triangle.branch",
                                           description: Text(core.state == .running ? "在配置的 [Proxy Group] 中添加策略组。" : "启动 Sluice 后可以查看和切换策略组。"))
                        .frame(minHeight: 240)
                } else {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 150), spacing: 10)], spacing: 10) {
                        ForEach(core.groups) { GroupCard(group: $0) }
                    }
                }
            }
            .padding(.horizontal, DS.gutter).padding(.bottom, DS.gutter)
        }
        .paneHeader { PaneHeader(title: "策略") }
    }
}

/// A policy group as a tile; clicking opens its options.
struct GroupCard: View {
    @EnvironmentObject var core: Core
    let group: PolicyGroup
    @State private var showing = false

    private var kindLabel: String {
        switch group.type {
        case "select": "手动选择策略组"
        case "url-test": "自动测试策略组"
        case "fallback": "故障转移策略组"
        case "load-balance": "负载均衡策略组"
        default: group.type
        }
    }

    var body: some View {
        let latency = group.options.first { $0.name == group.selected }?.latencyMs
        Button { showing = true } label: {
            VStack(alignment: .leading, spacing: 3) {
                Text(kindLabel).font(DS.caption).foregroundStyle(.secondary)
                Text(group.group).font(DS.heading).lineLimit(1)
                Spacer(minLength: 8)
                HStack {
                    Image(systemName: group.isSelectable ? "hand.point.up.left" : "bolt.horizontal").font(DS.caption).foregroundStyle(.tertiary)
                    Text(group.selected).font(DS.caption).foregroundStyle(.secondary).lineLimit(1)
                    Spacer()
                    if latency != nil {
                        let (t, c) = latencyStyle(latency)
                        Text(t).font(DS.caption.monospacedDigit()).foregroundStyle(c)
                    }
                }
            }
            .frame(maxWidth: .infinity, minHeight: 64, alignment: .topLeading)
            .padding(10)
            .tileBackground(highlighted: showing)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
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
                Text(g.group).font(DS.heading)
                Text(g.type).font(DS.small).foregroundStyle(.secondary)
                Spacer()
                Button("测试") { core.test(group: g.group) }.glassButton().controlSize(.small).disabled(g.isSelectable)
            }
            .padding(10)
            Divider()
            ScrollView {
                VStack(spacing: 0) {
                    ForEach(g.options, id: \.name) { o in OptionRow(group: g, option: o) }
                }
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
                Image(systemName: "checkmark").opacity(chosen ? 1 : 0).foregroundStyle(Color.accentColor).frame(width: 14)
                Text(option.name)
                Spacer()
                LatencyBadge(latency: option.latencyMs)
            }
            .padding(.horizontal, 10).padding(.vertical, 6)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
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

    private let columns = [GridItem(.adaptive(minimum: 170), spacing: 10)]

    var body: some View {
        let proxies = ConfigText.lines(of: "Proxy", in: text)
        let subs = ConfigText.lines(of: "Proxy Group", in: text).filter { $0.contains("policy-path=") }
        ScrollView {
            VStack(alignment: .leading, spacing: 10) {
                SectionTitle(text: "代理 (\(proxies.count))")
                LazyVGrid(columns: columns, spacing: 10) {
                    ForEach(proxies, id: \.self) { NodeCard(line: $0) }
                    AddCard { showAddNode = true }.help("添加节点")
                }
                SectionTitle(text: "订阅 (\(subs.count))")
                LazyVGrid(columns: columns, spacing: 10) {
                    ForEach(subs, id: \.self) { NodeCard(line: $0) }
                    AddCard { showAddSub = true }.help("添加订阅")
                }
            }
            .padding(.horizontal, DS.gutter).padding(.bottom, DS.gutter)
        }
        .paneHeader {
            PaneHeader(title: "节点", subtitle: "配置中的 [Proxy] 节点和订阅") {
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
            Text((parts.first ?? "").uppercased()).font(DS.caption).foregroundStyle(.secondary)
            Text(name).font(DS.heading).lineLimit(1)
            Spacer(minLength: 6)
            HStack {
                // Server and port only; credentials stay out of the list.
                Text(parts.dropFirst().prefix(2).filter { !$0.contains("=") }.joined(separator: ":"))
                    .font(.system(size: 11).monospaced()).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                Spacer()
                if latency != nil {
                    let (t, c) = latencyStyle(latency)
                    Text(t).font(DS.caption.monospacedDigit()).foregroundStyle(c)
                }
            }
        }
        .frame(maxWidth: .infinity, minHeight: 64, alignment: .topLeading)
        .padding(10)
        .tileBackground()
        .hoverLift()
        .help(name)
    }
}

struct AddCard: View {
    let action: () -> Void
    var body: some View {
        Button(action: action) {
            Image(systemName: "plus").font(.system(size: 18, weight: .light)).foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, minHeight: 84)
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(style: StrokeStyle(lineWidth: 1, dash: [5])).foregroundStyle(.separator))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .hoverLift()
    }
}

struct AddNodeSheet: View {
    @EnvironmentObject var core: Core
    @Environment(\.dismiss) private var dismiss
    @State private var input = ""
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: DS.gap) {
            Text("添加节点").font(.system(size: 20, weight: .semibold))
            Text("粘贴分享链接（ss://、vmess://、vless://、trojan://、hysteria2://）或代理行，例如 `HK = ss, hk.example.com, 8388, encrypt-method=aes-256-gcm, password=…`。")
                .foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            TextField("分享链接或代理行", text: $input, axis: .vertical)
                .lineLimit(3...6).textFieldStyle(.roundedBorder).font(.body.monospaced())
            if let error { Text(error).foregroundStyle(.red).textSelection(.enabled) }
            HStack {
                Spacer()
                Button("取消") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(busy ? "检查中…" : "添加") {
                    busy = true
                    Task {
                        error = await core.addNode(input)
                        busy = false
                        if error == nil { dismiss() }
                    }
                }
                .keyboardShortcut(.defaultAction).disabled(busy || input.isEmpty)
            }
        }
        .padding(20).frame(width: 520)
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
        VStack(alignment: .leading, spacing: DS.gap) {
            Text("添加订阅").font(.system(size: 20, weight: .semibold))
            Form {
                TextField("名称", text: $name, prompt: Text("Subscription"))
                TextField("URL", text: $url, prompt: Text("https://…"))
                TextField("名称过滤（正则，可选）", text: $filter, prompt: Text("例如 香港|HK"))
            }
            Text("保存配置前会先下载并检查节点。").font(DS.small).foregroundStyle(.secondary)
            if let error { Text(error).foregroundStyle(.red).textSelection(.enabled) }
            HStack {
                Spacer()
                Button("取消") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(busy ? "下载中…" : "添加") {
                    busy = true
                    Task {
                        error = await core.addSubscription(name: name, url: url, filter: filter)
                        busy = false
                        if error == nil { dismiss() }
                    }
                }
                .keyboardShortcut(.defaultAction).disabled(busy || url.isEmpty)
            }
        }
        .padding(20).frame(width: 520)
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
                Table(rows, selection: $selection) {
                    TableColumn("时间", value: \.time).width(min: 60, ideal: 70)
                    TableColumn("", value: \.proto).width(34)
                    TableColumn("目标", value: \.target).width(min: 160, ideal: 240)
                    TableColumn("策略", value: \.policy).width(min: 60, ideal: 90)
                    TableColumn("出站") { OutboundTag(name: $0.outbound) }
                    .width(min: 60, ideal: 90)
                }
                .overlay {
                    if core.connections.isEmpty {
                        ContentUnavailableView("还没有请求", systemImage: "list.bullet.rectangle",
                                               description: Text("经过 Sluice 的连接会实时显示在这里。"))
                    }
                }
                .frame(minWidth: 420)
                .scrollContentBackground(.hidden)
                .clipShape(RoundedRectangle(cornerRadius: DS.radius, style: .continuous))
                .glass()
                RequestDetail(connection: core.connections.first { $0.id == selection })
                    .scrollContentBackground(.hidden)
                    .frame(width: 280)
                    .glass()
                    .animation(DS.spring, value: selection)
            }
            .padding(.horizontal, DS.gutter).padding(.bottom, DS.gutter)
        }
    }
}

/// Colour-coded outbound name: direct green, reject red, proxies in the accent colour.
struct OutboundTag: View {
    let name: String
    var body: some View {
        let color: Color = name == "REJECT" ? .red : name == "DIRECT" ? .secondary : .accentColor
        Text(name).font(DS.caption).lineLimit(1)
            .foregroundStyle(color)
            .padding(.horizontal, 6).padding(.vertical, 1)
            .background(color.opacity(0.12), in: Capsule())
    }
}

struct RequestDetail: View {
    let connection: Connection?
    var body: some View {
        Group {
            if let c = connection {
                Form {
                    Section("请求") {
                        LabeledContent("目标") { Text(c.target).textSelection(.enabled) }
                        LabeledContent("协议", value: c.proto)
                        LabeledContent("时间", value: c.time)
                    }
                    Section("路由") {
                        LabeledContent("规则") { Text(c.rule).textSelection(.enabled) }
                        LabeledContent("策略", value: c.policy)
                        LabeledContent("出站") { OutboundTag(name: c.outbound) }
                    }
                }
                .formStyle(.grouped)
            } else {
                Text("选择一个请求查看详情").foregroundStyle(.secondary).frame(maxWidth: .infinity, maxHeight: .infinity)
            }
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
            PaneHeader(title: "规则", subtitle: "规则将按照从上至下的顺序进行测试。") {
                SearchField(prompt: "搜索", text: $filter)
            }
            Table(rows) {
                TableColumn("ID") { Text("\($0.id)").monospacedDigit().foregroundStyle(.secondary) }.width(36)
                TableColumn("类型", value: \.type).width(min: 90, ideal: 130)
                TableColumn("值", value: \.value).width(min: 140, ideal: 260)
                TableColumn("策略", value: \.policy).width(min: 70, ideal: 110)
                TableColumn("选项", value: \.options).width(min: 60, ideal: 90)
            }
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
                Text("查看目标会匹配哪条规则、使用哪个出站，不会真正建立连接。").font(DS.small).foregroundStyle(.secondary)
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

    var body: some View {
        let lines = core.logs.filter { filter.isEmpty || $0.message.localizedCaseInsensitiveContains(filter) || $0.level.localizedCaseInsensitiveContains(filter) }
        VStack(spacing: 0) {
            PaneHeader(title: "日志") {
                SearchField(prompt: "搜索", text: $filter)
                Toggle(isOn: $follow) { Label("跟随", systemImage: "arrow.down.to.line") }.toggleStyle(.button)
                Button { core.clearLogs() } label: { Label("清除", systemImage: "trash") }
            }
            ScrollViewReader { proxy in
                List(lines) { l in
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Text(l.time).foregroundStyle(.secondary)
                        Text(l.level).foregroundStyle(color(l.level)).frame(width: 44, alignment: .leading)
                        Text(l.message).textSelection(.enabled)
                    }
                    .font(.system(.callout, design: .monospaced))
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
        case "APP": .accentColor
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
            PaneHeader(title: "配置", subtitle: core.configPath) {
                Button("选取…", action: choose)
                Button("在 Finder 中显示") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: core.configPath)]) }
            }
            TextEditor(text: $text)
                .font(.system(.body, design: .monospaced))
                .autocorrectionDisabled()
                .padding(8)
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
