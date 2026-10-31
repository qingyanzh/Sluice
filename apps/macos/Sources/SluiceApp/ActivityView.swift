import Charts
import SwiftUI

/// The dashboard uses one column grid and one card shell for all four metrics.
struct ActivityView: View {
    @EnvironmentObject var core: Core
    @Binding var pane: Pane?
    @Binding var nodesIntent: NodesIntent?
    @State private var topBy = 0

    var body: some View {
        ScrollViewReader { scroll in
            ScrollView {
                VStack(alignment: .leading, spacing: DS.sectionGap) {
                    hero.entrance(0)
                    routeCard.entrance(1)
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            Text("流量与请求").font(DS.heading)
                            Spacer()
                            Text("本次运行").font(DS.small).foregroundStyle(DS.ink3)
                        }
                        ViewThatFits(in: .horizontal) {
                            dashboardGrid.frame(minWidth: 640)
                            VStack(spacing: DS.gap) {
                                trafficCard
                                connectionsCard
                                totalCard
                                topCard
                            }
                        }
                    }.entrance(2)
                    TrafficStatsView().entrance(3).id("stats")
                }
                .frame(maxWidth: DS.maxContentWidth)
                .frame(maxWidth: .infinity)
                .padding(.horizontal, DS.gutter).padding(.bottom, DS.gutter)
            }
            .paneHeader { PaneHeader(title: "活动", subtitle: Pane.activity.subtitle) }
            .task {
                if E2ELaunch.current?.destination == "stats" {
                    try? await Task.sleep(for: .seconds(2))
                    scroll.scrollTo("stats", anchor: .top)
                }
            }
        }
    }

    private var dashboardGrid: some View {
        VStack(spacing: DS.gap) {
            HStack(alignment: .top, spacing: DS.gap) {
                trafficCard.frame(maxWidth: .infinity)
                connectionsCard.frame(maxWidth: .infinity)
            }
            HStack(alignment: .top, spacing: DS.gap) {
                totalCard.frame(maxWidth: .infinity)
                topCard.frame(maxWidth: .infinity)
            }
        }
    }

    private var trafficCard: some View {
        TrafficCard(up: core.displayedRates.up, down: core.displayedRates.down, history: core.rateHistory, running: core.state == .running)
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
        // Tier 1: the state and the one action that changes it. Reload and restart stay small.
        return VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .center, spacing: 14) {
                StatusOrb(state: core.state)
                VStack(alignment: .leading, spacing: 5) {
                    Text(core.state.label).font(DS.display).tracking(-0.2)
                        .contentTransition(.opacity).animation(DS.spring, value: core.state.label)
                    Text(subline).font(DS.small).foregroundStyle(core.state.isFailed ? DS.fail : DS.ink2)
                        .lineLimit(2).textSelection(.enabled)
                }
                Spacer(minLength: 12)
                HStack(spacing: 8) {
                    Button { core.reload() } label: {
                        if core.reloading { ProgressView().controlSize(.mini) }
                        else { Image(systemName: "arrow.triangle.2.circlepath") }
                    }
                        .buttonStyle(RoundIconStyle())
                        .help(core.state == .running ? "重载配置" : "内核未运行，无法重载").accessibilityLabel("重载配置")
                        .disabled(core.state != .running || core.reloading)
                    Button { core.restart() } label: { Image(systemName: "arrow.clockwise") }
                        .buttonStyle(RoundIconStyle())
                        .help(core.isActive ? "重启内核" : "内核未运行，无法重启").accessibilityLabel("重启内核")
                        .disabled(!core.isActive)
                    StartStopButton()
                        .buttonStyle(core.isActive ? AnyButtonStyle(SecondaryCapsuleStyle(large: true)) : AnyButtonStyle(PrimaryCapsuleStyle(large: true)))
                        .padding(.leading, 4)
                }
            }
            if !core.summary.hasNodes {
                Notice(tone: DS.accent, icon: "globe.asia.australia", title: "尚未添加代理节点",
                       detail: "当前所有流量都会直连。添加订阅可以批量导入，也可以粘贴单个节点链接。") {
                    Button("添加节点") { nodesIntent = .node; pane = .nodes }.glassButton()
                    Button("添加订阅") { nodesIntent = .subscription; pane = .nodes }.glassButton(prominent: true)
                }
            }
        }
        .card()
    }

    /// Tier 2: how traffic leaves — mode, node, system proxy. Each fact opens the pane that changes it.
    private var routeCard: some View {
        HStack(spacing: 0) {
            fact("出站模式", OutboundMode(rawValue: core.mode)?.title ?? core.mode,
                 note: nil,
                 icon: OutboundMode(rawValue: core.mode)?.icon ?? "arrow.triangle.branch",
                 tone: nil) { pane = .policy }
            Divider().frame(height: 32)
            fact("当前节点", currentNode, icon: "globe.asia.australia",
                 tone: nil) { pane = core.summary.hasNodes ? .policy : .nodes }
            Divider().frame(height: 32)
            if proxyWithoutCore {
                fact("系统代理", "已开启 · 内核未运行", icon: "network", tone: DS.warn) { pane = .overview }
            } else {
                fact("系统代理", core.systemProxyOn ? "已接管" : "未接管", icon: "network",
                     tone: core.systemProxyOn ? DS.ok : nil) { pane = .overview }
            }
        }
        .padding(.vertical, 6).padding(.horizontal, 4)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glass()
    }

    /// The system proxy points at Sluice while nothing is listening: the user's network is broken.
    private var proxyWithoutCore: Bool { core.systemProxyOn && core.state != .running && core.state != .starting }

    private var currentNode: String {
        if !core.summary.hasNodes { return "无 · 直连" }
        guard core.state == .running, let selected = mainGroup?.selected else { return "启动后显示" }
        return selected == "DIRECT" ? "直连" : subscriptionNodeLabel(selected)
    }

    /// One fact: its tile is coloured by the state grammar (nil = grey, off or no data).
    private func fact(_ label: String, _ value: String, note: String? = nil, icon: String, tone: Color? = nil,
                      open: @escaping () -> Void) -> some View {
        Button(action: open) {
            HStack(spacing: 10) {
                Image(systemName: icon).font(.system(size: 17, weight: .regular)).foregroundStyle(tone ?? DS.ink3).frame(width: 24)
                VStack(alignment: .leading, spacing: 5) {
                    HStack(spacing: 4) {
                        Text(label).font(DS.caption).foregroundStyle(DS.ink2)
                        if let note { Text("· \(note)").font(DS.caption).foregroundStyle(DS.warn) }
                    }
                    Text(value).font(DS.label.weight(.medium)).foregroundStyle(tone == DS.warn ? DS.warn : Color.primary)
                        .lineLimit(1).truncationMode(.middle)
                        .contentTransition(.opacity).animation(DS.spring, value: value)
                }
                Spacer(minLength: 4)
                Image(systemName: "chevron.right").font(.system(size: 10, weight: .semibold)).foregroundStyle(DS.ink3)
            }
            .padding(.horizontal, 16).padding(.vertical, 12)
            .contentShape(Rectangle())
        }
        .buttonStyle(PressableStyle())
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var connectionsCard: some View {
        DashboardCard(title: "活动连接", icon: "point.3.connected.trianglepath.dotted", note: "实时") {
            BigNumber(value: "\(core.traffic?.active ?? 0)", unit: "个连接")
            Spacer(minLength: 12)
            Divider().opacity(0.6)
            HStack(spacing: 12) {
                statistic("\(core.connections.count)", label: "已记录请求")
                statistic("\(core.connections.filter { $0.outbound == "REJECT" }.count)", label: "已拒绝")
                statistic("\(core.groups.count)", label: "策略组")
            }
        }
    }

    private func statistic(_ value: String, label: String) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(value).font(DS.figure(20)).monospacedDigit()
                .contentTransition(.numericText())
                .animation(.smooth(duration: 0.5), value: value)
                .frame(width: 80, alignment: .leading)
            Text(label).font(DS.small).foregroundStyle(DS.ink2).fixedSize(horizontal: false, vertical: true)
        }.frame(maxWidth: .infinity, alignment: .leading)
    }

    private var totalCard: some View {
        let up = Double(core.traffic?.up ?? 0), down = Double(core.traffic?.down ?? 0)
        let (value, unit) = splitBytes(up + down)
        return DashboardCard(title: "累计流量", icon: "chart.bar", note: "上传 + 下载") {
            BigNumber(value: value, unit: unit)
            Spacer(minLength: 12)
            HStack {
                byteTotal("上传", value: up, tone: DS.ink2)
                Spacer()
                byteTotal("下载", value: down, tone: DS.accent)
            }
            GeometryReader { geometry in
                let fraction = up + down > 0 ? up / (up + down) : 0
                ZStack(alignment: .leading) {
                    Capsule().fill(DS.wellStrong)
                    if up + down > 0 {
                        Capsule().fill(DS.accent.opacity(0.7))
                        Capsule().fill(Color.primary.opacity(0.24)).frame(width: geometry.size.width * fraction)
                    }
                }
            }.frame(height: 5).accessibilityHidden(true)
        }
    }

    private func byteTotal(_ title: String, value: Double, tone: Color) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 5) {
                Circle().fill(tone).frame(width: 5, height: 5)
                Text(title).font(DS.small).foregroundStyle(DS.ink2)
            }
            Text(formatBytes(value)).font(DS.label.monospacedDigit())
                .contentTransition(.numericText())
                .animation(.smooth(duration: 0.7), value: formatBytes(value))
                .frame(width: 100, alignment: .leading)
        }
    }

    private var topCard: some View {
        let key: (Connection) -> String = topBy == 0
            ? { $0.target.split(separator: ":").dropLast().joined(separator: ":").ifEmpty($0.target) }
            : { $0.policy }
        let counts = Dictionary(grouping: core.connections, by: key).mapValues(\.count)
        let rows = counts.sorted { $0.value == $1.value ? $0.key < $1.key : $0.value > $1.value }.prefix(3)
        let highest = rows.first?.value ?? 1
        return DashboardCard(title: "请求排行", icon: "list.number", note: "前 3 项") {
            HStack(spacing: 0) {
                rankTab("域名", value: 0)
                rankTab("策略", value: 1)
                Spacer()
                Button { pane = .requests } label: {
                    HStack(spacing: 4) {
                        Text("全部请求")
                        Image(systemName: "arrow.up.right").font(.system(size: 9, weight: .medium))
                    }
                }.buttonStyle(.plain).font(DS.small).foregroundStyle(DS.ink2).help("查看全部请求")
            }
            if rows.isEmpty {
                VStack(spacing: 6) {
                    Text("暂无请求").font(DS.label).foregroundStyle(DS.ink2)
                    Text("经过 Sluice 的连接会出现在这里").font(DS.small).foregroundStyle(DS.ink3)
                }.frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                VStack(spacing: 12) {
                    ForEach(Array(rows), id: \.key) { name, count in
                        VStack(spacing: 5) {
                            HStack {
                                Text(subscriptionNodeLabel(name)).font(DS.small).lineLimit(1).truncationMode(.middle)
                                Spacer(minLength: 12)
                                Text("\(count)").font(DS.small.monospacedDigit()).foregroundStyle(DS.ink2)
                                    .frame(width: 56, alignment: .trailing)
                            }
                            GeometryReader { geometry in
                                ZStack(alignment: .leading) {
                                    Capsule().fill(DS.well)
                                    Capsule().fill(DS.accent.opacity(0.55))
                                        .frame(width: max(3, geometry.size.width * CGFloat(count) / CGFloat(highest)))
                                }
                            }.frame(height: 3)
                        }
                    }
                }
                Spacer(minLength: 0)
            }
        }
    }

    private func rankTab(_ title: String, value: Int) -> some View {
        Button { topBy = value } label: {
            Text(title).font(DS.small.weight(topBy == value ? .semibold : .regular))
                .foregroundStyle(topBy == value ? DS.accent : DS.ink3)
                .padding(.horizontal, 8).frame(height: 22)
                .background(topBy == value ? DS.accentFill : .clear,
                            in: RoundedRectangle(cornerRadius: 6, style: .continuous))
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(topBy == value ? .isSelected : [])
    }
}

/// A single header, inset, height and baseline rhythm for dashboard cards.
struct DashboardCard<Content: View>: View {
    let title: String
    let icon: String
    var note = ""
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 8) {
                CardTitle(text: title, icon: icon)
                Spacer(minLength: 8)
                if !note.isEmpty { Text(note).font(DS.caption).monospacedDigit().foregroundStyle(DS.ink3)
                    .fixedSize(horizontal: false, vertical: true) }
            }
            VStack(alignment: .leading, spacing: 12) { content }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
        .padding(DS.cardPadding)
        .frame(maxWidth: .infinity)
        .frame(height: DS.dashboardCardHeight, alignment: .topLeading)
        .glass()
    }
}

struct TrafficCard: View {
    let up: DisplayedRate
    let down: DisplayedRate
    let history: [TrafficRatePoint]
    var running = true
    @State private var peakFormatter = RateUnitFormatter()
    @State private var peakText = "0 B/s"

    var body: some View {
        let peak = history.map { max($0.up, $0.down) }.max() ?? 0
        DashboardCard(title: "实时流量", icon: "waveform.path", note: "峰值 \(peakText)") {
            HStack(alignment: .firstTextBaseline, spacing: 24) {
                rate("下载", value: down, color: DS.accent)
                rate("上传", value: up, color: DS.ink2)
                Spacer(minLength: 0)
            }
            Chart {
                ForEach(history) { value in
                    let position = value.time
                    AreaMark(x: .value("采样", position), y: .value("速率", value.down), series: .value("方向", "下载"))
                        .foregroundStyle(DS.accentWash).interpolationMethod(.monotone)
                    LineMark(x: .value("采样", position), y: .value("速率", value.down), series: .value("方向", "下载"))
                        .foregroundStyle(DS.accent).lineStyle(StrokeStyle(lineWidth: 1.5)).interpolationMethod(.monotone)
                    LineMark(x: .value("采样", position), y: .value("速率", value.up), series: .value("方向", "上传"))
                        .foregroundStyle(DS.ink2.opacity(0.8)).lineStyle(StrokeStyle(lineWidth: 1)).interpolationMethod(.monotone)
                }
            }
            .chartXScale(domain: chartStart...(history.last?.time ?? Date())).chartYScale(domain: 0...max(peak * 1.2, 1024))
            .chartXAxis(.hidden).chartYAxis(.hidden)
            .chartBackground { _ in
                VStack(spacing: 0) {
                    ForEach(0..<3) { _ in
                        Spacer()
                        Rectangle().fill(DS.well).frame(height: 0.5)
                    }
                }
            }
            .overlay {
                if !running || peak == 0 {
                    Text(running ? "等待流量" : "启动后显示实时流量").font(DS.small).foregroundStyle(DS.ink3)
                }
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("最近 60 次流量采样")
            .accessibilityValue("下载每秒 \(down.formatted.text)，上传每秒 \(up.formatted.text)")
            .frame(maxHeight: .infinity)
        }
        .onChange(of: peak, initial: true) { peakText = peakFormatter.format(peak).text }
    }

    /// Up to the last 60 s; a short history fills the width instead of hugging the right edge.
    private var chartStart: Date {
        let last = history.last?.time ?? Date()
        let window = last.addingTimeInterval(-59)
        let lower = max(history.first?.time ?? window, window)
        return lower < last ? lower : window
    }

    private func rate(_ title: String, value: DisplayedRate, color: Color) -> some View {
        let number = value.formatted.number, unit = value.formatted.unit + "/s"
        return VStack(alignment: .leading, spacing: 6) {
            BigNumber(value: number, unit: unit, width: 150)
            HStack(spacing: 5) {
                Circle().fill(color).frame(width: 5, height: 5)
                Text(title).font(DS.small).foregroundStyle(DS.ink2)
            }
        }
    }
}
