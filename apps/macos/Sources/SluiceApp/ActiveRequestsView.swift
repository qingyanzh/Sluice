import SwiftUI

struct ActiveRequestsView: View {
    @EnvironmentObject var core: Core
    @State private var filter = ""
    @State private var kind = RequestsView.OutboundKind.all
    @State private var selection: UInt64?
    @State private var paused = false
    @State private var frozen: [ActiveConnection] = []
    @State private var frozenRates: [UInt64: DisplayedRates] = [:]
    @State private var confirmCloseAll = false

    var body: some View {
        let source = paused ? frozen : core.activeConnections
        let rows = source.sorted(by: ActiveConnection.displayOrder).filter { kind.admits($0.outbound) && $0.matches(filter.trimmingCharacters(in: .whitespacesAndNewlines)) }
        VStack(spacing: 12) {
            ViewThatFits(in: .horizontal) {
                HStack(spacing: 12) { filters; Spacer(minLength: 0); actions }
                VStack(alignment: .leading, spacing: 12) {
                    filters
                    HStack { Spacer(); actions }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            if let error = core.activeConnectionsError {
                Text(error).font(DS.small).foregroundStyle(DS.warn)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            HStack(alignment: .top, spacing: DS.gap) {
                GeometryReader { geometry in
                    let columns = geometry.size.width >= ActiveConnectionRow.columnBreakpoint
                    VStack(spacing: 0) {
                        ActiveConnectionListHeader(showsTrafficColumns: columns)
                        Divider()
                        ScrollView {
                            LazyVStack(spacing: 0) {
                                ForEach(rows) { connection in
                                    ActiveConnectionRow(connection: connection,
                                                        rates: displayedRates(for: connection.id),
                                                        selected: selection == connection.id,
                                                        showsTrafficColumns: columns) {
                                        selection = connection.id
                                    }
                                    .overlay { ActiveConnectionMenu(connection: connection, core: core) }
                                    if connection.id != rows.last?.id {
                                        Divider().padding(.horizontal, 14)
                                    }
                                }
                            }
                            .padding(.horizontal, 6)
                        }
                        .overlay {
                            if rows.isEmpty {
                                if core.state != .running {
                                    EmptyState(icon: "arrow.up.arrow.down", title: "Sluice 未运行",
                                               detail: "启动后可查看活动 TCP 连接", action: ("启动 Sluice", { core.requestStart() }))
                                } else if !core.activeConnectionsLoaded {
                                    if let error = core.activeConnectionsError {
                                        EmptyState(icon: "exclamationmark.triangle", title: "无法读取活动连接", detail: error)
                                    } else {
                                        ProgressView("正在加载活动连接…").font(DS.small)
                                    }
                                } else if !filter.isEmpty || kind != .all {
                                    EmptyState(icon: "magnifyingglass", title: "没有匹配的活动连接", detail: "清除筛选查看全部连接",
                                               action: ("清除筛选", { filter = ""; kind = .all }))
                                } else {
                                    EmptyState(icon: "arrow.up.arrow.down", title: "没有活动连接", detail: "连接建立后会显示在这里；UDP 不在此列表中")
                                }
                            }
                        }
                    }
                }
                .frame(minWidth: 260, maxWidth: .infinity, maxHeight: .infinity)
                .clipShape(RoundedRectangle(cornerRadius: DS.radius, style: .continuous))
                .glass()
                detail(source.first { $0.id == selection })
                    .frame(width: 260).frame(maxHeight: .infinity, alignment: .top).glass()
            }
            HStack(spacing: 6) {
                Circle().fill(paused ? DS.warn : core.state == .running ? DS.ok : DS.off).frame(width: 6, height: 6)
                Text(paused ? "列表已暂停 · 网络流量继续运行" : core.eventsConnected ? "实时事件流 · 活动 TCP 连接" : "轮询更新 · 活动 TCP 连接")
                Spacer()
            }.font(DS.caption).foregroundStyle(DS.ink2)
        }
        .padding(.horizontal, DS.gutter).padding(.bottom, 12)
        .confirmationDialog("断开全部活动连接？", isPresented: $confirmCloseAll) {
            Button("全部断开", role: .destructive) { core.closeAllConnections() }
            Button("取消", role: .cancel) {}
        } message: {
            Text("所有当前打开的 TCP 连接都会断开，正在传输的请求可能中断")
        }
        .onAppear { core.observeActiveConnections(true) }
        .onDisappear { core.observeActiveConnections(false) }
        .onChange(of: rows.map(\.id)) {
            if let selection, !rows.contains(where: { $0.id == selection }) { self.selection = nil }
        }
    }

    private var filters: some View {
        HStack(spacing: 12) {
            GlassSegmented(options: [(RequestsView.OutboundKind.all, "全部", nil), (.proxy, "代理", nil), (.direct, "直连", nil)], selection: $kind)
                .frame(width: 200)
            SearchField(prompt: "目标、进程或策略链", text: $filter)
        }
    }

    private var actions: some View {
        HStack(spacing: 12) {
            Button {
                if !paused {
                    frozen = core.activeConnections
                    frozenRates = core.displayedConnectionRates
                }
                paused.toggle()
            } label: { Label(paused ? "继续更新" : "暂停更新", systemImage: paused ? "play.fill" : "pause") }
                .labelStyle(.iconOnly).help("仅暂停列表更新，网络流量继续运行")
            Button("全部断开", role: .destructive) { confirmCloseAll = true }
                .disabled(core.state != .running || core.activeConnections.isEmpty)
        }.glassButton()
    }

    private func canClose(_ id: UInt64) -> Bool {
        core.state == .running && core.activeConnections.contains { $0.id == id }
    }

    private func displayedRates(for id: UInt64) -> DisplayedRates {
        (paused ? frozenRates[id] : core.displayedConnectionRates[id]) ?? DisplayedRates()
    }

    @ViewBuilder private func detail(_ connection: ActiveConnection?) -> some View {
        if let connection {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Text(connection.target).font(DS.heading).textSelection(.enabled)
                    field("策略链", connection.policyChain)
                    field("规则", connection.rule)
                    field("进程", connection.process ?? "—")
                    field("来源", connection.src ?? "—")
                    field("协议", connection.network.uppercased())
                    field("开始时间", Date(timeIntervalSince1970: Double(connection.startMs) / 1000).formatted(date: .abbreviated, time: .standard))
                    field("上传", "\(formatBytes(Double(connection.up))) · \(displayedRates(for: connection.id).up.formatted.text)")
                    field("下载", "\(formatBytes(Double(connection.down))) · \(displayedRates(for: connection.id).down.formatted.text)")
                    Button("断开连接", role: .destructive) { core.closeConnection(connection.id) }
                        .glassButton().disabled(!canClose(connection.id))
                }.padding(DS.cardPadding)
            }
        } else {
            EmptyState(icon: "sidebar.right", title: "未选择连接", detail: "选择左侧的活动连接查看详情")
        }
    }

    private func field(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(DS.caption).foregroundStyle(DS.ink3)
            Text(value).font(DS.small).monospacedDigit().foregroundStyle(DS.ink2).textSelection(.enabled)
        }
    }
}

/// The header and every row share their traffic columns and responsive breakpoint.
struct ActiveConnectionListHeader: View {
    let showsTrafficColumns: Bool

    var body: some View {
        HStack(spacing: ActiveConnectionRow.columnSpacing) {
            Text("目标与路由").frame(maxWidth: .infinity, alignment: .leading)
            if showsTrafficColumns {
                Text("↑ 上传").frame(width: ActiveConnectionRow.trafficColumnWidth, alignment: .trailing)
                Text("↓ 下载").frame(width: ActiveConnectionRow.trafficColumnWidth, alignment: .trailing)
            } else {
                Text("速率 / 累计")
            }
        }
        .font(DS.caption).foregroundStyle(DS.ink2)
        .padding(.horizontal, 20).padding(.vertical, 12)
    }
}

struct ActiveConnectionRow: View {
    static let columnBreakpoint: CGFloat = 620
    static let trafficColumnWidth: CGFloat = 104
    static let columnSpacing: CGFloat = 20

    let connection: ActiveConnection
    let rates: DisplayedRates
    let selected: Bool
    let showsTrafficColumns: Bool
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            Group {
                if showsTrafficColumns {
                    HStack(spacing: Self.columnSpacing) {
                        destination.frame(maxWidth: .infinity, alignment: .leading)
                        traffic(upload: true).frame(width: Self.trafficColumnWidth, alignment: .trailing)
                        traffic(upload: false).frame(width: Self.trafficColumnWidth, alignment: .trailing)
                    }
                } else {
                    VStack(alignment: .leading, spacing: 12) {
                        destination
                        HStack(spacing: Self.columnSpacing) {
                            traffic(upload: true).frame(maxWidth: .infinity, alignment: .leading)
                            traffic(upload: false).frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                }
            }
            .padding(.horizontal, 14).padding(.vertical, 12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(selected ? DS.accent.opacity(0.08) : hovering ? Color.primary.opacity(0.035) : .clear,
                        in: RoundedRectangle(cornerRadius: DS.smallRadius, style: .continuous))
            .overlay {
                if selected {
                    RoundedRectangle(cornerRadius: DS.smallRadius, style: .continuous)
                        .strokeBorder(DS.accent.opacity(0.3), lineWidth: 1)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .accessibilityAddTraits(selected ? .isSelected : [])
    }

    private var destination: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Text(connection.target).font(DS.label.weight(.medium))
                    .foregroundStyle(Color.primary).lineLimit(1).truncationMode(.middle)
                    .help(connection.target)
                Spacer(minLength: 0)
                OutboundTag(name: connection.outbound).frame(maxWidth: 140, alignment: .trailing)
                    .help(connection.outbound)
            }
            HStack(spacing: 6) {
                if let process = connection.process, !process.isEmpty {
                    Text(process).lineLimit(1).truncationMode(.middle)
                        .help(process)
                    Text("·").foregroundStyle(DS.ink3)
                }
                Text(connection.policyChain).lineLimit(1).truncationMode(.middle)
                    .help(connection.policyChain)
            }
            .font(DS.small).foregroundStyle(DS.ink2)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func traffic(upload: Bool) -> some View {
        let rate = upload ? rates.up : rates.down
        let bytes = formatBytes(Double(upload ? connection.up : connection.down))
        let title = upload ? "上传" : "下载"
        return VStack(alignment: showsTrafficColumns ? .trailing : .leading, spacing: 4) {
            HStack(spacing: 4) {
                if !showsTrafficColumns { Text(upload ? "↑" : "↓") }
                Text(rate.formatted.text)
            }
            .font(DS.small.weight(.medium).monospacedDigit())
            .foregroundStyle(upload ? DS.ink2 : DS.accent)
            Text("\(bytes) 累计").font(DS.caption.monospacedDigit()).foregroundStyle(DS.ink3)
        }
        .fixedSize()
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(title)，速率 \(rate.formatted.text)，累计 \(bytes)")
    }
}
