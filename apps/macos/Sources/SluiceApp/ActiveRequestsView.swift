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
                HStack(spacing: 12) { filters; actions }
                VStack(alignment: .leading, spacing: 12) {
                    filters
                    HStack { Spacer(); actions }
                }
            }
            if let error = core.activeConnectionsError {
                Text(error).font(DS.small).foregroundStyle(DS.warn)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            HStack(alignment: .top, spacing: DS.gap) {
                ScrollView {
                    LazyVStack(spacing: 2) {
                        ForEach(rows) { connection in
                            Button { selection = connection.id } label: {
                                activeRow(connection)
                                    .padding(12)
                                    .background(selection == connection.id ? DS.accent.opacity(0.08) : .clear,
                                                in: RoundedRectangle(cornerRadius: DS.smallRadius))
                            }
                            .buttonStyle(.plain)
                            .contextMenu {
                                Button("复制目标") { copyText(connection.target) }
                                Button("复制策略链") { copyText(connection.policyChain) }
                                Divider()
                                Button("断开连接", role: .destructive) { core.closeConnection(connection.id) }
                                    .disabled(!canClose(connection.id))
                            }
                        }
                    }.padding(6)
                }
                .overlay {
                    if rows.isEmpty {
                        if core.state != .running {
                            EmptyState(icon: "arrow.up.arrow.down", title: "Sluice 未运行",
                                       detail: "启动后可查看活动 TCP 连接。", action: ("启动 Sluice", { core.start() }))
                        } else if !core.activeConnectionsLoaded {
                            if let error = core.activeConnectionsError {
                                EmptyState(icon: "exclamationmark.triangle", title: "无法读取活动连接", detail: error)
                            } else {
                                ProgressView("正在加载活动连接…").font(DS.small)
                            }
                        } else if !filter.isEmpty || kind != .all {
                            EmptyState(icon: "magnifyingglass", title: "没有匹配的活动连接", detail: "清除筛选查看全部连接。",
                                       action: ("清除筛选", { filter = ""; kind = .all }))
                        } else {
                            EmptyState(icon: "arrow.up.arrow.down", title: "没有活动连接", detail: "连接建立后会显示在这里；UDP 不在此列表中。")
                        }
                    }
                }
                .frame(minWidth: 260, maxWidth: .infinity, maxHeight: .infinity).glass()
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
            Text("所有当前打开的 TCP 连接都会断开，正在传输的请求可能中断。")
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

    private func activeRow(_ connection: ActiveConnection) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Text(connection.target).font(DS.label.weight(.medium)).lineLimit(1).truncationMode(.middle)
                Spacer(minLength: 4)
                OutboundTag(name: connection.outbound)
            }
            Text(connection.policyChain).font(DS.small).foregroundStyle(DS.ink2).lineLimit(2)
            if let process = connection.process { Text(process).font(DS.caption).foregroundStyle(DS.ink3) }
            ViewThatFits(in: .horizontal) {
                HStack(spacing: 12) {
                    connectionRate(connection, upload: true)
                    Spacer(minLength: 8)
                    connectionRate(connection, upload: false)
                }
                VStack(alignment: .leading, spacing: 4) {
                    connectionRate(connection, upload: true)
                    connectionRate(connection, upload: false)
                }
            }
            .font(DS.caption.monospacedDigit())
            .foregroundStyle(DS.ink2)
        }
    }

    private func displayedRates(for id: UInt64) -> DisplayedRates {
        (paused ? frozenRates[id] : core.displayedConnectionRates[id]) ?? DisplayedRates()
    }

    private func connectionRate(_ connection: ActiveConnection, upload: Bool) -> some View {
        let rates = displayedRates(for: connection.id)
        let bytes = upload ? connection.up : connection.down
        let rate = upload ? rates.up : rates.down
        return HStack(spacing: 4) {
            Text(upload ? "↑" : "↓")
            Text(formatBytes(Double(bytes))).frame(width: 68, alignment: .trailing)
            Text(rate.formatted.text).frame(width: 88, alignment: .trailing)
        }
        .foregroundStyle(upload ? DS.ink2 : DS.accent)
        .fixedSize()
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
