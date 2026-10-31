import AppKit
import SwiftUI

/// Only display metadata is extracted; passwords and subscription tokens stay out of the UI.
struct NodeRecord: Identifiable {
    let id: String
    let name: String
    let kind: String
    let endpoint: String
    let transport: String
    let filter: String
    let interval: String
    let isSubscription: Bool
    let section: String
    let reference: String
    let importsGroups: Bool
    var displayName: String { subscriptionNodeLabel(reference) }
    var canDelete: Bool { section != "Imported" }

    var copyableEndpoint: String? { isSubscription ? nil : endpoint }

    init(line: String, id: String, section: String? = nil) {
        self.id = id
        let pair = line.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
        name = pair.first ?? line
        reference = name
        let body = (section == "Subscription" ? "select, " : "") + (pair.count > 1 ? pair[1] : "")
        var quoted = false
        let parts = body.split { c in
            if c == "\"" { quoted.toggle() }
            return c == "," && !quoted
        }.map { $0.trimmingCharacters(in: .whitespaces) }
        var parameters: [String: String] = [:]
        for part in parts.dropFirst() {
            let kv = part.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            if kv.count == 2 { parameters[kv[0].lowercased()] = kv[1].trimmingCharacters(in: CharacterSet(charactersIn: "\"'")) }
        }
        isSubscription = parameters["policy-path"] != nil
        importsGroups = parameters["import-groups"].map { $0 == "true" } ?? (section == "Subscription")
        self.section = section ?? (isSubscription ? "Proxy Group" : "Proxy")
        kind = isSubscription ? "订阅" : (parts.first ?? "未知").uppercased()
        if let source = parameters["policy-path"] {
            endpoint = URL(string: source)?.host ?? "本地订阅文件"
        } else {
            let host = parts.count > 1 ? parts[1] : ""
            let port = parts.count > 2 ? parts[2] : ""
            endpoint = host.contains(":") && !host.hasPrefix("[") ? "[\(host)]:\(port)" : "\(host):\(port)"
        }
        let layer = parameters["grpc"] == "true" ? "gRPC" : parameters["ws"] == "true" ? "WebSocket" : "TCP"
        transport = ["hysteria2", "hy2"].contains(parts.first?.lowercased() ?? "") ? "QUIC / TLS" :
            layer + (parameters["reality-public-key"] != nil ? " / REALITY" : parameters["tls"] == "true" || kind == "TROJAN" ? " / TLS" : "")
        filter = parameters["policy-regex-filter"] ?? "不过滤"
        interval = humanInterval(Int(parameters["update-interval"] ?? "") ?? 86400)
    }

    init(subscription node: SubscriptionNode) {
        id = node.id; reference = node.id; name = node.name
        kind = node.kind?.uppercased() ?? "订阅节点"
        if let server = node.server, let port = node.port {
            endpoint = "\(server.contains(":") ? "[\(server)]" : server):\(port)"
        } else { endpoint = node.source }
        transport = node.source; filter = ""; interval = ""
        isSubscription = false; section = "Imported"
        importsGroups = false
    }

    func matches(_ query: String) -> Bool {
        query.isEmpty || [name, displayName, kind, endpoint, transport].contains { $0.localizedCaseInsensitiveContains(query) }
    }
}

struct NodesView: View {
    @EnvironmentObject var core: Core
    @Binding var intent: NodesIntent?
    @State private var showAddNode = false
    @State private var showAddSub = false
    @State private var records: [NodeRecord] = []
    @State private var loaded = false
    @State private var loadError: String?
    @State private var search = ""
    @State private var category = 0
    @State private var selected: NodeRecord?

    var body: some View {
        let query = search.trimmingCharacters(in: .whitespacesAndNewlines)
        let allRecords = records + core.catalogNodes.map(NodeRecord.init(subscription:))
        let visible = allRecords.filter { $0.matches(query) && (category == 0 || $0.isSubscription == (category == 2)) }
        VStack(spacing: 0) {
            PaneHeader(title: "节点", subtitle: "\(allRecords.filter { !$0.isSubscription }.count) 个节点 · \(records.filter(\.isSubscription).count) 个订阅") {
                Button { refresh() } label: { Label("刷新列表", systemImage: "arrow.clockwise") }.labelStyle(.iconOnly)
                Button { core.testNodes(allRecords.filter { !$0.isSubscription }.map(\.reference)) } label: {
                    Label(core.testingNodes.isEmpty ? "测试全部" : "测试中…", systemImage: "speedometer")
                }.disabled(!core.canTestNodes || allRecords.allSatisfy(\.isSubscription) || !core.testingNodes.isEmpty || !core.testingGroups.isEmpty)
                Button { showAddNode = true } label: { Label("添加节点", systemImage: "plus") }
                Button { showAddSub = true } label: { Label("添加订阅", systemImage: "link.badge.plus") }.glassButton(prominent: true)
            }
            HStack(spacing: 12) {
                GlassSegmented(options: [(0, "全部", nil), (1, "节点", nil), (2, "订阅", nil)], selection: $category)
                    .frame(width: 220)
                Spacer(minLength: 8)
                Text("\(visible.count) 项").font(DS.caption.monospacedDigit()).foregroundStyle(DS.ink2)
                SearchField(prompt: "名称、协议或服务器", text: $search)
            }
            .padding(.horizontal, DS.gutter).padding(.bottom, 12)
            if core.loadingCatalog { ProgressView("正在读取订阅节点…").font(DS.small).padding(.bottom, 8) }
            if let loadError = loadError ?? core.catalogError {
                ErrorText(raw: loadError).padding(.horizontal, DS.gutter).padding(.bottom, 12)
            }
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(visible) { node in
                        Button { selected = node } label: {
                            NodeBrowserRow(node: node, latency: latency(for: node), testing: core.isTesting(node: node.reference))
                        }
                        .buttonStyle(.plain)
                        .overlay {
                            RowContextMenu { [node, core, selected = $selected] in
                                let menu = RowContextMenu.Menu()
                                menu.addAction("查看详情") { selected.wrappedValue = node }
                                let testing = core.isTesting(node: node.reference)
                                menu.addAction(testing ? "测试中…" : "测试节点", isEnabled: !node.isSubscription && core.canTestNodes && !testing) {
                                    core.test(node: node.reference)
                                }
                                menu.addAction("复制名称") { copyText(node.name) }
                                if let endpoint = node.copyableEndpoint {
                                    menu.addAction("复制服务器") { copyText(endpoint) }
                                }
                                return menu
                            }
                        }
                        if node.id != visible.last?.id { Divider().padding(.leading, 60) }
                    }
                }
                .glass()
                .padding(.horizontal, DS.gutter)
            }
            .overlay {
                if !loaded && loadError == nil {
                    ProgressView("正在加载节点…").font(DS.small)
                } else if loaded && records.isEmpty {
                    EmptyState(icon: "globe.asia.australia", title: "尚未添加代理节点", detail: "添加订阅批量导入节点，或粘贴单个分享链接。",
                               action: ("添加订阅", { showAddSub = true }), secondary: ("添加节点", { showAddNode = true }))
                } else if visible.isEmpty {
                    EmptyState(icon: "magnifyingglass", title: "没有匹配的节点", detail: "试试其他名称、协议或服务器地址。",
                               action: ("清除筛选", { search = ""; category = 0 }))
                }
            }
            Text("无需启动代理即可查看和测试节点 · 订阅节点随来源更新")
                .font(DS.caption).foregroundStyle(DS.ink3).padding(12)
        }
        .sheet(isPresented: $showAddNode, onDismiss: refresh) { AddNodeSheet() }
        .sheet(isPresented: $showAddSub, onDismiss: refresh) { AddSubscriptionSheet() }
        .sheet(item: $selected) { NodeDetailSheet(node: $0, latency: latency(for: $0), changed: refresh) }
        .onAppear {
            refresh()
            switch intent {
            case .node: showAddNode = true
            case .subscription: showAddSub = true
            case nil: break
            }
            intent = nil
        }
        .onChange(of: core.configPath) { refresh() }
        .onChange(of: core.summary.proxyCount) { refresh() }
        .onChange(of: core.summary.subscriptionCount) { refresh() }
        .onChange(of: core.reloading) { _, busy in if !busy { refresh() } }
    }

    private func latency(for node: NodeRecord) -> Int? {
        core.nodeLatencies[node.reference] ?? core.groups.lazy.flatMap(\.options).first { $0.name == node.reference && $0.latencyMs != nil }?.latencyMs
    }

    private func refresh() {
        let text: String
        do { text = try String(contentsOfFile: core.configPath, encoding: .utf8) }
        catch {
            loadError = "无法读取节点列表：\(error.localizedDescription)"
            return
        }
        loaded = true
        loadError = nil
        records = ["Subscription", "Proxy Group", "Proxy"].flatMap { section in
            ConfigText.lines(of: section, in: text).compactMap { line in
                let name = line.split(separator: "=", maxSplits: 1).first.map { $0.trimmingCharacters(in: .whitespaces) } ?? line
                let node = NodeRecord(line: line, id: "\(section):\(name)", section: section)
                return section == "Proxy" || node.isSubscription ? node : nil
            }
        }
        core.refreshSummary()
        Task { await core.loadNodeCatalog() }
    }
}

struct NodeBrowserRow: View {
    let node: NodeRecord
    let latency: Int?
    var testing = false
    @State private var hovering = false

    var body: some View {
        HStack(spacing: 12) {
            IconTile(symbol: node.isSubscription ? "link" : "server.rack", size: 28)
            VStack(alignment: .leading, spacing: 3) {
                Text(node.displayName).font(DS.label.weight(.medium)).foregroundStyle(Color.primary).lineLimit(1)
                Text(node.endpoint).font(DS.small).foregroundStyle(DS.ink2).lineLimit(1).truncationMode(.middle)
            }
            Spacer(minLength: 8)
            // Protocol and latency sit in fixed columns so badges line up down the list.
            Text(node.kind).font(DS.caption).foregroundStyle(DS.ink2).lineLimit(1)
                .padding(.horizontal, 8).frame(height: 22).background(Color.primary.opacity(0.045), in: Capsule())
                .frame(width: 96, alignment: .trailing)
            if !node.isSubscription { LatencyBadge(latency: latency, testing: testing) }
            Image(systemName: "chevron.right").font(DS.caption).foregroundStyle(DS.ink3)
        }
        .padding(.horizontal, DS.cardPadding).padding(.vertical, 14)
        .background(hovering ? Color.primary.opacity(0.035) : .clear)
        .contentShape(Rectangle())
        .onHover { hovering = $0 }
        .accessibilityElement(children: .combine)
        .help("查看 \(node.name) 的详情")
    }
}

struct NodeDetailSheet: View {
    @EnvironmentObject var core: Core
    @Environment(\.dismiss) private var dismiss
    let node: NodeRecord
    let latency: Int?
    var changed: () -> Void = {}
    @State private var confirmDelete = false
    @State private var working = false
    @State private var error: String?
    @State private var requestedImportGroups: Bool?

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            SheetHeader(icon: node.isSubscription ? "link" : "server.rack", title: node.displayName,
                        detail: node.isSubscription ? "订阅信息" : "节点连接信息")
            VStack(spacing: 12) {
                row("类型", node.kind)
                row("服务器", node.endpoint)
                if node.isSubscription {
                    row("名称过滤", node.filter)
                    row("更新间隔", node.interval)
                    Toggle("导入订阅自带的策略组", isOn: Binding(get: { requestedImportGroups ?? node.importsGroups }, set: { on in
                        requestedImportGroups = on; working = true
                        Task {
                            let text = core.readConfig()
                            error = await core.saveConfig(ConfigText.setImportGroups(on, source: node.name, section: node.section, in: text), expected: text)
                            working = false
                            if error == nil { changed() } else { requestedImportGroups = nil }
                        }
                    })).disabled(working)
                } else {
                    row(node.canDelete ? "传输方式" : "来源", node.transport)
                    HStack {
                        Text("最近延迟").font(DS.label).foregroundStyle(DS.ink2)
                        Spacer(minLength: 16)
                        LatencyBadge(latency: core.nodeLatencies[node.reference] ?? latency, testing: core.isTesting(node: node.reference))
                    }
                }
                if let result = core.nodeTests[node.reference] {
                    row("连接耗时", result.connectMs.map { "\($0) ms" } ?? "—")
                    row("响应延迟", result.latencyMs.map { "\($0) ms" } ?? "—")
                    if let outbound = result.outbound { row("实际出站", outbound) }
                    if let status = result.status { row("HTTP 状态", String(status)) }
                    if let error = result.error {
                        Text(error).font(DS.small).foregroundStyle(DS.fail).textSelection(.enabled)
                    }
                }
            }
            .padding(DS.cardPadding).glass()
            Text(node.isSubscription ? "订阅完整地址和凭据可在配置页编辑。" : node.canDelete ? "连接参数可在配置页编辑，节点切换请前往策略页。" : "此节点由订阅管理，参数随订阅更新。无需启动代理服务即可测速。")
                .font(DS.small).foregroundStyle(DS.ink2)
            if let error { Text(error).font(DS.small).foregroundStyle(DS.fail).textSelection(.enabled) }
            HStack {
                if node.canDelete {
                    Button(role: .destructive) { confirmDelete = true } label: { Label("删除", systemImage: "trash") }
                        .glassButton().disabled(working)
                }
                if node.isSubscription {
                    Button {
                        if core.state == .running { core.reload() }
                        Task { await core.loadNodeCatalog(); changed() }
                    } label: { Label("刷新节点", systemImage: "arrow.triangle.2.circlepath") }
                        .glassButton().disabled(core.loadingCatalog || core.reloading)
                        .help("重新下载订阅并重载配置")
                } else {
                    if let endpoint = node.copyableEndpoint {
                        Button("复制服务器") { copyText(endpoint) }.glassButton()
                    }
                    Button(core.isTesting(node: node.reference) ? "测试中…" : "测试节点") { core.test(node: node.reference) }
                        .glassButton().disabled(!core.canTestNodes || core.isTesting(node: node.reference))
                }
                Spacer()
                Button("完成") { dismiss() }.keyboardShortcut(.cancelAction).glassButton(prominent: true)
            }
        }
        .padding(24).frame(width: 480)
        .confirmationDialog(node.isSubscription ? "删除订阅「\(node.name)」？" : "删除节点「\(node.name)」？",
                            isPresented: $confirmDelete, titleVisibility: .visible) {
            Button(node.isSubscription ? "删除订阅" : "删除节点", role: .destructive) {
                working = true
                Task {
                    error = await core.removeEntry(node.name, isSubscription: node.isSubscription)
                    working = false
                    if error == nil { changed(); dismiss() }
                }
            }
            Button("取消", role: .cancel) {}
        } message: {
            Text("会同时从所有策略组中移除它，并立即保存配置。")
        }
    }

    private func row(_ title: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(title).foregroundStyle(DS.ink2)
            Spacer(minLength: 16)
            Text(value).monospacedDigit().multilineTextAlignment(.trailing).textSelection(.enabled)
        }.font(DS.label)
    }
}

func copyText(_ value: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(value, forType: .string)
}

/// "24 小时", "30 分钟", "45 秒".
func humanInterval(_ seconds: Int) -> String {
    if seconds >= 3600, seconds % 3600 == 0 { return "\(seconds / 3600) 小时" }
    if seconds >= 60, seconds % 60 == 0 { return "\(seconds / 60) 分钟" }
    return "\(seconds) 秒"
}
