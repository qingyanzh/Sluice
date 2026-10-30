import SwiftUI

struct DNSView: View {
    @EnvironmentObject private var core: Core
    @State private var search = ""
    @State private var entries: [DNSCacheEntry] = []
    @State private var loaded = false
    @State private var working = false
    @State private var loadError: String?
    @State private var feedback: String?
    @State private var flushFailed = false
    @State private var flushRequested = false
    @State private var requestID = UUID()

    /// Changing the pane's API, running state, or action cancels the previous request loop.
    private struct RefreshContext: Equatable {
        let running: Bool
        let port: Int?
        let requestID: UUID
    }

    var body: some View {
        let query = search.trimmingCharacters(in: .whitespacesAndNewlines)
        let rows = entries.filter { $0.matches(query) }.sorted {
            ($0.name, $0.type) < ($1.name, $1.type)
        }
        VStack(spacing: 0) {
            PaneHeader(title: Pane.dns.title, subtitle: Pane.dns.subtitle) {
                SearchField(prompt: "域名、类型或解析结果", text: $search)
                Button { requestID = UUID() } label: {
                    Label("刷新", systemImage: "arrow.clockwise")
                }
                .labelStyle(.iconOnly).help("刷新 DNS 缓存")
                .disabled(core.state != .running || working)
                Button {
                    flushRequested = true
                    requestID = UUID()
                } label: {
                    Label("清空缓存", systemImage: "trash")
                }
                .disabled(core.state != .running || working)
            }
            if let loadError, !entries.isEmpty {
                ErrorText(raw: loadError)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, DS.gutter).padding(.bottom, 12)
            }
            Table(rows) {
                TableColumn("域名") { entry in
                    Text(entry.name).font(DS.label).textSelection(.enabled).help(entry.name)
                        .contextMenu { Button("复制域名") { copyText(entry.name) } }
                }
                .width(min: 160, ideal: 240)
                TableColumn("类型") { entry in
                    Text(entry.type).font(DS.caption.monospaced()).foregroundStyle(DS.ink2)
                }
                .width(60)
                TableColumn("解析结果") { entry in
                    let answers = entry.answers.joined(separator: ", ")
                    Text(answers).font(DS.label).textSelection(.enabled).help(answers)
                        .contextMenu { Button("复制解析结果") { copyText(answers) } }
                }
                .width(min: 160, ideal: 300)
                TableColumn("剩余 TTL") { entry in
                    Text("\(entry.ttl) 秒").font(DS.small.monospacedDigit()).foregroundStyle(DS.ink2)
                        .frame(width: 80, alignment: .trailing)
                }
                .width(min: 85, ideal: 100)
            }
            .scrollContentBackground(.hidden)
            .overlay {
                if core.state != .running {
                    if core.state == .starting {
                        EmptyState(icon: "network", title: "Sluice 启动中", detail: "内核运行后会自动加载 DNS 缓存。")
                    } else {
                        EmptyState(icon: "network", title: "Sluice 未运行",
                                   detail: "启动后可查看和清空 DNS 缓存。",
                                   action: ("启动 Sluice", { core.start() }))
                    }
                } else if !loaded && loadError == nil {
                    ProgressView("正在加载 DNS 缓存…").font(DS.small)
                } else if rows.isEmpty {
                    if let loadError {
                        EmptyState(icon: "exclamationmark.triangle", title: "无法读取 DNS 缓存",
                                   detail: loadError, action: ("重试", { requestID = UUID() }))
                    } else if !query.isEmpty {
                        EmptyState(icon: "magnifyingglass", title: "没有匹配的缓存",
                                   detail: "试试其他域名、类型或解析结果。", action: ("清除筛选", { search = "" }))
                    } else {
                        EmptyState(icon: "network", title: "暂无 DNS 缓存",
                                   detail: "域名解析后，缓存记录会自动显示在这里。",
                                   action: ("刷新", { requestID = UUID() }))
                    }
                }
            }
            .glass()
            .padding(.horizontal, DS.gutter)
            HStack(spacing: 8) {
                if let feedback {
                    Label(feedback, systemImage: flushFailed ? "exclamationmark.triangle" : "checkmark.circle")
                        .foregroundStyle(flushFailed ? DS.fail : DS.ok)
                } else {
                    Text("显示 \(rows.count) / \(entries.count) 条缓存")
                }
                Spacer(minLength: 12)
                Text(core.state == .running ? "每秒自动刷新" : "内核停止时暂停刷新")
            }
            .font(DS.caption).monospacedDigit().foregroundStyle(DS.ink2)
            .padding(.horizontal, DS.gutter).padding(.vertical, 12)
        }
        .task(id: RefreshContext(running: core.state == .running, port: core.summary.apiPort, requestID: requestID)) {
            await poll()
        }
    }

    @MainActor
    private func poll() async {
        working = false
        guard core.state == .running, let api = core.api else {
            entries = []
            loaded = false
            loadError = core.state == .running ? "未配置控制 API" : nil
            feedback = nil
            flushRequested = false
            return
        }
        working = true
        if flushRequested {
            flushRequested = false
            feedback = nil
            do {
                let result = try await api.flushDNS()
                guard !Task.isCancelled else { return }
                // Keep the visible snapshot until the next successful read.
                feedback = "已清空 \(result.flushed) 条缓存"
                flushFailed = false
            } catch {
                guard !Task.isCancelled else { return }
                feedback = "清空缓存失败：\(error.localizedDescription)"
                flushFailed = true
            }
        }
        while !Task.isCancelled {
            do {
                let cache = try await api.dns()
                guard !Task.isCancelled else { return }
                entries = cache.entries
                loaded = true
                loadError = nil
            } catch {
                guard !Task.isCancelled else { return }
                loadError = "读取 DNS 缓存失败：\(error.localizedDescription)"
            }
            working = false
            do { try await Task.sleep(for: .seconds(1)) }
            catch { return }
        }
    }
}
