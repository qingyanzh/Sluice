import AppKit
import SwiftUI
import UserNotifications

// MARK: - Model

/// A node change the core reported for one source, shown until dismissed.
struct SubscriptionNotice: Identifiable, Hashable {
    let source: String
    let change: SubscriptionStatus.Change
    var id: String { "\(source)|\(change.at)" }

    /// "新增 3 个节点，移除 1 个节点"
    var summary: String {
        var parts: [String] = []
        if !change.added.isEmpty { parts.append("新增 \(change.added.count) 个节点") }
        if !change.removed.isEmpty { parts.append("移除 \(change.removed.count) 个节点") }
        return parts.joined(separator: "，")
    }
}

/// A `[Subscription]` line (or a legacy `policy-path` group) joined with its fetch status.
struct SubscriptionSource: Identifiable {
    let name: String
    let url: String
    let filter: String
    let userAgent: String
    let intervalSeconds: Int
    /// Legacy `Group = select, policy-path=…` sources are read-only here.
    let isLegacy: Bool
    var status: SubscriptionStatus?
    var id: String { name }
    var host: String { URL(string: url)?.host ?? "本地文件" }

    /// Every source in the config, in file order.
    static func all(in text: String, statuses: [SubscriptionStatus]) -> [SubscriptionSource] {
        let independent = ConfigText.lines(of: "Subscription", in: text).compactMap { parse($0, legacy: false) }
        let legacy = ConfigText.lines(of: "Proxy Group", in: text).compactMap { parse($0, legacy: true) }
        return (independent + legacy).map { source in
            var source = source
            source.status = statuses.first { $0.group == source.name }
            return source
        }
    }

    private static func parse(_ line: String, legacy: Bool) -> SubscriptionSource? {
        guard let eq = line.firstIndex(of: "=") else { return nil }
        let name = StructuredConfig.trim(String(line[..<eq]))
        var quoted = false
        let parts = line[line.index(after: eq)...].split {
            if $0 == "\"" { quoted.toggle() }
            return $0 == "," && !quoted
        }.map { StructuredConfig.trim(String($0)) }
        var values: [String: String] = [:]
        for part in parts {
            guard let split = part.firstIndex(of: "=") else { continue }
            let key = StructuredConfig.trim(String(part[..<split])).lowercased()
            values[key] = StructuredConfig.trim(String(part[part.index(after: split)...])).trimmingCharacters(in: CharacterSet(charactersIn: "\""))
        }
        guard let url = values["policy-path"], !name.isEmpty else { return nil }
        return SubscriptionSource(name: name, url: url, filter: values["policy-regex-filter"] ?? "",
                                  userAgent: values["user-agent"] ?? "",
                                  intervalSeconds: Int(values["update-interval"] ?? "") ?? 86400, isLegacy: legacy)
    }

    /// The `[Subscription]` line for these settings.
    func line(url: String, filter: String, userAgent: String, intervalHours: Int) -> String {
        var line = "\(name) = policy-path=\"\(url)\", update-interval=\(max(1, intervalHours) * 3600)"
        if !filter.isEmpty { line += ", policy-regex-filter=\"\(filter)\"" }
        if !userAgent.isEmpty { line += ", user-agent=\"\(userAgent)\"" }
        return line
    }
}

/// Posts a macOS notification, asking for permission the first time.
enum SystemNotice {
    static func post(title: String, body: String) {
        guard Bundle.main.bundleIdentifier != nil else { return }
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert, .sound]) { granted, _ in
            guard granted else { return }
            let content = UNMutableNotificationContent()
            content.title = title
            content.body = body
            center.add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil))
        }
    }
}

enum SubscriptionFormat {
    static func bytes(_ value: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(clamping: value), countStyle: .binary)
    }

    /// "2026-12-01 · 剩余 31 天", "已过期".
    static func expiry(_ date: Date, now: Date = Date()) -> String {
        let day = date.formatted(.dateTime.year().month(.twoDigits).day(.twoDigits))
        let days = Calendar.current.dateComponents([.day], from: Calendar.current.startOfDay(for: now), to: Calendar.current.startOfDay(for: date)).day ?? 0
        if days < 0 { return "\(day) · 已过期" }
        return days == 0 ? "\(day) · 今天到期" : "\(day) · 剩余 \(days) 天"
    }

    static func relative(_ date: Date) -> String {
        date.formatted(.relative(presentation: .named, unitsStyle: .abbreviated))
    }
}

// MARK: - Page

struct SubscriptionsView: View {
    @EnvironmentObject var core: Core
    @State private var text = ""
    @State private var adding = false
    @State private var editing: SubscriptionSource?
    @State private var deleting: SubscriptionSource?
    @State private var error: String?

    private var sources: [SubscriptionSource] { SubscriptionSource.all(in: text, statuses: core.subscriptions) }

    var body: some View {
        let sources = sources
        let nodeCount = sources.compactMap(\.status?.nodeCount).reduce(0, +)
        VStack(spacing: 0) {
            PaneHeader(title: "订阅", subtitle: sources.isEmpty ? "尚未添加订阅" : "\(sources.count) 个订阅 · \(nodeCount) 个节点") {
                Button { update() } label: {
                    Label(core.updatingSubscriptions ? "正在更新…" : "全部更新", systemImage: "arrow.triangle.2.circlepath")
                }.disabled(sources.isEmpty || core.updatingSubscriptions || !core.canChangeProfile)
                Button { adding = true } label: { Label("添加订阅", systemImage: "plus") }.glassButton(prominent: true)
            }
            ScrollView {
                VStack(alignment: .leading, spacing: DS.gap) {
                    if !sources.isEmpty {
                        GuideStrip(icon: "info.circle", text: "订阅只提供节点，并按设定间隔自动更新；要决定流量使用哪些节点，请在「策略」页编写策略组",
                                   action: ("前往策略", { core.requestedPane = .policy }))
                    }
                    if let error { ErrorText(raw: error).transition(.opacity) }
                    ForEach(core.subscriptionNotices) { notice in
                        SubscriptionNoticeBanner(notice: notice) { withAnimation(DS.spring) { core.dismissSubscriptionNotice(notice) } }
                            .transition(.move(edge: .top).combined(with: .opacity))
                    }
                    ForEach(Array(sources.enumerated()), id: \.element.id) { index, source in
                        SubscriptionCard(source: source, edit: { editing = source }, delete: { deleting = source })
                            .modifier(Entrance(index: index))
                    }
                }
                .padding(.horizontal, DS.gutter).padding(.bottom, DS.gutter)
                .animation(DS.spring, value: core.subscriptionNotices)
            }
            .overlay {
                if sources.isEmpty {
                    EmptyState(icon: "link.badge.plus", title: "尚未添加订阅", detail: "订阅只导入节点，以及流量和到期信息",
                               action: ("添加订阅", { adding = true }))
                }
            }
        }
        .sheet(isPresented: $adding, onDismiss: refresh) { AddSubscriptionSheet() }
        .sheet(item: $editing, onDismiss: refresh) { SubscriptionEditSheet(source: $0) }
        .confirmationDialog("删除订阅「\(deleting?.name ?? "")」？", isPresented: Binding(get: { deleting != nil }, set: { if !$0 { deleting = nil } }),
                            titleVisibility: .visible) {
            Button("删除订阅", role: .destructive) {
                guard let source = deleting else { return }
                Task {
                    error = await core.removeEntry(source.name, isSubscription: true)
                    refresh()
                }
            }
            Button("取消", role: .cancel) {}
        } message: { Text("它的节点会从所有策略组中移除，并立即保存配置") }
        .onAppear(perform: refresh)
        .onChange(of: core.configPath) { refresh() }
        .onChange(of: core.reloading) { _, busy in if !busy { refresh() } }
    }

    private func refresh() {
        text = core.readConfig()
        Task { await core.loadNodeCatalog() }
    }

    private func update() {
        Task {
            withAnimation(DS.spring) { error = nil }
            let failure = await core.updateSubscriptions()
            withAnimation(DS.spring) { error = failure }
            refresh()
        }
    }
}

private struct SubscriptionNoticeBanner: View {
    let notice: SubscriptionNotice
    let dismiss: () -> Void
    @State private var expanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Image(systemName: "bell.badge").foregroundStyle(DS.accent)
                Text("「\(notice.source)」已更新：\(notice.summary)").font(DS.label.weight(.medium))
                Text(SubscriptionFormat.relative(Date(timeIntervalSince1970: TimeInterval(notice.change.at))))
                    .font(DS.caption).foregroundStyle(DS.ink3)
                Spacer(minLength: 8)
                Button(expanded ? "收起" : "查看变动") { withAnimation(DS.spring) { expanded.toggle() } }
                    .buttonStyle(.link).font(DS.small)
                Button(action: dismiss) { Image(systemName: "xmark") }.buttonStyle(.borderless).help("关闭提示")
            }
            if expanded {
                HStack(alignment: .top, spacing: 24) {
                    changeList("新增", notice.change.added, tone: DS.ok)
                    changeList("移除", notice.change.removed, tone: DS.fail)
                }.transition(.opacity)
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
        .background(DS.accentWash, in: RoundedRectangle(cornerRadius: DS.radius, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: DS.radius, style: .continuous).strokeBorder(DS.accent.opacity(0.25), lineWidth: 0.5))
    }

    @ViewBuilder private func changeList(_ title: String, _ names: [String], tone: Color) -> some View {
        if !names.isEmpty {
            VStack(alignment: .leading, spacing: 4) {
                Text("\(title) \(names.count)").font(DS.caption).foregroundStyle(tone)
                ForEach(names.prefix(8), id: \.self) { Text($0).font(DS.small).lineLimit(1) }
                if names.count > 8 { Text("等 \(names.count) 个").font(DS.small).foregroundStyle(DS.ink3) }
            }
        }
    }
}

private struct SubscriptionCard: View {
    @EnvironmentObject var core: Core
    let source: SubscriptionSource
    let edit: () -> Void
    let delete: () -> Void
    @State private var hovering = false

    /// One state, one colour: failure red, attention orange, healthy green.
    private var health: (String, Color) {
        guard let status = source.status else { return ("等待更新", DS.off) }
        if status.lastError != nil { return ("更新失败", DS.fail) }
        if let date = status.expiryDate, date < Date() { return ("已过期", DS.fail) }
        if let fraction = status.usedFraction, fraction >= 1 { return ("流量已用完", DS.fail) }
        if let date = status.expiryDate, date.timeIntervalSinceNow < 7 * 86400 { return ("即将到期", DS.warn) }
        if let fraction = status.usedFraction, fraction > 0.9 { return ("流量即将用完", DS.warn) }
        return ("正常", DS.ok)
    }

    var body: some View {
        let status = source.status
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                IconTile(symbol: "link", on: true, size: 32, tone: health.1 == DS.ok ? DS.accent : health.1)
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 8) {
                        Text(source.name).font(DS.heading).lineLimit(1)
                        StatusBadge(text: health.0, tone: health.1)
                    }
                    Text(source.host).font(DS.small).foregroundStyle(DS.ink2).lineLimit(1).truncationMode(.middle)
                }
                Spacer(minLength: 12)
                Button("编辑", action: edit).glassButton().disabled(source.isLegacy)
                    .help(source.isLegacy ? "旧式订阅请在配置文本中修改" : "修改地址、过滤条件和更新间隔")
                menu
            }
            Grid(horizontalSpacing: 12) { GridRow {
                trafficTile(status).gridCellColumns(1)
                tile("到期时间", value: status?.expiryDate.map { $0.formatted(.dateTime.year().month(.twoDigits).day(.twoDigits)) } ?? "未提供",
                     note: status?.expiryDate.map(daysLeft) ?? "服务商未提供到期信息",
                     tone: expiryTone(status?.expiryDate))
                tile("节点", value: status.map { "\($0.nodeCount) 个" } ?? "—",
                     note: source.filter.isEmpty ? "未设置过滤" : "按「\(source.filter)」过滤")
                tile("自动更新", value: "每 \(humanInterval(source.intervalSeconds))",
                     note: status?.lastFetchDate.map { "上次 " + SubscriptionFormat.relative($0) } ?? "尚未下载")
            } }
            if let raw = status?.lastError {
                let error = FriendlyError.explain(raw)
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(DS.fail)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(error.headline).font(DS.small.weight(.medium))
                        Text((error.hint ?? "") + (status?.nodeCount ?? 0 > 0 ? "；当前继续使用上次下载的节点" : ""))
                            .font(DS.small).foregroundStyle(DS.ink2)
                    }
                    Spacer()
                    Button("复制详情") { copyText(raw) }.buttonStyle(.link).font(DS.small)
                }
                .padding(10)
                .background(DS.fail.opacity(0.06), in: RoundedRectangle(cornerRadius: DS.smallRadius, style: .continuous))
            }
        }
        .padding(DS.cardPadding)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .glass(highlighted: hovering)
        .animation(DS.spring, value: hovering)
        .onHover { hovering = $0 }
        .contextMenu {
            Button("编辑…", action: edit).disabled(source.isLegacy)
            Button("复制订阅地址") { copyText(source.url) }
            Button("删除订阅", role: .destructive, action: delete)
        }
    }

    private var menu: some View {
        Menu {
            Button("复制订阅地址") { copyText(source.url) }
            Divider()
            Button("删除订阅", role: .destructive, action: delete)
        } label: { Image(systemName: "ellipsis").frame(width: 28, height: 28) }
            .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
            .help("更多操作")
    }

    private func daysLeft(_ date: Date) -> String {
        let days = Calendar.current.dateComponents([.day], from: Calendar.current.startOfDay(for: Date()), to: Calendar.current.startOfDay(for: date)).day ?? 0
        return days < 0 ? "已过期 \(-days) 天" : days == 0 ? "今天到期" : "剩余 \(days) 天"
    }

    private func expiryTone(_ date: Date?) -> Color {
        guard let date else { return .primary }
        return date < Date() ? DS.fail : date.timeIntervalSinceNow < 7 * 86400 ? DS.warn : .primary
    }

    private func trafficTile(_ status: SubscriptionStatus?) -> some View {
        let fraction = status?.usedFraction
        let tone: Color = (fraction ?? 0) > 0.9 ? DS.fail : (fraction ?? 0) > 0.75 ? DS.warn : DS.accent
        return VStack(alignment: .leading, spacing: 6) {
            Text("已用流量").font(DS.caption).foregroundStyle(DS.ink3)
            Text(status?.used.map(SubscriptionFormat.bytes) ?? "未提供").font(DS.heading.monospacedDigit()).lineLimit(1)
            ProgressView(value: fraction ?? 0).progressViewStyle(.linear).tint(tone).opacity(fraction == nil ? 0.3 : 1)
            Text(status?.total.flatMap { $0 > 0 ? "共 \(SubscriptionFormat.bytes($0)) · \(Int(((fraction ?? 0) * 100).rounded()))%" : nil } ?? "服务商未提供总量")
                .font(DS.caption).foregroundStyle(DS.ink2).lineLimit(1)
        }
        .padding(12)
        .frame(maxWidth: .infinity, minHeight: 92, alignment: .topLeading)
        .background(DS.well, in: RoundedRectangle(cornerRadius: DS.smallRadius, style: .continuous))
    }

    private func tile(_ title: String, value: String, note: String, tone: Color = .primary) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(DS.caption).foregroundStyle(DS.ink3)
            Text(value).font(DS.heading.monospacedDigit()).foregroundStyle(tone).lineLimit(1).minimumScaleFactor(0.85)
            Spacer(minLength: 0)
            Text(note).font(DS.caption).foregroundStyle(DS.ink2).lineLimit(1).truncationMode(.tail)
        }
        .padding(12)
        .frame(maxWidth: .infinity, minHeight: 92, alignment: .topLeading)
        .background(DS.well, in: RoundedRectangle(cornerRadius: DS.smallRadius, style: .continuous))
    }
}

// MARK: - Sheets

struct SubscriptionIntervalPicker: View {
    @Binding var hours: Int
    static let choices = [1, 3, 6, 12, 24, 72, 168]
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("自动更新").font(DS.caption).foregroundStyle(DS.ink2)
            Picker("", selection: $hours) {
                ForEach(Self.choices.contains(hours) ? Self.choices : (Self.choices + [hours]).sorted(), id: \.self) { value in
                    Text(value % 24 == 0 ? "每 \(value / 24) 天" : "每 \(value) 小时").tag(value)
                }
            }
            .labelsHidden().frame(maxWidth: .infinity, minHeight: 34)
        }
    }
}

private struct SubscriptionEditSheet: View {
    @EnvironmentObject var core: Core
    @Environment(\.dismiss) private var dismiss
    let source: SubscriptionSource
    @State private var url = ""
    @State private var filter = ""
    @State private var userAgent = ""
    @State private var hours = 24
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            SheetHeader(icon: "link", title: source.name, detail: "修改后会立即重新下载订阅")
            SheetField(label: "订阅地址", prompt: "https://…", text: $url)
            HStack(alignment: .top, spacing: 12) {
                SheetField(label: "节点过滤（正则，可选）", prompt: "例如 香港|HK", text: $filter)
                SubscriptionIntervalPicker(hours: $hours)
            }
            SheetField(label: "User-Agent（可选）", prompt: "留空使用默认值", text: $userAgent)
            SheetFooter(error: error, primary: busy ? "正在保存…" : "保存", enabled: !busy && !url.isEmpty, cancel: { dismiss() }) {
                busy = true
                Task {
                    error = await core.editSubscription(source, url: url, filter: filter, userAgent: userAgent, intervalHours: hours)
                    busy = false
                    if error == nil { dismiss() }
                }
            }
        }
        .padding(28).frame(width: 560)
        .onAppear {
            url = source.url; filter = source.filter; userAgent = source.userAgent
            hours = max(1, source.intervalSeconds / 3600)
        }
    }
}

extension Core {
    /// Rewrites one `[Subscription]` line, keeping its name so group references stay valid.
    func editSubscription(_ source: SubscriptionSource, url: String, filter: String, userAgent: String, intervalHours: Int) async -> String? {
        let url = url.trimmingCharacters(in: .whitespaces)
        let filter = filter.trimmingCharacters(in: .whitespaces)
        let userAgent = userAgent.trimmingCharacters(in: .whitespaces)
        guard Self.isSubscriptionURL(url) else { return "订阅地址需要以 http://、https:// 或 file:// 开头" }
        guard ![url, filter, userAgent].contains(where: { $0.contains(where: { "\r\n\"".contains($0) }) }) else {
            return "地址、过滤规则和 User-Agent 不能包含换行或双引号"
        }
        if !filter.isEmpty, (try? NSRegularExpression(pattern: filter)) == nil { return "节点过滤不是有效的正则表达式" }
        let text = readConfig()
        let line = source.line(url: url, filter: filter, userAgent: userAgent, intervalHours: intervalHours)
        guard let updated = ConfigText.replace(source.name, in: "Subscription", with: line, of: text) else {
            return "配置里找不到订阅「\(source.name)」"
        }
        return Core.explain(await saveConfig(updated, expected: text), as: "订阅没有保存，配置没有改动")
    }
}

extension ConfigText {
    /// Replaces the `name = …` line of `[section]` in place, leaving references alone.
    static func replace(_ name: String, in section: String, with line: String, of text: String) -> String? {
        var current = ""
        var found = false
        let lines = text.components(separatedBy: "\n").map { raw -> String in
            let trimmed = raw.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("[") && trimmed.hasSuffix("]") { current = String(trimmed.dropFirst().dropLast()); return raw }
            guard !found, current == section, !trimmed.hasPrefix("#"), let eq = trimmed.firstIndex(of: "="),
                  trimmed[..<eq].trimmingCharacters(in: .whitespaces) == name else { return raw }
            found = true
            return line
        }
        return found ? lines.joined(separator: "\n") : nil
    }
}

/// One line of orientation at the top of a page: what this page is for and where to go next.
struct GuideStrip: View {
    let icon: String
    let text: String
    var action: (String, () -> Void)? = nil
    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: icon).foregroundStyle(DS.accent)
            Text(text).font(DS.small).foregroundStyle(DS.ink2).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 8)
            if let action { Button(action.0, action: action.1).buttonStyle(.link).font(DS.small.weight(.medium)) }
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
        .background(DS.accentWash, in: RoundedRectangle(cornerRadius: DS.smallRadius, style: .continuous))
    }
}
