import SwiftUI

/// Two-pane policy group editor: everything that can be a member on the left,
/// grouped by where it comes from; the group's ordered members on the right.
/// Members can mix local nodes, other groups and nodes from any subscription;
/// a whole subscription can also be included dynamically (`use=`).
struct GroupConfigSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State var group: StructuredConfig.Group
    let isNew: Bool
    /// DIRECT, REJECT, local groups and local nodes, in config order.
    let policies: [String]
    var sourceNames: [String] = []
    var loadCatalog: (() async throws -> SubscriptionCatalog)? = nil
    /// Kept for callers; the editor only edits the group itself.
    var usage: Binding<PolicyGroupUse>? = nil
    var submitTitle: String? = nil
    var save: ((StructuredConfig.Group) async -> String?)? = nil
    let apply: (StructuredConfig.Group) -> String?

    @State private var nodes: [SubscriptionNode] = []
    @State private var localGroups: Set<String> = []
    @State private var catalogLoaded = false
    @State private var loadingNodes = false
    @State private var nodesError: String?
    @State private var search = ""
    @State private var source = Library.all
    @State private var error: String?
    @State private var saving = false

    var title: String { isNew ? "新建策略组" : "编辑策略组" }

    /// Which part of the library the left pane shows.
    enum Library: Hashable { case all, builtIn, local, subscription(String) }

    private static let kinds: [(String, String, String)] = [
        ("select", "手动选择", "hand.tap"), ("url-test", "自动测速", "bolt"),
        ("fallback", "故障转移", "arrow.triangle.branch"), ("load-balance", "负载均衡", "scale.3d"),
    ]

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header.padding(24)
            Divider()
            HStack(spacing: 0) {
                library.frame(width: 320)
                Divider()
                members.frame(maxWidth: .infinity)
            }
            .frame(height: 400)
            Divider()
            footer.padding(.horizontal, 24).padding(.vertical, 16)
        }
        .font(DS.label)
        .frame(width: 760)
        .disabled(saving).interactiveDismissDisabled(saving)
        .onChange(of: group) { error = nil }
        .task { await refreshNodes() }
    }

    // MARK: Header

    private var header: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .firstTextBaseline) {
                Text(title).font(DS.title)
                Spacer()
                Text(summary).font(DS.small.monospacedDigit()).foregroundStyle(DS.ink2)
            }
            HStack(alignment: .bottom, spacing: 16) {
                SheetField(label: "名称", prompt: "例如 Proxy", text: $group.name).frame(width: 220)
                VStack(alignment: .leading, spacing: 6) {
                    Text("类型").font(DS.caption).foregroundStyle(DS.ink2)
                    GlassSegmented(options: Self.kinds.map { ($0.0, $0.1, $0.2) },
                                   selection: Binding(get: { group.type.lowercased() }, set: { group.type = $0 }))
                }
            }
            if group.isAutomatic {
                HStack(alignment: .bottom, spacing: 16) {
                    SheetField(label: "测速地址", prompt: "http://www.gstatic.com/generate_204", text: $group.url)
                    SheetField(label: "间隔（秒）", prompt: "600", text: $group.interval).frame(width: 120)
                    if group.type.lowercased() == "url-test" {
                        SheetField(label: "容差（毫秒）", prompt: "50", text: Binding(get: { group.parameter("tolerance") ?? "" },
                                                                                  set: { group.setTolerance($0) })).frame(width: 120)
                    }
                }
                .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
        .animation(DS.spring, value: group.isAutomatic)
    }

    private var summary: String {
        let count = group.members.count
        return group.sources.isEmpty ? "\(count) 个成员" : "\(count) 个成员 · 动态包含 \(group.sources.count) 个订阅"
    }

    // MARK: Library

    private struct Candidate: Identifiable, Hashable {
        let id: String
        let title: String
        let detail: String
        let symbol: String
    }

    private var candidates: [Candidate] {
        let builtIn = ["DIRECT", "REJECT"].map { Candidate(id: $0, title: $0 == "DIRECT" ? "直接连接" : "拒绝", detail: $0, symbol: $0 == "DIRECT" ? "arrow.right" : "nosign") }
        let local = policies.filter { !["DIRECT", "REJECT"].contains($0) && $0 != group.name }.map {
            Candidate(id: $0, title: $0, detail: localGroups.contains($0) ? "策略组" : "本地节点", symbol: localGroups.contains($0) ? "square.stack.3d.up" : "server.rack")
        }
        let remote = nodes.map { Candidate(id: $0.id, title: $0.name, detail: $0.source, symbol: "globe") }
        switch source {
        case .all: return builtIn + local + remote
        case .builtIn: return builtIn
        case .local: return local
        case .subscription(let name): return remote.filter { $0.detail == name }
        }
    }

    private var visibleCandidates: [Candidate] {
        let query = search.trimmingCharacters(in: .whitespaces)
        return candidates.filter { query.isEmpty || $0.title.localizedCaseInsensitiveContains(query) || $0.detail.localizedCaseInsensitiveContains(query) }
    }

    private var library: some View {
        VStack(alignment: .leading, spacing: 10) {
            VStack(alignment: .leading, spacing: 8) {
                Picker("", selection: $source) {
                    Text("全部来源").tag(Library.all)
                    Text("内置").tag(Library.builtIn)
                    Text("本地节点与策略组").tag(Library.local)
                    if !sourceNames.isEmpty { Divider() }
                    ForEach(sourceNames, id: \.self) { Text("订阅 · \($0)").tag(Library.subscription($0)) }
                }
                .labelsHidden().frame(maxWidth: .infinity)
                SearchField(prompt: "搜索节点", text: $search).frame(maxWidth: .infinity)
            }
            if case .subscription(let name) = source { dynamicToggle(name) }
            if loadingNodes { ProgressView().controlSize(.small).frame(maxWidth: .infinity) }
            if let nodesError {
                HStack(alignment: .firstTextBaseline) {
                    Text(nodesError).font(DS.small).foregroundStyle(DS.warn).lineLimit(2)
                    Spacer()
                    Button("重试") { Task { await refreshNodes() } }.buttonStyle(.link)
                }
            }
            let visible = visibleCandidates
            HStack {
                Text("\(visible.count) 项").font(DS.caption.monospacedDigit()).foregroundStyle(DS.ink3)
                Spacer()
                Button("全部添加") { add(visible.map(\.id)) }
                    .buttonStyle(.link).font(DS.small).disabled(visible.allSatisfy { group.members.contains($0.id) })
            }
            List(visible) { candidate in
                let added = group.members.contains(candidate.id)
                Button { added ? remove(candidate.id) : add([candidate.id]) } label: {
                    HStack(spacing: 10) {
                        Image(systemName: candidate.symbol).frame(width: 16).foregroundStyle(DS.ink2)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(candidate.title).lineLimit(1).truncationMode(.middle)
                            Text(candidate.detail).font(DS.caption).foregroundStyle(DS.ink3).lineLimit(1)
                        }
                        Spacer(minLength: 6)
                        Image(systemName: added ? "checkmark.circle.fill" : "plus.circle")
                            .foregroundStyle(added ? DS.accent : DS.ink3)
                            .contentTransition(.symbolEffect(.replace))
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .listRowSeparator(.hidden)
            }
            .listStyle(.plain).scrollContentBackground(.hidden)
            .overlay {
                if visible.isEmpty && !loadingNodes {
                    Text(search.isEmpty ? "此来源没有可用节点" : "没有匹配的节点").font(DS.small).foregroundStyle(DS.ink3)
                }
            }
        }
        .padding(16)
        .background(Color.primary.opacity(0.025))
    }

    private func dynamicToggle(_ name: String) -> some View {
        let on = group.sources.contains(name)
        return Toggle(isOn: Binding(get: { on }, set: { include in
            withAnimation(DS.spring) {
                if include { group.sources.append(name) } else { group.sources.removeAll { $0 == name } }
            }
        })) {
            VStack(alignment: .leading, spacing: 1) {
                Text("动态包含整个订阅").font(DS.label.weight(.medium))
                Text("订阅更新后自动跟随节点变化").font(DS.caption).foregroundStyle(DS.ink2)
            }
        }
        .toggleStyle(.switch).controlSize(.small)
        .padding(10)
        .background(DS.accent.opacity(on ? 0.08 : 0.03), in: RoundedRectangle(cornerRadius: DS.smallRadius, style: .continuous))
    }

    // MARK: Members

    private var members: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("成员").font(DS.heading)
                Text("按顺序优先，可拖动排序").font(DS.caption).foregroundStyle(DS.ink3)
                Spacer()
                if !group.members.isEmpty {
                    Button("清空") { withAnimation(DS.spring) { group.members.removeAll() } }.buttonStyle(.link).font(DS.small)
                }
            }
            if !group.sources.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    FlowChips(items: group.sources) { name in
                        withAnimation(DS.spring) { group.sources.removeAll { $0 == name } }
                    }
                    HStack(spacing: 8) {
                        Text("节点过滤").font(DS.caption).foregroundStyle(DS.ink2)
                        TextField("", text: $group.nodeFilter, prompt: Text("正则，可选，例如 香港|HK").foregroundStyle(DS.ink3))
                            .textFieldStyle(.roundedBorder)
                    }
                }
                .padding(10)
                .background(DS.accent.opacity(0.06), in: RoundedRectangle(cornerRadius: DS.smallRadius, style: .continuous))
                .transition(.opacity)
            }
            List {
                ForEach(Array(group.members.enumerated()), id: \.element) { index, member in
                    memberRow(member, index: index)
                        .listRowSeparator(.hidden)
                }
                .onMove { from, to in group.members.move(fromOffsets: from, toOffset: to) }
            }
            .listStyle(.plain).scrollContentBackground(.hidden)
            .overlay {
                if group.members.isEmpty && group.sources.isEmpty {
                    VStack(spacing: 6) {
                        Image(systemName: "tray").font(.system(size: 22)).foregroundStyle(DS.ink3)
                        Text("从左侧添加节点或策略组").font(DS.small).foregroundStyle(DS.ink2)
                    }
                }
            }
        }
        .padding(16)
        .animation(DS.spring, value: group.members)
        .animation(DS.spring, value: group.sources)
    }

    private func memberRow(_ member: String, index: Int) -> some View {
        let node = nodes.first { $0.id == member }
        let missing = catalogLoaded && member.hasPrefix("@") && node == nil
        return HStack(spacing: 10) {
            Text("\(index + 1)").font(DS.caption.monospacedDigit()).foregroundStyle(DS.ink3).frame(width: 20, alignment: .trailing)
            Image(systemName: "line.3.horizontal").foregroundStyle(DS.ink3)
            VStack(alignment: .leading, spacing: 1) {
                Text(node?.name ?? (member == "DIRECT" ? "直接连接" : member == "REJECT" ? "拒绝" : subscriptionNodeLabel(member)))
                    .lineLimit(1).truncationMode(.middle)
                Text(node?.source ?? (localGroups.contains(member) ? "策略组" : ["DIRECT", "REJECT"].contains(member) ? "内置" : "本地节点"))
                    .font(DS.caption).foregroundStyle(DS.ink3)
            }
            Spacer(minLength: 6)
            if missing {
                StatusBadge(text: "已失效", tone: DS.warn).help("订阅更新后找不到这个节点，运行时会跳过")
            }
            Button { remove(member) } label: { Image(systemName: "minus.circle") }
                .buttonStyle(.borderless).foregroundStyle(DS.ink2).help("移除")
        }
        .padding(.vertical, 2)
    }

    // MARK: Footer

    private var footer: some View {
        HStack(spacing: 12) {
            if let error {
                Label(error, systemImage: "exclamationmark.circle.fill").font(DS.small).foregroundStyle(DS.fail).lineLimit(2)
            }
            Spacer()
            Button("取消") { dismiss() }.keyboardShortcut(.cancelAction).glassButton()
            Button(saving ? "正在保存…" : submitTitle ?? "保存") { submit() }
                .keyboardShortcut(.defaultAction).glassButton(prominent: true)
        }
    }

    // MARK: Actions

    private func add(_ ids: [String]) {
        withAnimation(DS.spring) {
            for id in ids where !group.members.contains(id) && id != group.name { group.members.append(id) }
        }
    }

    private func remove(_ id: String) {
        withAnimation(DS.spring) { group.members.removeAll { $0 == id } }
    }

    private func refreshNodes() async {
        guard let loadCatalog, !loadingNodes else { return }
        loadingNodes = true
        defer { loadingNodes = false }
        do {
            let catalog = try await loadCatalog()
            nodes = catalog.nodes
            localGroups = Set(catalog.groups.map(\.group).filter { !$0.hasPrefix("@") })
            catalogLoaded = true
            nodesError = catalog.warnings.flatMap { $0.isEmpty ? nil : $0.joined(separator: "\n") }
        } catch { nodesError = error.localizedDescription }
    }

    private func submit() {
        var group = group
        group.name = StructuredConfig.trim(group.name)
        guard !group.name.isEmpty, !group.name.contains(where: { ",=\r\n".contains($0) }),
              !["#", ";", "//", "["].contains(where: group.name.hasPrefix) else {
            error = "请填写有效名称，不能包含逗号或等号"; return
        }
        guard !group.members.isEmpty || !group.sources.isEmpty || group.parameter("policy-path") != nil else {
            error = "至少添加一个成员或订阅"; return
        }
        guard !group.serialised.contains("\r"), !group.serialised.contains("\n"), !group.url.contains(","),
              !group.members.contains(group.name), StructuredConfig.Group(line: group.serialised) == group else {
            error = "成员或参数包含无法保存的字符"; return
        }
        if !group.interval.isEmpty, UInt64(group.interval) == nil { error = "间隔需要填写非负整数秒"; return }
        if let tolerance = group.parameter("tolerance"), UInt64(tolerance) == nil { error = "容差需要填写非负整数毫秒"; return }
        if !group.nodeFilter.isEmpty, (try? NSRegularExpression(pattern: group.nodeFilter)) == nil {
            error = "节点过滤不是有效的正则表达式"; return
        }
        if let save {
            saving = true
            Task {
                let failure = await save(group)
                saving = false
                if let failure { error = failure } else { dismiss() }
            }
        } else if let failure = apply(group) { error = failure } else { dismiss() }
    }
}

/// Removable chips for the subscriptions a group includes dynamically.
private struct FlowChips: View {
    let items: [String]
    let remove: (String) -> Void
    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 6) {
                ForEach(items, id: \.self) { item in
                    HStack(spacing: 4) {
                        Image(systemName: "link").font(.system(size: 10))
                        Text("整个订阅 · \(item)").font(DS.caption)
                        Button { remove(item) } label: { Image(systemName: "xmark").font(.system(size: 9, weight: .bold)) }
                            .buttonStyle(.borderless)
                    }
                    .padding(.horizontal, 8).frame(height: 22)
                    .foregroundStyle(DS.accent)
                    .background(DS.accent.opacity(0.12), in: Capsule())
                }
            }
        }
    }
}

extension StructuredConfig.Group {
    mutating func setTolerance(_ value: String) {
        let value = StructuredConfig.trim(value)
        parameters.removeAll { StructuredConfig.trim(String($0.prefix { $0 != "=" })).lowercased() == "tolerance" }
        if !value.isEmpty { parameters.append("tolerance=\(value)") }
    }
}
