import SwiftUI

/// All modes edit ConfigDraft.text. The Config pane owns validation/save/reload.
struct StructuredConfigEditors: View {
    @EnvironmentObject var core: Core
    @Binding var text: String
    var section: String
    @State private var selection: Int?
    @State private var ruleEdit: RuleEdit?
    @State private var groupEdit: GroupEdit?

    private var document: StructuredConfig { StructuredConfig(text) }
    private var ids: [Int] { section == "Rule" ? document.rules.map(\.id) : document.groups.map(\.id) }
    private var selectedIndex: Int? { selection.flatMap { ids.firstIndex(of: $0) } }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text(section == "Rule" ? "规则" : "策略组").font(DS.heading)
                Text("\(ids.count)").font(DS.small).monospacedDigit().foregroundStyle(DS.ink3)
                    .frame(width: 48, alignment: .trailing)
                Spacer()
                Button("添加", systemImage: "plus") { edit(nil) }
                Button("编辑", systemImage: "pencil") { edit(selection) }.disabled(selectedIndex == nil)
                Button("删除", systemImage: "minus") {
                    if let selection { mutate { $0.delete(selection, in: section) } }
                }.disabled(selectedIndex == nil)
                Button { move(-1) } label: { Image(systemName: "arrow.up") }
                    .help("上移").disabled(selectedIndex == nil || selectedIndex == 0)
                Button { move(1) } label: { Image(systemName: "arrow.down") }
                    .help("下移").disabled(selectedIndex == nil || selectedIndex == ids.count - 1)
            }.glassButton()
            Text("修改会同步到文本草稿；完成后点击下方的保存按钮")
                .font(DS.small).foregroundStyle(DS.ink2)
            if document.unparsedCount(in: section) > 0 {
                Label("部分行无法显示为表格，已保留原文。请在文本中编辑。", systemImage: "info.circle")
                    .font(DS.small).foregroundStyle(DS.warn)
            }
            if section == "Rule" { ruleTable } else { groupTable }
        }
        .padding(20)
        .glassPanel()
        .sheet(item: $ruleEdit) { request in
            RuleConfigSheet(rule: request.rule, isNew: request.line == nil, policies: document.policies) { rule in
                guard text == request.snapshot else { return "草稿已更新，请关闭后重新编辑。" }
                mutate { $0.setRule(rule, at: request.line) }
                return nil
            }
        }
        .sheet(item: $groupEdit) { request in
            GroupConfigSheet(group: request.group, isNew: request.line == nil, policies: document.policies,
                             sourceNames: StructuredConfig(request.snapshot).subscriptionNames,
                             loadCatalog: { try await core.subscriptionCatalog(in: request.snapshot) }) { group in
                guard text == request.snapshot else { return "草稿已更新，请关闭后重新编辑。" }
                guard !document.groups.contains(where: { $0.id != request.line && $0.value.name == group.name }),
                      !document.policies.filter({ !document.groups.map { $0.value.name }.contains($0) }).contains(group.name),
                      !ConfigText.lines(of: "Subscription", in: text).contains(where: { $0.split(separator: "=", maxSplits: 1).first?.trimmingCharacters(in: .whitespaces) == group.name })
                else { return "这个名称已被使用，请选择其他名称。" }
                mutate { $0.setGroup(group, at: request.line) }
                return nil
            }
        }
        .onChange(of: text) {
            if let selection, !ids.contains(selection) { self.selection = nil }
        }
        .onChange(of: section) { selection = nil }
    }

    private var ruleTable: some View {
        editorTable(headers: ["类型", "值", "策略", "选项"], weights: [0.30, 0.32, 0.20, 0.18],
                    rows: document.rules.map { ($0.id, [$0.value.type, $0.value.value, $0.value.policy, $0.value.options]) })
            .overlay { if document.rules.isEmpty { empty("还没有规则", detail: "添加规则后，流量将按从上到下的顺序匹配") } }
    }

    private var groupTable: some View {
        editorTable(headers: ["名称", "类型", "成员 / 自动测试"], weights: [0.18, 0.22, 0.60],
                    rows: document.groups.map { item in
                        let group = item.value
                        var detail = group.members.joined(separator: ", ")
                        if !group.sources.isEmpty { detail += (detail.isEmpty ? "" : "\n") + "订阅节点：" + group.sources.joined(separator: "、") }
                        if !group.nodeFilter.isEmpty { detail += "\n节点过滤：" + group.nodeFilter }
                        // Subscription groups have no fixed members: say where their nodes come from.
                        if let source = group.parameter("policy-path") {
                            let from = "订阅 · \(subscriptionSourceLabel(source))"
                            detail = detail.isEmpty ? from : from + "\n" + detail
                            if let filter = group.parameter("policy-regex-filter") { detail += "\n过滤：" + filter }
                        }
                        if !group.url.isEmpty { detail += "\n" + group.url }
                        if !group.interval.isEmpty { detail += "\n每 " + group.interval + " 秒测试" }
                        return (item.id, [group.name, group.type, detail])
                    })
            .overlay { if document.groups.isEmpty { empty("还没有策略组", detail: "添加策略组，将节点组合为手动或自动策略") } }
    }

    /// Proportional columns and variable-height rows keep all fields readable in
    /// the space beside the profile list, including long member lists and URLs.
    private func editorTable(headers: [String], weights: [CGFloat], rows: [(id: Int, cells: [String])]) -> some View {
        GeometryReader { geometry in
            let width = max(0, geometry.size.width - 16 - CGFloat(headers.count - 1) * 12)
            VStack(spacing: 0) {
                HStack(alignment: .top, spacing: 12) {
                    ForEach(headers.indices, id: \.self) { column in
                        Text(headers[column]).font(DS.caption).foregroundStyle(DS.ink2)
                            .frame(width: width * weights[column], alignment: .leading)
                    }
                }.padding(.vertical, 10).padding(.horizontal, 8)
                Divider()
                ScrollView(.vertical) {
                    LazyVStack(spacing: 2) {
                        ForEach(rows, id: \.id) { row in
                            HStack(alignment: .top, spacing: 12) {
                                ForEach(headers.indices, id: \.self) { column in
                                    // The first column is a keyword (rule type, group name): one line, set in code.
                                    if column == 0 {
                                        Text(row.cells[column]).font(section == "Rule" ? DS.code : DS.small.weight(.medium))
                                            .lineLimit(1).minimumScaleFactor(0.8).truncationMode(.middle)
                                            .frame(width: width * weights[column], alignment: .leading)
                                            .help(row.cells[column])
                                    } else {
                                        Text(row.cells[column]).font(DS.small)
                                            .fixedSize(horizontal: false, vertical: true)
                                            .frame(width: width * weights[column], alignment: .leading)
                                            .help(row.cells[column])
                                    }
                                }
                            }
                            .padding(.vertical, 9).padding(.horizontal, 8)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(selection == row.id ? DS.accentFill : Color.clear,
                                        in: RoundedRectangle(cornerRadius: DS.smallRadius))
                            .contentShape(Rectangle())
                            .onTapGesture(count: 2) { selection = row.id; edit(row.id) }
                            .onTapGesture { selection = row.id }
                            .contextMenu { Button("编辑") { edit(row.id) } }
                            .accessibilityAddTraits(selection == row.id ? [.isSelected] : [])
                        }
                    }
                }
            }
        }
    }

    private func empty(_ title: String, detail: String) -> some View {
        VStack(spacing: 12) {
            Text(title).font(DS.heading)
            Text(detail).font(DS.small).foregroundStyle(DS.ink2)
            Button("添加") { edit(nil) }.glassButton(prominent: true)
        }.padding(20)
    }
    private func edit(_ id: Int?) {
        if section == "Rule" {
            ruleEdit = RuleEdit(line: id, rule: document.rules.first { $0.id == id }?.value ?? .init(), snapshot: text)
        } else {
            groupEdit = GroupEdit(line: id, group: document.groups.first { $0.id == id }?.value ?? .init(), snapshot: text)
        }
    }
    private func mutate(_ action: (inout StructuredConfig) -> Void) {
        var updated = document
        action(&updated)
        text = updated.serialise()
        selection = nil
    }
    private func move(_ offset: Int) {
        guard let selection, let index = selectedIndex, ids.indices.contains(index + offset) else { return }
        let destination = ids[index + offset]
        mutate { $0.move(selection, by: offset, in: section) }
        self.selection = destination
    }
    private struct RuleEdit: Identifiable {
        let id = UUID()
        let line: Int?
        let rule: StructuredConfig.Rule
        let snapshot: String
    }
    private struct GroupEdit: Identifiable {
        let id = UUID()
        let line: Int?
        let group: StructuredConfig.Group
        let snapshot: String
    }
}

struct RuleConfigSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State var rule: StructuredConfig.Rule
    let isNew: Bool
    let policies: [String]
    let apply: (StructuredConfig.Rule) -> String?
    @State private var error: String?
    var title: String { isNew ? "添加规则" : "编辑规则" }

    var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            Text(title).font(DS.title)
            Form {
                Picker("类型", selection: $rule.type) {
                    ForEach(choices(StructuredConfig.Rule.types, including: rule.type), id: \.self) { Text($0).tag($0) }
                }
                if !rule.isFinal { TextField("值", text: $rule.value) }
                Picker("策略", selection: $rule.policy) {
                    ForEach(choices(policies, including: rule.policy), id: \.self) { Text($0).tag($0) }
                }
                TextField("选项", text: $rule.options, prompt: Text("no-resolve").foregroundStyle(DS.ink3))
                if ["AND", "OR", "NOT"].contains(rule.type.uppercased()) {
                    Text("嵌套条件示例：((DOMAIN,example.com),(DST-PORT,443))")
                        .font(DS.small).foregroundStyle(DS.ink2)
                }
            }.textFieldStyle(.roundedBorder)
            if let error { ErrorText(raw: error) }
            HStack {
                Spacer()
                Button("取消") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("更新草稿") {
                    var rule = rule
                    rule.normalise()
                    guard (rule.isFinal || !rule.value.isEmpty), !rule.policy.isEmpty,
                          !rule.serialised.contains("\n"), !rule.serialised.contains("\r"),
                          let parsed = StructuredConfig.Rule(line: rule.serialised), parsed == rule
                    else { error = "请填写有效的值和策略，字段不能包含换行或多余的逗号。"; return }
                    if let failure = apply(rule) { error = failure } else { dismiss() }
                }.keyboardShortcut(.defaultAction).glassButton(prominent: true)
            }.glassButton()
        }.font(DS.label).padding(28).frame(width: 560)
        .onChange(of: rule) { error = nil }
    }
}

private func choices(_ values: [String], including value: String) -> [String] {
    values.contains(value) ? values : [value] + values
}

/// Where a subscription's nodes come from, without its token: the host for URLs,
/// the file name for file:// sources.
func subscriptionSourceLabel(_ source: String) -> String {
    guard let url = URL(string: source) else { return source }
    if url.isFileURL { return url.lastPathComponent }
    return url.host ?? source
}

/// Independent sources and legacy `policy-path` groups in the current draft.
/// it is filtered. Deleting one edits the draft; nothing is written until it is saved.
struct SubscriptionsEditor: View {
    @EnvironmentObject var core: Core
    @Binding var text: String
    @State private var pendingDelete: NodeRecord?

    private var subscriptions: [NodeRecord] {
        ["Subscription", "Proxy Group"].flatMap { section in ConfigText.lines(of: section, in: text).compactMap { line in
            let name = line.split(separator: "=", maxSplits: 1).first.map { $0.trimmingCharacters(in: .whitespaces) } ?? line
            let record = NodeRecord(line: line, id: "\(section):\(name)", section: section)
            return record.isSubscription ? record : nil
        } }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                Text("订阅").font(DS.heading)
                Text("\(subscriptions.count)").font(DS.small.monospacedDigit()).foregroundStyle(DS.ink3)
                Spacer()
                Button("在订阅页管理") { core.requestedPane = .subscriptions }.buttonStyle(.link).font(DS.small)
            }
            Text("删除会同步到文本草稿；完成后点击下方的保存按钮").font(DS.small).foregroundStyle(DS.ink2)
            if subscriptions.isEmpty {
                EmptyState(icon: "link", title: "还没有订阅", detail: "在订阅页添加订阅，再到策略页编写策略组",
                           action: ("前往订阅", { core.requestedPane = .subscriptions }))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    VStack(spacing: 8) {
                        ForEach(subscriptions) { sub in row(sub) }
                    }
                }
            }
        }
        .padding(DS.cardPadding)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .glass()
        .confirmationDialog("删除订阅「\(pendingDelete?.name ?? "")」？", isPresented: Binding(
            get: { pendingDelete != nil }, set: { if !$0 { pendingDelete = nil } }), titleVisibility: .visible) {
            Button("删除订阅", role: .destructive) {
                if let sub = pendingDelete { text = ConfigText.remove(sub.name, from: sub.section, of: text) }
                pendingDelete = nil
            }
            Button("取消", role: .cancel) { pendingDelete = nil }
        } message: {
            Text("订阅及其节点引用会从草稿中移除；没有剩余成员的策略组会拒绝连接")
        }
    }

    private func row(_ sub: NodeRecord) -> some View {
        HStack(spacing: 12) {
            IconTile(symbol: "link", size: 28)
            VStack(alignment: .leading, spacing: 3) {
                Text(sub.name).font(DS.label.weight(.medium)).lineLimit(1)
                Text("\(sub.endpoint) · 过滤：\(sub.filter) · 每 \(sub.interval)更新")
                    .font(DS.small).foregroundStyle(DS.ink2).lineLimit(1).truncationMode(.middle)
            }
            Spacer(minLength: 8)
            Button(role: .destructive) { pendingDelete = sub } label: { Label("删除", systemImage: "trash") }
                .glassButton()
        }
        .padding(12)
        .background(DS.well, in: RoundedRectangle(cornerRadius: DS.smallRadius, style: .continuous))
    }
}
