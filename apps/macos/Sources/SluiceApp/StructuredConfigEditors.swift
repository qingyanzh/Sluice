import SwiftUI

/// All modes edit ConfigDraft.text. The Config pane owns validation/save/reload.
struct StructuredConfigEditors: View {
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
            Text("修改会同步到文本草稿；完成后点击下方的保存按钮。")
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
            RuleConfigSheet(rule: request.rule, policies: document.policies) { rule in
                guard text == request.snapshot else { return "草稿已更新，请关闭后重新编辑。" }
                mutate { $0.setRule(rule, at: request.line) }
                return nil
            }
        }
        .sheet(item: $groupEdit) { request in
            GroupConfigSheet(group: request.group, policies: document.policies) { group in
                guard text == request.snapshot else { return "草稿已更新，请关闭后重新编辑。" }
                guard !document.groups.contains(where: { $0.id != request.line && $0.value.name == group.name }),
                      !document.policies.filter({ !document.groups.map { $0.value.name }.contains($0) }).contains(group.name)
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
        editorTable(headers: ["类型", "值", "策略", "选项"], weights: [0.25, 0.33, 0.23, 0.19],
                    rows: document.rules.map { ($0.id, [$0.value.type, $0.value.value, $0.value.policy, $0.value.options]) })
            .overlay { if document.rules.isEmpty { empty("还没有规则", detail: "添加规则后，流量将按从上到下的顺序匹配。") } }
    }

    private var groupTable: some View {
        editorTable(headers: ["名称", "类型", "成员 / 自动测试"], weights: [0.18, 0.22, 0.60],
                    rows: document.groups.map { item in
                        let group = item.value
                        var detail = group.members.joined(separator: ", ")
                        if !group.url.isEmpty { detail += "\n" + group.url }
                        if !group.interval.isEmpty { detail += "\n每 " + group.interval + " 秒测试" }
                        return (item.id, [group.name, group.type, detail])
                    })
            .overlay { if document.groups.isEmpty { empty("还没有策略组", detail: "添加策略组，将节点组合为手动或自动策略。") } }
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
                }.padding(.vertical, 10)
                Divider()
                ScrollView(.vertical) {
                    LazyVStack(spacing: 2) {
                        ForEach(rows, id: \.id) { row in
                            HStack(alignment: .top, spacing: 12) {
                                ForEach(headers.indices, id: \.self) { column in
                                    Text(row.cells[column]).font(DS.small)
                                        .fixedSize(horizontal: false, vertical: true)
                                        .frame(width: width * weights[column], alignment: .leading)
                                        .help(row.cells[column])
                                }
                            }
                            .padding(.vertical, 10)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(selection == row.id ? DS.accent.opacity(0.10) : Color.clear,
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

private struct RuleConfigSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State var rule: StructuredConfig.Rule
    let policies: [String]
    let apply: (StructuredConfig.Rule) -> String?
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            Text("编辑规则").font(DS.title)
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
            if let error { Text(error).font(DS.small).foregroundStyle(DS.fail) }
            HStack {
                Spacer()
                Button("取消") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("更新草稿") {
                    rule.normalise()
                    guard (rule.isFinal || !rule.value.isEmpty), !rule.policy.isEmpty,
                          !rule.serialised.contains("\n"), !rule.serialised.contains("\r"),
                          let parsed = StructuredConfig.Rule(line: rule.serialised), parsed == rule
                    else { error = "请填写有效的值和策略，字段不能包含换行或多余的逗号。"; return }
                    if let failure = apply(rule) { error = failure } else { dismiss() }
                }.keyboardShortcut(.defaultAction).glassButton(prominent: true)
            }.glassButton()
        }.font(DS.label).padding(28).frame(width: 560)
    }
}

private struct GroupConfigSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State var group: StructuredConfig.Group
    let policies: [String]
    let apply: (StructuredConfig.Group) -> String?
    @State private var error: String?
    private var candidates: [String] { policies.filter { $0 != group.name && !group.members.contains($0) } }

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("编辑策略组").font(DS.title)
            Form {
                TextField("名称", text: $group.name)
                Picker("类型", selection: $group.type) {
                    ForEach(choices(StructuredConfig.Group.types, including: group.type), id: \.self) { Text($0).tag($0) }
                }
                if group.isAutomatic {
                    TextField("测试 URL", text: $group.url, prompt: Text("http://www.gstatic.com/generate_204").foregroundStyle(DS.ink3))
                    TextField("间隔（秒）", text: $group.interval, prompt: Text("600").foregroundStyle(DS.ink3))
                }
            }.textFieldStyle(.roundedBorder)
            HStack {
                Text("成员（按优先顺序）").font(DS.heading)
                Spacer()
                Menu("添加成员") {
                    ForEach(candidates, id: \.self) { member in Button(member) { group.members.append(member) } }
                }.disabled(candidates.isEmpty)
            }
            ScrollView {
                VStack(spacing: 8) {
                    if group.members.isEmpty {
                        Text("从节点和策略组中添加成员。订阅组也可以使用原有的 policy-path。")
                            .font(DS.small).foregroundStyle(DS.ink2).padding(.vertical, 12)
                    }
                    ForEach(Array(group.members.enumerated()), id: \.offset) { index, member in
                        HStack {
                            Text(member).lineLimit(1)
                            Spacer()
                            Button { group.members.swapAt(index, index - 1) } label: { Image(systemName: "arrow.up") }
                                .disabled(index == 0).help("上移成员")
                            Button { group.members.swapAt(index, index + 1) } label: { Image(systemName: "arrow.down") }
                                .disabled(index + 1 == group.members.count).help("下移成员")
                            Button { group.members.remove(at: index) } label: { Image(systemName: "minus") }.help("移除成员")
                        }.padding(.vertical, 4)
                    }
                }
            }.frame(height: 160)
            if let error { Text(error).font(DS.small).foregroundStyle(DS.fail) }
            HStack {
                Spacer()
                Button("取消") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("更新草稿") { submit() }.keyboardShortcut(.defaultAction).glassButton(prominent: true)
            }
        }
        .font(DS.label).glassButton().padding(28).frame(width: 580)
    }

    private func submit() {
        group.name = StructuredConfig.trim(group.name)
        guard !group.name.isEmpty, !group.name.contains(where: { ",=\r\n".contains($0) }),
              !["#", ";", "//", "["].contains(where: group.name.hasPrefix),
              !group.serialised.contains("\r"), !group.serialised.contains("\n"),
              !group.url.contains(","), !group.members.contains(group.name),
              StructuredConfig.Group(line: group.serialised) == group,
              !group.members.isEmpty || group.parameter("policy-path") != nil
        else { error = "请填写有效名称，并添加至少一个成员或保留订阅参数。"; return }
        if !group.interval.isEmpty, UInt64(group.interval) == nil {
            error = "间隔需要填写非负整数秒。"; return
        }
        if let failure = apply(group) { error = failure } else { dismiss() }
    }
}

private func choices(_ values: [String], including value: String) -> [String] {
    values.contains(value) ? values : [value] + values
}
