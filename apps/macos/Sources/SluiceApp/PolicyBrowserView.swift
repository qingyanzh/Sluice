import SwiftUI

private struct PolicyEditRequest: Identifiable {
    let id = UUID()
    let path: String
    let text: String
    let group: StructuredConfig.Group
    let originalName: String?
    let knownGroups: [PolicyGroup]
}

private struct PolicyReferenceRequest: Identifiable {
    let id = UUID()
    let name: String
    let organization: PolicyOrganization
    var linkRule = false
    let path: String
    let text: String
}

struct PolicyView: View {
    @EnvironmentObject var core: Core
    @ObservedObject var draft: ConfigDraft
    @State private var filter = ""
    @State private var text = ""
    @State private var showUnused = false
    @State private var editing: PolicyEditRequest?
    @State private var reference: PolicyReferenceRequest?

    private var organization: PolicyOrganization {
        PolicyOrganization(document: StructuredConfig(text), groups: core.policyGroups, nodes: core.catalogNodes)
    }
    private var activeName: String { core.activeProfileName ?? URL(fileURLWithPath: core.configPath).deletingPathExtension().lastPathComponent }

    var body: some View {
        let organization = organization
        let groups = visibleGroups(organization)
        let used = groups.filter { organization.usage(of: $0.group) != "未引用" }
        let unused = groups.filter { organization.usage(of: $0.group) == "未引用" }
        ScrollView {
            VStack(alignment: .leading, spacing: DS.gap) {
                executionCard(organization)
                if let error = core.catalogError { ErrorText(raw: error) }
                if core.loadingCatalog && core.policyGroups.isEmpty {
                    ProgressView("正在读取策略组…").font(DS.small).frame(maxWidth: .infinity).padding(.vertical, 40)
                } else if groups.isEmpty {
                    EmptyState(icon: "square.stack", title: filter.isEmpty ? "还没有策略组" : "没有匹配的策略组",
                               detail: filter.isEmpty ? "新建策略组，从任意订阅挑选节点" : "清除搜索后查看全部策略组",
                               action: filter.isEmpty ? ("新建策略组", { edit(nil) }) : ("清除搜索", { filter = "" }))
                        .padding(.vertical, 40)
                } else {
                    groupList(used, organization: organization)
                    if !unused.isEmpty {
                        Button { withAnimation(DS.spring) { showUnused.toggle() } } label: {
                            HStack(spacing: 6) {
                                Image(systemName: "chevron.right").rotationEffect(.degrees(showUnused || !filter.isEmpty ? 90 : 0))
                                Text("未被规则引用的组").font(DS.label.weight(.semibold))
                                Text("\(unused.count)").font(DS.caption.monospacedDigit()).foregroundStyle(DS.ink3)
                                Spacer()
                            }.contentShape(Rectangle())
                        }
                        .buttonStyle(.plain).foregroundStyle(DS.ink2).padding(.top, 4)
                        if showUnused || !filter.isEmpty {
                            groupList(unused, organization: organization).transition(.opacity)
                        }
                    }
                }
            }
            .padding(.horizontal, DS.gutter).padding(.bottom, DS.gutter)
        }
        .paneHeader {
            PaneHeader(title: "策略", subtitle: "\(activeName) · \(core.policyGroups.count) 个策略组") {
                SearchField(prompt: "搜索策略组或节点", text: $filter).frame(width: 200)
                TestAllLatencyButton().help("测试当前配置的所有策略组")
                Button { edit(nil) } label: { Label("新建策略组", systemImage: "plus") }
                    .glassButton(prominent: true).disabled(!core.canChangeProfile)
            }
        }
        .onAppear(perform: refreshText)
        .task(id: "\(core.configPath)|\(core.state == .running)") {
            refreshText()
            if core.state != .running { await core.loadNodeCatalog() }
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in refreshText() }
        .onChange(of: core.reloading) { _, busy in if !busy { refreshText() } }
        .sheet(item: $editing, onDismiss: refreshText) { request in
            PolicyGroupSaveSheet(request: request)
        }
        .sheet(item: $reference, onDismiss: refreshText) { request in
            PolicyReferencesSheet(request: request)
        }
    }

    private func visibleGroups(_ organization: PolicyOrganization) -> [PolicyGroup] {
        let query = filter.trimmingCharacters(in: .whitespacesAndNewlines)
        return core.policyGroups.filter { group in
            query.isEmpty || subscriptionNodeLabel(group.group).localizedCaseInsensitiveContains(query)
                || group.options.contains { subscriptionNodeLabel($0.name).localizedCaseInsensitiveContains(query) }
        }
    }

    private func groupList(_ groups: [PolicyGroup], organization: PolicyOrganization) -> some View {
        VStack(spacing: DS.gap) {
            ForEach(Array(groups.enumerated()), id: \.element.id) { index, group in
                let owned = organization.source(of: group.group) == nil
                GroupSection(group: group, filter: filter, interactive: true, usage: organization.usage(of: group.group),
                             onEdit: owned ? { edit(group) } : nil,
                             onCopy: owned ? nil : { copy(group) },
                             onDefault: organization.defaultPolicy != group.group ? { makeDefault(group) } : nil,
                             onRule: { references(group, link: true) }, onReferences: { references(group, link: false) })
                    .modifier(Entrance(index: index))
            }
        }
    }

    private var modeControls: some View {
        GlassSegmented(options: OutboundMode.allCases.map { ($0, $0.title, $0.icon) },
                       selection: Binding(get: { OutboundMode(rawValue: core.mode) ?? .rule }, set: { core.setMode($0.rawValue) }))
            .disabled(core.state != .running)
            .frame(maxWidth: 360)
    }

    private func executionCard(_ organization: PolicyOrganization) -> some View {
        let root = organization.defaultPolicy ?? "DIRECT"
        let direct = core.state == .running && core.mode == "direct"
        let path = direct ? ["DIRECT"] : organization.chain(from: root)
        let mode = OutboundMode(rawValue: core.mode) ?? .rule
        return VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 12) {
                Text("出站").font(DS.heading)
                Spacer(minLength: 12)
                modeControls
            }
            HStack(spacing: 6) {
                ForEach(Array(path.enumerated()), id: \.offset) { index, step in
                    if index > 0 { Image(systemName: "chevron.right").font(.system(size: 10, weight: .semibold)).foregroundStyle(DS.ink3) }
                    Text(subscriptionShortLabel(step))
                        .font(DS.label.weight(index == path.count - 1 ? .semibold : .regular))
                        .foregroundStyle(index == path.count - 1 ? DS.accent : .primary)
                        .lineLimit(1).truncationMode(.middle)
                        .padding(.horizontal, 10).frame(height: 26)
                        .background((index == path.count - 1 ? DS.accent : Color.primary).opacity(index == path.count - 1 ? 0.12 : 0.05), in: Capsule())
                }
                Spacer(minLength: 0)
            }
            .animation(DS.spring, value: path)
            Text(core.state != .running ? "内核未启动，可先编辑策略组和测速" : direct ? "直接连接模式不经过策略组" : mode == .global ? "全局代理：所有流量走默认出口" : "未命中专用规则的流量走默认出口")
                .font(DS.small).foregroundStyle(DS.ink2)
        }.card()
    }

    private func refreshText() {
        text = core.readConfig()
        draft.refresh(path: core.configPath, disk: text)
    }
    private func edit(_ group: PolicyGroup?) {
        let snapshot = core.readConfig()
        let original = group.flatMap { selected in StructuredConfig(snapshot).groups.first { $0.value.name == selected.group }?.value }
        editing = PolicyEditRequest(path: core.configPath, text: snapshot, group: original ?? StructuredConfig.Group(), originalName: original?.name, knownGroups: core.policyGroups)
    }
    private func copy(_ group: PolicyGroup) {
        let snapshot = core.readConfig()
        let org = PolicyOrganization(document: StructuredConfig(snapshot), groups: core.policyGroups, nodes: core.catalogNodes)
        let base = subscriptionNodeLabel(group.group).replacingOccurrences(of: " · 策略组", with: "") + " 副本"
        let taken = ConfigText.names(in: snapshot).union(core.policyGroups.map(\.group))
        var name = base; var suffix = 2
        while taken.contains(name) { name = "\(base) \(suffix)"; suffix += 1 }
        editing = PolicyEditRequest(path: core.configPath, text: snapshot, group: org.ownedCopy(of: group, named: name), originalName: nil, knownGroups: core.policyGroups)
    }
    private func makeDefault(_ group: PolicyGroup) {
        let snapshot = core.readConfig(); let path = core.configPath
        Task {
            core.lastActionError = await core.makeDefaultPolicy(group.group, path: path, expected: snapshot)
            refreshText()
        }
    }
    private func references(_ group: PolicyGroup, link: Bool) {
        reference = PolicyReferenceRequest(name: group.group, organization: organization, linkRule: link, path: core.configPath, text: core.readConfig())
    }
}

private struct PolicyGroupSaveSheet: View {
    @EnvironmentObject var core: Core
    let request: PolicyEditRequest
    @State private var usage = PolicyGroupUse()
    var body: some View {
        GroupConfigSheet(group: request.group, isNew: request.originalName == nil,
                         policies: StructuredConfig(request.text).policies,
                         sourceNames: StructuredConfig(request.text).subscriptionNames,
                         loadCatalog: { try await core.subscriptionCatalog(in: request.text) },
                         usage: $usage, submitTitle: "保存", save: { group in
            await core.savePolicyGroup(group, originalName: request.originalName, usage: usage,
                                       path: request.path, expected: request.text, knownGroups: request.knownGroups)
        }) { _ in nil }
    }
}

private struct PolicyReferencesSheet: View {
    @EnvironmentObject var core: Core
    @Environment(\.dismiss) private var dismiss
    let request: PolicyReferenceRequest
    @State private var usage = PolicyGroupUse(mode: .rule)
    @State private var busy = false
    @State private var error: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            SheetHeader(icon: "arrow.triangle.branch", title: subscriptionNodeLabel(request.name), detail: request.linkRule ? "关联专用规则" : "引用与执行链")
            if request.linkRule {
                Picker("规则类型", selection: $usage.ruleType) {
                    Text("域名及子域名").tag("DOMAIN-SUFFIX"); Text("精确域名").tag("DOMAIN"); Text("进程名称").tag("PROCESS-NAME")
                }
                SheetField(label: "匹配值", prompt: usage.ruleType == "PROCESS-NAME" ? "例如 Safari" : "例如 example.com", text: $usage.value)
                Text("规则插入在 FINAL 之前，只处理匹配的请求").font(DS.small).foregroundStyle(DS.ink2)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(request.organization.chain(from: request.name).map(subscriptionNodeLabel).joined(separator: " → ")).font(DS.label).textSelection(.enabled)
                        let rules = request.organization.ruleReferences(to: request.name)
                        let parents = request.organization.parentReferences(to: request.name)
                        if rules.isEmpty && parents.isEmpty { Text("此组尚未被规则或其他组引用，不承载流量").font(DS.small).foregroundStyle(DS.ink2) }
                        ForEach(Array(rules.enumerated()), id: \.offset) { _, rule in Text("规则：\(rule.type) \(rule.value)").font(DS.small) }
                        ForEach(parents, id: \.self) { Text("被策略组引用：\(subscriptionNodeLabel($0))").font(DS.small) }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }.frame(maxHeight: 340)
            }
            SheetFooter(error: error, primary: request.linkRule ? "保存规则" : "完成", enabled: !busy,
                        cancel: { dismiss() }) {
                if !request.linkRule { dismiss(); return }
                busy = true
                Task {
                    error = await core.linkPolicyRule(request.name, usage: usage, path: request.path, expected: request.text)
                    busy = false
                    if error == nil { dismiss() }
                }
            }
        }.padding(28).frame(width: 560).disabled(busy).interactiveDismissDisabled(busy)
    }
}
