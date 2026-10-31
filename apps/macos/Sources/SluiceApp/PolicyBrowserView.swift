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
    @State private var expanded: [String: Bool] = [:]
    @State private var editing: PolicyEditRequest?
    @State private var reference: PolicyReferenceRequest?
    @State private var pendingSwitch: String?
    @State private var switching = false
    @State private var importing = false

    private var organization: PolicyOrganization {
        PolicyOrganization(document: StructuredConfig(text), groups: core.policyGroups, nodes: core.catalogNodes)
    }
    private var activeName: String { core.activeProfileName ?? URL(fileURLWithPath: core.configPath).deletingPathExtension().lastPathComponent }
    private var profileNames: [String] { [activeName] + core.profileNames.filter { $0 != activeName } }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: DS.gap) {
                modeControls
                executionCard
                if let error = core.catalogError { Text(error).font(DS.small).foregroundStyle(DS.warn) }
                HStack {
                    Text("配置与策略组").font(DS.heading)
                    Spacer()
                    Button("导入独立配置", systemImage: "square.and.arrow.down") { importing = true }.glassButton().disabled(!core.canChangeProfile)
                    Button("新建组", systemImage: "plus") { edit(nil) }.glassButton()
                        .disabled(!core.canChangeProfile || switching)
                    TestAllLatencyButton().controlSize(.small).help("测试当前配置的所有策略组，不含其他配置")
                }
                ForEach(profileNames, id: \.self) { name in
                    profile(name)
                }
            }
            .padding(.horizontal, DS.gutter).padding(.bottom, DS.gutter)
        }
        .paneHeader {
            PaneHeader(title: "策略", subtitle: "按配置管理 · 规则决定执行入口") {
                SearchField(prompt: "搜索当前配置的策略或节点", text: $filter)
            }
        }
        .onAppear {
            if let values = core.preferences.dictionary(forKey: "policy.expansions.v1") as? [String: Bool] { expanded = values }
            refreshText(); core.refreshProfiles()
        }
        .task(id: "\(core.configPath)|\(core.state == .running)") {
            refreshText()
            if core.state != .running { await core.loadNodeCatalog() }
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in refreshText(); core.refreshProfiles() }
        .onChange(of: core.reloading) { _, busy in if !busy { refreshText() } }
        .sheet(isPresented: $importing) { IndependentProfileImportSheet() }
        .sheet(item: $editing, onDismiss: refreshText) { request in
            PolicyGroupSaveSheet(request: request)
        }
        .sheet(item: $reference, onDismiss: refreshText) { request in
            PolicyReferencesSheet(request: request)
        }
        .confirmationDialog("切换配置会放弃当前未保存的修改", isPresented: Binding(get: { pendingSwitch != nil }, set: { if !$0 { pendingSwitch = nil } })) {
            if let name = pendingSwitch {
                Button("放弃修改并切换到「\(name)」", role: .destructive) { switchProfile(name) }
                Button("复制草稿并切换到「\(name)」") { switchProfile(name, copyDraft: true) }
            }
            Button("取消", role: .cancel) { pendingSwitch = nil }
        } message: { Text("复制草稿会覆盖目标配置，原配置文件保持不变。") }
    }

    private var modeControls: some View {
        VStack(alignment: .leading, spacing: 8) {
            GlassSegmented(options: OutboundMode.allCases.map { ($0, $0.title, $0.icon) },
                           selection: Binding(get: { OutboundMode(rawValue: core.mode) ?? .rule }, set: { core.setMode($0.rawValue) }))
                .disabled(core.state != .running)
            Text((OutboundMode(rawValue: core.mode) ?? .rule).explanation).font(DS.small).foregroundStyle(DS.ink2)
        }
    }

    private var executionCard: some View {
        let root = organization.defaultPolicy ?? "DIRECT"
        let direct = core.state == .running && core.mode == "direct"
        let path = direct ? ["DIRECT"] : organization.chain(from: root)
        return VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label(core.state == .running ? "当前配置 · \(activeName)" : "配置预览 · \(activeName)", systemImage: "arrow.triangle.branch")
                    .font(DS.heading)
                Spacer()
                StatusBadge(text: direct ? "直接连接" : "默认出口", tone: DS.accent)
            }
            Text(path.map(subscriptionNodeLabel).joined(separator: " → "))
                .font(DS.label.weight(.medium)).foregroundStyle(DS.accent)
                .fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
            Text(direct ? "直接连接模式跳过策略组。" : core.mode == "global" && core.state == .running
                 ? "全局代理使用 FINAL 的入口；折叠与展开只影响展示。"
                 : "专用规则优先匹配；未命中时使用此默认出口。导入组需要被引用才会承担流量。")
                .font(DS.small).foregroundStyle(DS.ink2)
        }.card()
    }

    @ViewBuilder private func profile(_ name: String) -> some View {
        let active = name == activeName
        let key = "profile|\(profilePath(name))"
        DisclosureGroup(isExpanded: expansion(key, default: active, forced: active && !filter.isEmpty)) {
            VStack(alignment: .leading, spacing: DS.gap) {
                if active {
                    if core.loadingCatalog && core.policyGroups.isEmpty { ProgressView("正在读取策略组…").font(DS.small) }
                    else if organization.sections(filter: filter).isEmpty {
                        EmptyState(icon: "square.stack", title: filter.isEmpty ? "还没有策略组" : "没有匹配的策略组",
                                   detail: filter.isEmpty ? "新建自己的策略组，或在节点页添加订阅。" : "清除搜索后查看全部策略。",
                                   action: filter.isEmpty ? ("新建组", { edit(nil) }) : ("清除搜索", { filter = "" }))
                    } else {
                        ForEach(organization.sections(filter: filter)) { section in
                            sourceSection(section, organization: organization, active: true, path: core.configPath)
                        }
                    }
                } else {
                    InactivePolicyPreview(name: name, expanded: expanded[key] ?? false,
                                          expansion: { section in expansion("section|\(profilePath(name))|\(section)", default: section == "mine") },
                                          switchProfile: requestSwitch)
                }
            }.padding(.top, 14)
        } label: {
            HStack(spacing: 10) {
                Image(systemName: active ? "doc.text.fill" : "doc.text").foregroundStyle(active ? DS.accent : DS.ink2)
                Text(name).font(DS.heading)
                StatusBadge(text: active ? "当前启用" : "未启用 · 只读预览", tone: active ? DS.ok : DS.off)
                Spacer()
                if active { Text("\(core.policyGroups.count) 个组").font(DS.small).foregroundStyle(DS.ink2) }
            }
        }
        .padding(DS.cardPadding).glass()
    }

    private func sourceSection(_ section: PolicySourceSection, organization: PolicyOrganization, active: Bool, path: String) -> some View {
        DisclosureGroup(isExpanded: expansion("section|\(path)|\(section.id)", default: section.isLocal, forced: !filter.isEmpty)) {
            VStack(spacing: DS.gap) {
                ForEach(section.groups) { group in
                    GroupSection(group: group, filter: filter, interactive: active, usage: organization.usage(of: group.group),
                                 onEdit: section.isLocal ? { edit(group) } : nil,
                                 onCopy: { copy(group) },
                                 onDefault: organization.defaultPolicy != group.group ? { makeDefault(group) } : nil,
                                 onRule: { references(group, link: true) }, onReferences: { references(group, link: false) })
                }
            }.padding(.top, 10)
        } label: {
            HStack {
                Text(section.title).font(DS.label.weight(.semibold))
                Text("\(section.groups.count)").font(DS.caption.monospacedDigit()).foregroundStyle(DS.ink3)
                Spacer()
                if section.groups.contains(where: { $0.group == organization.defaultPolicy }) { Text("含默认出口").font(DS.caption).foregroundStyle(DS.accent) }
            }
        }
    }

    private func expansion(_ key: String, default value: Bool, forced: Bool = false) -> Binding<Bool> {
        Binding(get: { forced || (expanded[key] ?? value) }, set: { on in
            expanded[key] = on; core.preferences.set(expanded, forKey: "policy.expansions.v1")
        })
    }
    private func profilePath(_ name: String) -> String {
        URL(fileURLWithPath: core.configPath).deletingLastPathComponent().appendingPathComponent(name).appendingPathExtension("conf").path
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
    private func requestSwitch(_ name: String) {
        if draft.hasChanges { pendingSwitch = name } else { switchProfile(name) }
    }
    private func switchProfile(_ name: String, copyDraft: Bool = false) {
        pendingSwitch = nil; switching = true
        Task {
            defer { switching = false }
            do {
                if copyDraft { try await core.copyDraftAndSwitch(to: name, text: draft.text) }
                else { try await core.switchProfile(to: name) }
                refreshText()
            } catch { core.lastActionError = error.localizedDescription }
        }
    }
}

private struct InactivePolicyPreview: View {
    @EnvironmentObject var core: Core
    let name: String
    let expanded: Bool
    let expansion: (String) -> Binding<Bool>
    let switchProfile: (String) -> Void
    @State private var snapshot: ProfilePolicySnapshot?
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("仅预览此配置，展开不会改变当前运行方案。").font(DS.small).foregroundStyle(DS.ink2)
                Spacer()
                Button("切换并启用") { switchProfile(name) }.glassButton(prominent: true).disabled(!core.canChangeProfile)
            }
            if let error { Text(error).font(DS.small).foregroundStyle(DS.warn) }
            else if let snapshot {
                let org = snapshot.organization
                if let root = org.defaultPolicy { Text("默认路径：" + org.chain(from: root).map(subscriptionNodeLabel).joined(separator: " → ")).font(DS.small).foregroundStyle(DS.ink2) }
                ForEach(org.sections()) { section in
                    DisclosureGroup(isExpanded: expansion(section.id)) {
                        VStack(spacing: DS.gap) {
                            ForEach(section.groups) { group in GroupSection(group: group, interactive: false, usage: org.usage(of: group.group)) }
                        }.padding(.top, 10)
                    } label: { Text("\(section.title)（\(section.groups.count)）").font(DS.label.weight(.semibold)) }
                }
            } else { ProgressView("正在读取此配置…").font(DS.small) }
        }
        .task(id: "\(name)|\(expanded)") {
            guard expanded else { return }
            do { snapshot = try await core.profilePolicySnapshot(name); error = nil }
            catch { self.error = error.localizedDescription }
        }
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
                Text("规则会插入 FINAL 之前，只处理匹配的请求。").font(DS.small).foregroundStyle(DS.ink2)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        Text(request.organization.chain(from: request.name).map(subscriptionNodeLabel).joined(separator: " → ")).font(DS.label).textSelection(.enabled)
                        let rules = request.organization.ruleReferences(to: request.name)
                        let parents = request.organization.parentReferences(to: request.name)
                        if rules.isEmpty && parents.isEmpty { Text("此组尚未被规则或其他组引用，不承担路由流量。").font(DS.small).foregroundStyle(DS.ink2) }
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
