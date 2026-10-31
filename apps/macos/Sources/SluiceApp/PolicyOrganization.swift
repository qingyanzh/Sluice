import Foundation

struct ProfilePolicySnapshot {
    let name: String
    let path: String
    let text: String
    let catalog: SubscriptionCatalog
    var organization: PolicyOrganization { PolicyOrganization(document: StructuredConfig(text), groups: catalog.groups, nodes: catalog.nodes) }
}

struct PolicySourceSection: Identifiable {
    let id: String
    let title: String
    let groups: [PolicyGroup]
    let isLocal: Bool
}

/// Ownership and references are independent of accordion presentation and current
/// selection. This model is also used for read-only previews of inactive profiles.
struct PolicyOrganization {
    let document: StructuredConfig
    let groups: [PolicyGroup]
    let nodes: [SubscriptionNode]

    var defaultPolicy: String? { document.rules.first(where: { $0.value.isFinal })?.value.policy }
    var byName: [String: PolicyGroup] { Dictionary(groups.map { ($0.group, $0) }, uniquingKeysWith: { first, _ in first }) }

    func source(of name: String) -> String? {
        if name.hasPrefix("@"), let slash = name.firstIndex(of: "/") {
            return String(name[name.index(after: name.startIndex)..<slash]).removingPercentEncoding
        }
        return document.groups.first { $0.value.name == name && $0.value.parameter("policy-path") != nil }?.value.name
    }

    func sections(filter: String = "") -> [PolicySourceSection] {
        let query = filter.trimmingCharacters(in: .whitespacesAndNewlines)
        let visible = groups.filter { group in
            query.isEmpty || subscriptionNodeLabel(group.group).localizedCaseInsensitiveContains(query)
                || group.options.contains { subscriptionNodeLabel($0.name).localizedCaseInsensitiveContains(query) }
                || (source(of: group.group)?.localizedCaseInsensitiveContains(query) ?? false)
        }
        let local = visible.filter { source(of: $0.group) == nil }
        let sources = Set(visible.compactMap { source(of: $0.group) }).sorted { $0.localizedStandardCompare($1) == .orderedAscending }
        return (local.isEmpty ? [] : [PolicySourceSection(id: "mine", title: "我的策略组", groups: local, isLocal: true)])
            + sources.map { source in
                PolicySourceSection(id: "source:\(source)", title: "\(source) · 订阅策略组", groups: visible.filter { self.source(of: $0.group) == source }, isLocal: false)
            }
    }

    func ruleReferences(to name: String) -> [StructuredConfig.Rule] { document.rules.map(\.value).filter { $0.policy == name } }
    func parentReferences(to name: String) -> [String] { groups.filter { $0.options.contains { $0.name == name } }.map(\.group) }
    func usage(of name: String) -> String {
        var parts: [String] = []
        if defaultPolicy == name { parts.append("默认出口") }
        let rules = ruleReferences(to: name).filter { !$0.isFinal }.count
        if rules > 0 { parts.append("规则引用 \(rules)") }
        let parents = parentReferences(to: name).count
        if parents > 0 { parts.append("组引用 \(parents)") }
        return parts.isEmpty ? "未引用" : parts.joined(separator: " · ")
    }

    func chain(from root: String) -> [String] {
        var current = root
        var seen: Set<String> = []
        var chain: [String] = []
        while seen.insert(current).inserted {
            chain.append(current)
            guard let group = byName[current] else { return chain }
            if group.type == "load-balance" { chain.append("按连接分配"); return chain }
            guard let next = group.options.first(where: { $0.name == group.selected })?.name ?? group.options.first?.name else { return chain }
            current = next
        }
        chain.append("循环引用")
        return chain
    }

    func ownedCopy(of group: PolicyGroup, named name: String) -> StructuredConfig.Group {
        var copy = StructuredConfig.Group()
        copy.name = name; copy.type = group.type
        let source = source(of: group.group)
        if let original = document.groups.first(where: { $0.value.name == group.group })?.value {
            if original.parameter("policy-path") == nil {
                copy = original; copy.name = name
                return copy
            }
            copy.members = original.members
            copy.sources = original.sources + (original.sources.contains(original.name) ? [] : [original.name])
        } else {
            copy.members = group.options.map { option in
                nodes.first { ($0.aliases ?? []).contains(option.name) && (source == nil || $0.source == source) }?.id ?? option.name
            }
        }
        copy.url = group.url ?? ""
        copy.interval = group.interval.map(String.init) ?? ""
        if let tolerance = group.tolerance { copy.parameters.append("tolerance=\(tolerance)") }
        return copy
    }
}

struct PolicyGroupUse: Equatable {
    enum Mode: String, CaseIterable { case available, defaultExit, rule
        var title: String {
            switch self { case .available: "保存供其他组引用"; case .defaultExit: "设为默认出口"; case .rule: "关联专用规则" }
        }
    }
    var mode = Mode.available
    var ruleType = "DOMAIN-SUFFIX"
    var value = ""
}

/// Lossless mutations used by the policy page. Saving always goes through the
/// core validator and an expected-text comparison before writing the config.
enum PolicyChanges {
    static func associate(_ name: String, usage: PolicyGroupUse, in text: String) throws -> String {
        let value = usage.value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty, !value.contains(where: { ",\r\n".contains($0) }),
              ["DOMAIN", "DOMAIN-SUFFIX", "PROCESS-NAME"].contains(usage.ruleType) else { throw APIError(message: "请填写有效的规则值。") }
        if usage.ruleType != "PROCESS-NAME", value.contains(where: { "/: #".contains($0) }) { throw APIError(message: "请填写域名，如 example.com。") }
        var rule = StructuredConfig.Rule(); rule.type = usage.ruleType; rule.value = value; rule.policy = name
        var document = StructuredConfig(text); document.setRule(rule)
        return document.serialise()
    }
    static func setDefault(_ name: String, in text: String) -> String {
        var document = StructuredConfig(text)
        let finals = document.rules.filter { $0.value.isFinal }
        if finals.isEmpty {
            var rule = StructuredConfig.Rule(); rule.type = "FINAL"; rule.policy = name
            document.setRule(rule)
        } else {
            for entry in finals { var rule = entry.value; rule.policy = name; document.setRule(rule, at: entry.id) }
        }
        return document.serialise()
    }

    static func upsert(_ group: StructuredConfig.Group, originalName: String?, usage: PolicyGroupUse,
                       in text: String, knownGroups: [PolicyGroup]) throws -> String {
        guard !group.name.isEmpty, !["DIRECT", "REJECT"].contains(group.name), !["@", "#", ";", "//", "["].contains(where: group.name.hasPrefix), !group.name.contains(where: { ",=\r\n\"".contains($0) }) else {
            throw APIError(message: "请填写有效名称；@ 前缀保留给订阅策略。")
        }
        var document = StructuredConfig(text)
        let original = originalName.flatMap { name in document.groups.first { $0.value.name == name } }
        if originalName != nil && original == nil { throw APIError(message: "原策略组已被删除，请刷新后重试。") }
        if group.name != originalName && (ConfigText.names(in: text).contains(group.name) || knownGroups.contains { $0.group == group.name }) {
            throw APIError(message: "这个名称已被使用，请选择其他名称。")
        }
        // Rename references before inserting lines, so physical indices remain valid.
        if let old = originalName, old != group.name {
            for entry in document.groups where entry.id != original?.id {
                var value = entry.value
                value.members = value.members.map { $0 == old ? group.name : $0 }
                if value != entry.value { document.setGroup(value, at: entry.id) }
            }
            for entry in document.rules where entry.value.policy == old {
                var rule = entry.value; rule.policy = group.name; document.setRule(rule, at: entry.id)
            }
        }
        document.setGroup(group, at: original?.id)
        var graph = Dictionary(knownGroups.map { ($0.group, $0.options.map(\.name)) }, uniquingKeysWith: { first, _ in first })
        if let originalName, originalName != group.name { graph.removeValue(forKey: originalName) }
        for entry in document.groups { graph[entry.value.name] = entry.value.members }
        var visiting: Set<String> = []; var finished: Set<String> = []
        func visit(_ name: String) throws {
            guard graph[name] != nil, !finished.contains(name) else { return }
            guard visiting.insert(name).inserted else { throw APIError(message: "策略组存在循环引用，请调整成员关系。") }
            for member in graph[name] ?? [] { try visit(member) }
            visiting.remove(name); finished.insert(name)
        }
        try visit(group.name)
        var saved = document.serialise()
        switch usage.mode {
        case .available: break
        case .defaultExit: saved = setDefault(group.name, in: saved)
        case .rule:
            saved = try associate(group.name, usage: usage, in: saved)
        }
        return saved
    }
}
