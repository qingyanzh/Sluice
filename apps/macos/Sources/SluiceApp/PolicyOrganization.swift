import Foundation

// MARK: - Read model

/// A profile's text plus its expanded catalog, for previewing a profile that is not active.
struct ProfilePolicySnapshot {
    let name: String
    let path: String
    let text: String
    let catalog: SubscriptionCatalog
    var organization: PolicyOrganization { PolicyOrganization(document: StructuredConfig(text), groups: catalog.groups, nodes: catalog.nodes) }
}

/// One fold on the policy page: the user's own groups, or the groups of one subscription source.
struct PolicySourceSection: Identifiable {
    let id: String
    let title: String
    let groups: [PolicyGroup]
    let isLocal: Bool
}

/// Answers three questions about a profile's policy groups, independent of the
/// current UI state: where each group comes from (`source`), who uses it (`usage`)
/// and where traffic ends up (`chain`). Also used for read-only previews.
struct PolicyOrganization {
    let document: StructuredConfig
    let groups: [PolicyGroup]
    let nodes: [SubscriptionNode]

    var defaultPolicy: String? { document.rules.first(where: { $0.value.isFinal })?.value.policy }
    var byName: [String: PolicyGroup] { Dictionary(groups.map { ($0.group, $0) }, uniquingKeysWith: { first, _ in first }) }

    // MARK: Source

    /// The subscription source a group belongs to, or nil for the user's own groups:
    /// - `@Source/Name`: imported from an independent `[Subscription]` source;
    /// - a group with `policy-path`: a legacy group that is its own source.
    func source(of name: String) -> String? {
        if let imported = importedSource(of: name) { return imported }
        let legacy = document.groups.first { $0.value.name == name && $0.value.parameter("policy-path") != nil }
        return legacy?.value.name
    }

    private func importedSource(of name: String) -> String? {
        guard name.hasPrefix("@"), let slash = name.firstIndex(of: "/") else { return nil }
        return String(name[name.index(after: name.startIndex)..<slash]).removingPercentEncoding
    }

    /// "我的策略组" first, then one section per source in natural order.
    func sections(filter: String = "") -> [PolicySourceSection] {
        let visible = groups.filter { matches($0, query: filter.trimmingCharacters(in: .whitespacesAndNewlines)) }
        let local = visible.filter { source(of: $0.group) == nil }
        let sources = Set(visible.compactMap { source(of: $0.group) })
            .sorted { $0.localizedStandardCompare($1) == .orderedAscending }

        var result: [PolicySourceSection] = []
        if !local.isEmpty {
            result.append(PolicySourceSection(id: "mine", title: "我的策略组", groups: local, isLocal: true))
        }
        for source in sources {
            result.append(PolicySourceSection(id: "source:\(source)", title: "\(source) · 订阅策略组",
                                              groups: visible.filter { self.source(of: $0.group) == source }, isLocal: false))
        }
        return result
    }

    /// A group matches by its own label, any option's label, or its source name.
    private func matches(_ group: PolicyGroup, query: String) -> Bool {
        guard !query.isEmpty else { return true }
        let hit = { (text: String) in text.localizedCaseInsensitiveContains(query) }
        return hit(subscriptionNodeLabel(group.group))
            || group.options.contains { hit(subscriptionNodeLabel($0.name)) }
            || source(of: group.group).map(hit) ?? false
    }

    // MARK: Usage

    func ruleReferences(to name: String) -> [StructuredConfig.Rule] { document.rules.map(\.value).filter { $0.policy == name } }
    func parentReferences(to name: String) -> [String] { groups.filter { $0.options.contains { $0.name == name } }.map(\.group) }

    /// e.g. "默认出口 · 规则引用 2 · 组引用 1", or "未引用".
    func usage(of name: String) -> String {
        var parts: [String] = []
        if defaultPolicy == name { parts.append("默认出口") }
        let rules = ruleReferences(to: name).filter { !$0.isFinal }.count
        if rules > 0 { parts.append("规则引用 \(rules)") }
        let parents = parentReferences(to: name).count
        if parents > 0 { parts.append("组引用 \(parents)") }
        return parts.isEmpty ? "未引用" : parts.joined(separator: " · ")
    }

    // MARK: Chain

    /// Follows each group's selected option (or its first) from `root` down to a node.
    /// Ends with "按连接分配" at a load-balance group and "循环引用" on a cycle.
    func chain(from root: String) -> [String] {
        let byName = byName
        var chain: [String] = []
        var seen: Set<String> = []
        var current = root
        while seen.insert(current).inserted {
            chain.append(current)
            guard let group = byName[current] else { return chain }  // reached a node
            if group.type == "load-balance" { return chain + ["按连接分配"] }
            let selected = group.options.first { $0.name == group.selected } ?? group.options.first
            guard let next = selected?.name else { return chain }
            current = next
        }
        return chain + ["循环引用"]
    }

    // MARK: Owned copy

    /// An editable local group equivalent to `group`.
    func ownedCopy(of group: PolicyGroup, named name: String) -> StructuredConfig.Group {
        let original = document.groups.first(where: { $0.value.name == group.group })?.value

        // A local group: copy it verbatim under the new name.
        if let original, original.parameter("policy-path") == nil {
            var copy = original
            copy.name = name
            return copy
        }

        var copy = StructuredConfig.Group()
        copy.name = name
        copy.type = group.type
        if let original {
            // A legacy `policy-path` group: keep its members and use it as a source.
            copy.members = original.members
            copy.sources = original.sources + (original.sources.contains(original.name) ? [] : [original.name])
        } else {
            // An imported group: pin each option to its node id within the same source.
            let source = source(of: group.group)
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

// MARK: - Edits

/// What to do with a group after saving it.
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

/// Lossless text-to-text edits used by the policy page. Saving always goes through the
/// core validator and an expected-text comparison before writing the config.
enum PolicyChanges {
    private static let ruleTypes = ["DOMAIN", "DOMAIN-SUFFIX", "PROCESS-NAME"]

    /// Adds a `ruleType,value,name` rule.
    static func associate(_ name: String, usage: PolicyGroupUse, in text: String) throws -> String {
        let value = usage.value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty, !value.contains(where: { ",\r\n".contains($0) }), ruleTypes.contains(usage.ruleType) else {
            throw APIError(message: "请填写有效的规则值。")
        }
        if usage.ruleType != "PROCESS-NAME", value.contains(where: { "/: #".contains($0) }) {
            throw APIError(message: "请填写域名，如 example.com。")
        }
        var rule = StructuredConfig.Rule()
        rule.type = usage.ruleType; rule.value = value; rule.policy = name
        var document = StructuredConfig(text)
        document.setRule(rule)
        return document.serialise()
    }

    /// Points every FINAL rule at `name`, adding one if there is none.
    static func setDefault(_ name: String, in text: String) -> String {
        var document = StructuredConfig(text)
        let finals = document.rules.filter { $0.value.isFinal }
        if finals.isEmpty {
            var rule = StructuredConfig.Rule()
            rule.type = "FINAL"; rule.policy = name
            document.setRule(rule)
        }
        for entry in finals {
            var rule = entry.value
            rule.policy = name
            document.setRule(rule, at: entry.id)
        }
        return document.serialise()
    }

    /// Creates `group`, or replaces `originalName` with it (renaming references),
    /// rejects cycles, then applies `usage`.
    static func upsert(_ group: StructuredConfig.Group, originalName: String?, usage: PolicyGroupUse,
                       in text: String, knownGroups: [PolicyGroup]) throws -> String {
        try validateName(group.name)
        var document = StructuredConfig(text)
        let original = originalName.flatMap { name in document.groups.first { $0.value.name == name } }
        if originalName != nil && original == nil { throw APIError(message: "原策略组已被删除，请刷新后重试。") }
        let renamed = originalName.flatMap { $0 != group.name ? $0 : nil }
        if group.name != originalName && (ConfigText.names(in: text).contains(group.name) || knownGroups.contains { $0.group == group.name }) {
            throw APIError(message: "这个名称已被使用，请选择其他名称。")
        }

        // Rename references before inserting lines, so physical indices remain valid.
        if let renamed { renameReferences(from: renamed, to: group.name, in: &document, except: original?.id) }
        document.setGroup(group, at: original?.id)
        try rejectCycles(from: group.name, in: document, knownGroups: knownGroups, removed: renamed)

        let saved = document.serialise()
        switch usage.mode {
        case .available: return saved
        case .defaultExit: return setDefault(group.name, in: saved)
        case .rule: return try associate(group.name, usage: usage, in: saved)
        }
    }

    /// Built-in policies and the `@` prefix (subscription groups) are reserved;
    /// separators would break the config line.
    private static func validateName(_ name: String) throws {
        let reservedPrefixes = ["@", "#", ";", "//", "["]
        guard !name.isEmpty, !["DIRECT", "REJECT"].contains(name),
              !reservedPrefixes.contains(where: name.hasPrefix),
              !name.contains(where: { ",=\r\n\"".contains($0) }) else {
            throw APIError(message: "请填写有效名称；@ 前缀保留给订阅策略。")
        }
    }

    private static func renameReferences(from old: String, to new: String, in document: inout StructuredConfig, except skipped: Int?) {
        for entry in document.groups where entry.id != skipped {
            var value = entry.value
            value.members = value.members.map { $0 == old ? new : $0 }
            if value != entry.value { document.setGroup(value, at: entry.id) }
        }
        for entry in document.rules where entry.value.policy == old {
            var rule = entry.value
            rule.policy = new
            document.setRule(rule, at: entry.id)
        }
    }

    /// Depth-first search over local groups plus the expanded catalog, from `root`.
    private static func rejectCycles(from root: String, in document: StructuredConfig, knownGroups: [PolicyGroup], removed: String?) throws {
        var members = Dictionary(knownGroups.map { ($0.group, $0.options.map(\.name)) }, uniquingKeysWith: { first, _ in first })
        if let removed { members.removeValue(forKey: removed) }
        for entry in document.groups { members[entry.value.name] = entry.value.members }

        var visiting: Set<String> = []
        var finished: Set<String> = []
        func visit(_ name: String) throws {
            guard let children = members[name], !finished.contains(name) else { return }
            guard visiting.insert(name).inserted else { throw APIError(message: "策略组存在循环引用，请调整成员关系。") }
            for child in children { try visit(child) }
            visiting.remove(name)
            finished.insert(name)
        }
        try visit(root)
    }
}
