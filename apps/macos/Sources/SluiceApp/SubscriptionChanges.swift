import Foundation

/// Rename the source identity and its references together, leaving addresses and
/// unrelated text alone. Node/group names after the source prefix stay unchanged.
enum SubscriptionChanges {
    static func reference(_ value: String, from old: String, to new: String, legacy: Bool = false) -> String {
        if legacy && value == old { return new }
        let prefix = subscriptionNodeReference(source: old, name: "")
        guard value.hasPrefix(prefix) else { return value }
        return subscriptionNodeReference(source: new, name: "") + value.dropFirst(prefix.count)
    }

    static func validateName(_ name: String) throws {
        guard !name.isEmpty, name == name.trimmingCharacters(in: .whitespacesAndNewlines),
              !["DIRECT", "REJECT"].contains(name), !["@", "#", ";", "//", "["].contains(where: name.hasPrefix),
              !name.contains(where: { "|,=\"\r\n".contains($0) }) else { throw APIError(message: "请填写有效的订阅名称，不能包含 |、逗号、等号或换行。") }
    }

    static func rename(_ old: String, to new: String, in text: String) throws -> String {
        try validateName(new)
        guard old != new else { return text }
        guard let source = SubscriptionSource.all(in: text, statuses: []).first(where: { $0.name == old }) else {
            throw APIError(message: "订阅已被修改，请刷新后重试。")
        }
        guard !ConfigText.names(in: text).contains(new) else { throw APIError(message: "名称「\(new)」已被使用。") }
        let section = source.isLegacy ? "Proxy Group" : "Subscription"
        guard let line = ConfigText.lines(of: section, in: text).first(where: { $0.split(separator: "=", maxSplits: 1).first.map { StructuredConfig.trim(String($0)) } == old }),
              let equal = line.firstIndex(of: "="),
              let renamed = ConfigText.replace(old, in: section, with: new + " " + line[equal...], of: text) else {
            throw APIError(message: "找不到这个订阅，请刷新后重试。")
        }
        var document = StructuredConfig(renamed)
        for entry in document.groups {
            var group = entry.value
            group.sources = group.sources.map { $0 == old ? new : $0 }
            group.members = group.members.map { reference($0, from: old, to: new, legacy: source.isLegacy) }
            document.setGroup(group, at: entry.id)
        }
        for entry in document.rules {
            var rule = entry.value
            rule.policy = reference(rule.policy, from: old, to: new, legacy: source.isLegacy)
            document.setRule(rule, at: entry.id)
        }
        return document.serialise()
    }
}
