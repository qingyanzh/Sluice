import Foundation

/// A lossless config document. Only explicitly edited entries are rendered again;
/// comments, unknown lines, section order and individual line endings remain intact.
struct StructuredConfig {
    struct Line {
        var text: String
        var ending: String
    }

    struct Entry<Value>: Identifiable {
        let id: Int // physical line, valid for this document snapshot
        let value: Value
    }

    struct Rule: Equatable {
        static let types = ["DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "GEOSITE", "IP-CIDR", "IP-CIDR6", "GEOIP", "IP-ASN", "RULE-SET", "DOMAIN-SET", "DST-PORT", "DEST-PORT", "IN-PORT", "SRC-IP", "PROTOCOL", "PROCESS-NAME", "URL-REGEX", "AND", "OR", "NOT", "FINAL"]
        var type = "DOMAIN-SUFFIX"
        var value = ""
        var policy = "DIRECT"
        var options = ""
        var isFinal: Bool { type.uppercased() == "FINAL" }

        init() {}
        init?(line: String) {
            let parts = StructuredConfig.splitRule(line)
            guard let kind = parts.first, Self.types.contains(kind.uppercased()) else { return nil }
            type = kind
            if isFinal {
                guard parts.count >= 2, !parts[1].isEmpty else { return nil }
                policy = parts[1]
                options = parts.dropFirst(2).joined(separator: ",")
            } else {
                guard parts.count >= 3, !parts[1].isEmpty, !parts[2].isEmpty else { return nil }
                value = parts[1]
                policy = parts[2]
                options = parts.dropFirst(3).joined(separator: ",")
            }
        }
        mutating func normalise() {
            type = StructuredConfig.trim(type)
            value = isFinal ? "" : StructuredConfig.trim(value)
            policy = StructuredConfig.trim(policy)
            options = StructuredConfig.trim(options)
        }
        var serialised: String {
            let fields = isFinal ? [type, policy] : [type, value, policy]
            return (fields + (options.isEmpty ? [] : [options])).joined(separator: ",")
        }
    }

    struct Group: Equatable {
        static let types = ["select", "url-test", "fallback", "load-balance"]
        var name = ""
        var type = "select"
        var members: [String] = []
        // Keep all parameters, including subscription/filter/tolerance and future keys.
        var parameters: [String] = []
        var isAutomatic: Bool { type.lowercased() != "select" }
        var url: String {
            get { parameter("url") ?? "" }
            set { setParameter("url", to: newValue) }
        }
        var interval: String {
            get { parameter("interval") ?? "" }
            set { setParameter("interval", to: newValue) }
        }
        var sources: [String] {
            get { (parameter("use") ?? "").split(separator: "|").map { StructuredConfig.trim(String($0)) }.filter { !$0.isEmpty } }
            set { setParameter("use", to: newValue.joined(separator: "|")) }
        }
        var nodeFilter: String {
            get { parameter("node-filter") ?? "" }
            set { setParameter("node-filter", to: newValue.isEmpty ? "" : "\"\(newValue)\"") }
        }
        var importsGroups: Bool {
            get { parameter("import-groups") == "true" }
            set { setParameter("import-groups", to: newValue ? "true" : "false") }
        }

        init() {}
        init?(line: String) {
            guard let eq = line.firstIndex(of: "=") else { return nil }
            name = StructuredConfig.trim(String(line[..<eq]))
            var quoted = false
            let parts = line[line.index(after: eq)...].split(omittingEmptySubsequences: false) {
                if $0 == "\"" { quoted.toggle() }
                return $0 == "," && !quoted
            }.map { StructuredConfig.trim(String($0)) }.filter { !$0.isEmpty }
            guard !name.isEmpty, let kind = parts.first, Self.types.contains(kind.lowercased()) else { return nil }
            type = kind
            members = parts.dropFirst().filter { !$0.contains("=") }
            parameters = parts.dropFirst().filter { $0.contains("=") }
        }
        func parameter(_ key: String) -> String? {
            parameters.last { Self.key($0) == key }.map {
                let value = StructuredConfig.trim(String($0[$0.index(after: $0.firstIndex(of: "=")!)...]))
                if value.count >= 2, value.first == "\"", value.last == "\"" {
                    return String(value.dropFirst().dropLast())
                }
                return value
            }
        }
        private static func key(_ parameter: String) -> String {
            StructuredConfig.trim(String(parameter.prefix { $0 != "=" })).lowercased()
        }
        mutating func setParameter(_ key: String, to value: String) {
            guard parameter(key) != (value.isEmpty ? nil : value) else { return }
            if let index = parameters.lastIndex(where: { Self.key($0) == key }) {
                parameters[index] = "\(key)=\(value)"
                if value.isEmpty { parameters.removeAll { Self.key($0) == key } }
            } else if !value.isEmpty {
                parameters.append("\(key)=\(value)")
            }
        }
        var serialised: String { "\(name) = " + ([type] + members + parameters).joined(separator: ", ") }
    }

    private var lines: [Line] = []
    init(_ text: String) {
        // Split by Unicode scalars: CRLF is one Swift Character, but two scalars.
        let scalars = text.unicodeScalars
        var start = scalars.startIndex
        var cursor = start
        while cursor < scalars.endIndex {
            if scalars[cursor] == "\n" || scalars[cursor] == "\r" {
                let end = cursor
                var next = scalars.index(after: cursor)
                if scalars[cursor] == "\r", next < scalars.endIndex, scalars[next] == "\n" { next = scalars.index(after: next) }
                lines.append(Line(text: String(scalars[start..<end]), ending: String(scalars[cursor..<next])))
                start = next
                cursor = next
            } else { cursor = scalars.index(after: cursor) }
        }
        if start < scalars.endIndex { lines.append(Line(text: String(scalars[start...]), ending: "")) }
    }
    func serialise() -> String { lines.map { $0.text + $0.ending }.joined() }
    var rules: [Entry<Rule>] { indices(in: "Rule").compactMap { i in Rule(line: Self.trim(lines[i].text)).map { Entry(id: i, value: $0) } } }
    var groups: [Entry<Group>] { indices(in: "Proxy Group").compactMap { i in Group(line: Self.trim(lines[i].text)).map { Entry(id: i, value: $0) } } }
    var subscriptionNames: [String] {
        let independent = ConfigText.lines(of: "Subscription", in: serialise()).compactMap {
            $0.split(separator: "=", maxSplits: 1).first.map { Self.trim(String($0)) }
        }
        return independent + groups.filter { $0.value.parameter("policy-path") != nil }.map { $0.value.name }
    }
    var policies: [String] {
        let proxies = indices(in: "Proxy").compactMap { i -> String? in
            guard let eq = lines[i].text.firstIndex(of: "=") else { return nil }
            return Self.trim(String(lines[i].text[..<eq]))
        }
        var seen: Set<String> = []
        return (["DIRECT", "REJECT"] + groups.map { $0.value.name } + proxies).filter { !$0.isEmpty && seen.insert($0).inserted }
    }
    func unparsedCount(in section: String) -> Int {
        indices(in: section).count - (section == "Rule" ? rules.count : groups.count)
    }
    mutating func setRule(_ rule: Rule, at id: Int? = nil) {
        if let id {
            guard let entry = rules.first(where: { $0.id == id }), entry.value != rule else { return }
            replace(rule.serialised, at: id)
        } else {
            // New rules must precede FINAL to be reachable.
            insert(rule.serialised, in: "Rule", before: rules.first(where: { $0.value.isFinal })?.id)
        }
    }
    mutating func setGroup(_ group: Group, at id: Int? = nil) {
        if let id {
            guard let entry = groups.first(where: { $0.id == id }), entry.value != group else { return }
            replace(group.serialised, at: id)
        } else { insert(group.serialised, in: "Proxy Group") }
    }
    mutating func delete(_ id: Int, in section: String) {
        guard indices(in: section).contains(id) else { return }
        lines.remove(at: id)
    }
    /// Swap entry contents, leaving intervening comments and blank lines in place.
    mutating func move(_ id: Int, by offset: Int, in section: String) {
        let entries = section == "Rule" ? rules.map(\.id) : groups.map(\.id)
        guard let index = entries.firstIndex(of: id), entries.indices.contains(index + offset) else { return }
        let other = entries[index + offset]
        let text = lines[id].text
        lines[id].text = lines[other].text
        lines[other].text = text
    }
    private mutating func replace(_ text: String, at id: Int) {
        let indent = String(lines[id].text.prefix { $0 == " " || $0 == "\t" })
        lines[id].text = indent + text
    }
    private mutating func insert(_ text: String, in section: String, before: Int? = nil) {
        let newline = lines.first(where: { !$0.ending.isEmpty })?.ending ?? "\n"
        let headers = lines.indices.filter { Self.header(lines[$0].text) == section }
        if let header = headers.last {
            let end = lines.indices.first { $0 > header && Self.header(lines[$0].text) != nil } ?? lines.count
            let index = before ?? end
            if index > 0 && lines[index - 1].ending.isEmpty { lines[index - 1].ending = newline }
            lines.insert(Line(text: text, ending: newline), at: index)
        } else {
            if let last = lines.indices.last, lines[last].ending.isEmpty { lines[last].ending = newline }
            lines.append(Line(text: "[\(section)]", ending: newline))
            lines.append(Line(text: text, ending: newline))
        }
    }
    private func indices(in section: String) -> [Int] {
        var current = ""
        return lines.indices.filter { i in
            let text = Self.trim(lines[i].text)
            if let header = Self.header(text) { current = header; return false }
            return current == section && !text.isEmpty && !["#", ";", "//"].contains(where: text.hasPrefix)
        }
    }
    private static func header(_ line: String) -> String? {
        let line = trim(line)
        guard line.hasPrefix("["), line.hasSuffix("]") else { return nil }
        return trim(String(line.dropFirst().dropLast()))
    }
    static func trim(_ value: String) -> String { value.trimmingCharacters(in: .whitespacesAndNewlines) }
    /// Mirrors the core's comma splitting for AND/OR/NOT and regex values.
    static func splitRule(_ line: String) -> [String] {
        var depth = 0
        var start = line.startIndex
        var result: [String] = []
        for index in line.indices {
            switch line[index] {
            case "(": depth += 1
            case ")": depth -= 1
            case "," where depth == 0:
                result.append(trim(String(line[start..<index])))
                start = line.index(after: index)
            default: break
            }
        }
        result.append(trim(String(line[start...])))
        return result
    }
}
