import Foundation

/// Open TCP connections; recent routing decisions use a separate ID namespace.
struct ActiveConnection: Decodable, Identifiable {
    let id: UInt64
    let startMs: UInt64
    let network: String
    let target: String
    let src: String?
    let rule: String
    let policy: String
    let chain: [String]
    let outbound: String
    let process: String?
    let up: UInt64
    let down: UInt64
    let rateUp: UInt64
    let rateDown: UInt64

    enum CodingKeys: String, CodingKey {
        case id, network, target, src, rule, policy, chain, outbound, process, up, down
        case startMs = "start_ms", rateUp = "rate_up", rateDown = "rate_down"
    }

    var policyChain: String { chain.joined(separator: " → ") }

    func matches(_ query: String) -> Bool {
        query.isEmpty || ([target, src ?? "", rule, policy, outbound, process ?? ""] + chain)
            .contains { $0.localizedCaseInsensitiveContains(query) }
    }

    static func displayOrder(_ lhs: Self, _ rhs: Self) -> Bool {
        (lhs.startMs, lhs.id) < (rhs.startMs, rhs.id)
    }

    /// Open/close events received during a snapshot request take precedence over
    /// that response. Merge individual IDs so busy streams cannot starve refreshes.
    static func reconcile(_ snapshot: [Self], current: [Self], changedIDs: Set<UInt64>) -> [Self] {
        let currentByID = Dictionary(current.map { ($0.id, $0) }, uniquingKeysWith: { _, latest in latest })
        var merged = Dictionary(snapshot.map { ($0.id, $0) }, uniquingKeysWith: { _, latest in latest })
        for id in changedIDs { merged[id] = currentByID[id] }
        return merged.values.sorted(by: displayOrder)
    }
}

struct NodeTestResult: Decodable {
    let node: String
    let outbound: String?
    let ok: Bool
    let connectMs: UInt64?
    let latencyMs: Int?
    let status: Int?
    let error: String?

    enum CodingKeys: String, CodingKey {
        case node, outbound, ok, status, error
        case connectMs = "connect_ms", latencyMs = "latency_ms"
    }
}

struct GroupTestResult: Decodable {
    let tested: String
    let selected: String
    let results: [GroupOption]
}

struct TrafficEvent: Decodable {
    let timeMs: UInt64
    let up: UInt64
    let down: UInt64
    let policies: [PolicyRate]
    let totalUp: UInt64
    let totalDown: UInt64
    let active: Int

    enum CodingKeys: String, CodingKey {
        case up, down, policies, active
        case timeMs = "time_ms", totalUp = "total_up", totalDown = "total_down"
    }
}

struct LogEvent: Decodable {
    let timeMs: UInt64
    let level: String
    let message: String

    enum CodingKeys: String, CodingKey {
        case level, message
        case timeMs = "time_ms"
    }
}

struct SSEFrame: Equatable {
    let event: String
    let data: String
}

/// Incremental UTF-8 SSE parser. CR, LF and CRLF work across arbitrary byte chunks.
/// Only a blank line dispatches data; comments and incomplete frames are ignored.
struct SSEParser {
    private var line: [UInt8] = []
    private var event = ""
    private var data: [String] = []
    private var dataSize = 0
    private var skipLF = false
    private var firstLine = true

    mutating func append(_ byte: UInt8) throws -> SSEFrame? {
        if skipLF {
            skipLF = false
            if byte == 10 { return nil }
        }
        if byte == 13 || byte == 10 {
            skipLF = byte == 13
            return consumeLine()
        }
        // Bound memory even if a server sends an unterminated line or frame.
        guard line.count + dataSize < 1_048_576 else {
            throw APIError(message: "事件流帧过大")
        }
        line.append(byte)
        return nil
    }

    private mutating func consumeLine() -> SSEFrame? {
        var text = String(decoding: line, as: UTF8.self)
        line.removeAll(keepingCapacity: true)
        if firstLine {
            firstLine = false
            if text.hasPrefix("\u{FEFF}") { text.removeFirst() }
        }
        if text.isEmpty {
            let frame = data.isEmpty ? nil : SSEFrame(event: event.isEmpty ? "message" : event, data: data.joined(separator: "\n"))
            event = ""
            data = []
            dataSize = 0
            return frame
        }
        if text.hasPrefix(":") { return nil }
        let parts = text.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
        var value = parts.count == 2 ? String(parts[1]) : ""
        if value.hasPrefix(" ") { value.removeFirst() }
        switch parts[0] {
        case "event": event = value
        case "data": data.append(value); dataSize += value.utf8.count + 1
        default: break
        }
        return nil
    }
}
