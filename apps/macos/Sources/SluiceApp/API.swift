import Foundation

struct SubscriptionNode: Decodable, Identifiable, Hashable {
    let id: String
    let name: String
    let source: String
    var kind: String? = nil
    var server: String? = nil
    var port: UInt16? = nil
    var aliases: [String]? = nil
    var title: String { "\(source) / \(name)" }
}

struct SubscriptionCatalog: Decodable {
    let nodes: [SubscriptionNode]
    let groups: [PolicyGroup]
    var warnings: [String]? = nil
}

func subscriptionNodeLabel(_ reference: String) -> String {
    guard reference.hasPrefix("@"), let slash = reference.firstIndex(of: "/") else { return reference }
    let source = String(reference[reference.index(after: reference.startIndex)..<slash]).removingPercentEncoding
    let suffix = String(reference[reference.index(after: slash)...])
    let isGroup = suffix.hasPrefix("group/")
    let name = (isGroup ? String(suffix.dropFirst(6)) : suffix).removingPercentEncoding
    guard let source, let name else { return reference }
    return "\(source) / \(name)\(isGroup ? " · 策略组" : "")"
}

func subscriptionNodeReference(source: String, name: String) -> String {
    func component(_ value: String) -> String {
        value.unicodeScalars.map { scalar in
            if scalar.value < 33 || CharacterSet.controlCharacters.contains(scalar) || "%/,=|\"@".unicodeScalars.contains(scalar) {
                return String(scalar).utf8.map { String(format: "%%%02X", $0) }.joined()
            }
            return String(scalar)
        }.joined()
    }
    return "@\(component(source))/\(component(name))"
}

struct GroupOption: Decodable, Hashable {
    let name: String
    /// nil: not tested yet; -1: last health check failed.
    let latencyMs: Int?
    var error: String? = nil

    enum CodingKeys: String, CodingKey {
        case name, error
        case latencyMs = "latency_ms"
    }
}

struct PolicyGroup: Decodable, Identifiable, Hashable {
    let group: String
    let type: String
    var selected: String
    var options: [GroupOption]
    var url: String? = nil
    var interval: UInt64? = nil
    var tolerance: UInt64? = nil

    var id: String { group }
    var isSelectable: Bool { type == "select" }
    func updated(selected: String? = nil, options: [GroupOption]? = nil) -> Self {
        var copy = self
        if let selected { copy.selected = selected }
        if let options { copy.options = options }
        return copy
    }
}

struct RouteResult: Decodable {
    let target: String
    let rule: String
    let policy: String
    let outbound: String
}

struct Traffic: Decodable {
    let up: UInt64
    let down: UInt64
    let active: Int
}

struct DNSCache: Decodable {
    let entries: [DNSCacheEntry]
}

struct DNSCacheEntry: Decodable, Identifiable {
    let name: String
    let type: String
    let ttl: Int
    let answers: [String]

    var id: String { "\(type):\(name)" }

    func matches(_ query: String) -> Bool {
        query.isEmpty || ([name, type] + answers).contains { $0.localizedCaseInsensitiveContains(query) }
    }
}

struct DNSFlushResult: Decodable {
    let flushed: Int
}

struct APIError: LocalizedError {
    let message: String
    var status: Int? = nil
    var errorDescription: String? { message }
}

struct CoreStatus: Decodable {
    let pid: Int32
    let uid: UInt32
    let enhancedMode: Bool
    let config: String
    enum CodingKeys: String, CodingKey { case pid, uid, config; case enhancedMode = "enhanced_mode" }
}

/// Client for the core's control API (see src/api.rs).
struct APIClient {
    let port: Int
    let host: String
    let session: URLSession

    init(port: Int, session: URLSession = .shared, host: String = "127.0.0.1") {
        self.port = port
        self.host = host
        self.session = session
    }

    private func url(_ path: String) -> URL {
        URL(string: "http://\(host):\(port)\(path)")!
    }

    private func request(_ method: String, _ path: String, timeout: TimeInterval = 15) async throws -> Data {
        var req = URLRequest(url: url(path), timeoutInterval: timeout)
        req.httpMethod = method
        let (data, response) = try await session.data(for: req)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(status) else {
            let body = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
            throw APIError(message: body?["error"] as? String ?? "HTTP \(status)", status: status)
        }
        return data
    }

    private static func escape(_ s: String) -> String {
        s.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed.subtracting(CharacterSet(charactersIn: "&=+/?#%"))) ?? s
    }

    func status() async throws -> CoreStatus {
        try JSONDecoder().decode(CoreStatus.self, from: await request("GET", "/v1/status", timeout: 2))
    }

    func shutdown() async throws { _ = try await request("POST", "/v1/shutdown", timeout: 10) }

    func policies() async throws -> [PolicyGroup] {
        try JSONDecoder().decode([PolicyGroup].self, from: await request("GET", "/v1/policies"))
    }

    func select(group: String, option: String) async throws {
        _ = try await request("POST", "/v1/policies/\(Self.escape(group))?select=\(Self.escape(option))")
    }

    func test(group: String) async throws -> GroupTestResult {
        try JSONDecoder().decode(GroupTestResult.self, from: await request("POST", "/v1/policies/\(Self.escape(group))/test"))
    }

    func test(node: String) async throws -> NodeTestResult {
        try JSONDecoder().decode(NodeTestResult.self, from: await request("POST", "/v1/nodes/\(Self.escape(node))/test"))
    }

    func activeConnections() async throws -> [ActiveConnection] {
        try JSONDecoder().decode([ActiveConnection].self, from: await request("GET", "/v1/connections/active"))
    }

    func closeConnection(_ id: UInt64) async throws {
        _ = try await request("DELETE", "/v1/connections/\(id)")
    }

    func closeAllConnections() async throws {
        _ = try await request("DELETE", "/v1/connections")
    }

    func switchProfile(path: String) async throws {
        _ = try await request("POST", "/v1/profile?path=\(Self.escape(path))")
    }

    /// Cancellation closes URLSession's byte stream. A quiet stream times out so the
    /// caller can reconnect; the core normally sends a heartbeat every 15 seconds.
    func events(opened: @MainActor () async throws -> Void,
                receive: @MainActor (SSEFrame) async throws -> Void) async throws {
        var req = URLRequest(url: url("/v1/events"), timeoutInterval: 45)
        req.setValue("text/event-stream", forHTTPHeaderField: "Accept")
        let (bytes, response) = try await session.bytes(for: req)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard status == 200,
              (response as? HTTPURLResponse)?.value(forHTTPHeaderField: "Content-Type")?
                .lowercased().hasPrefix("text/event-stream") == true else {
            throw APIError(message: "事件流不可用 (HTTP \(status))", status: status)
        }
        try Task.checkCancellation()
        try await opened()
        var parser = SSEParser()
        for try await byte in bytes {
            try Task.checkCancellation()
            if let frame = try parser.append(byte) { try await receive(frame) }
        }
        throw APIError(message: "事件流已结束")
    }

    func mode() async throws -> String {
        let body = try JSONSerialization.jsonObject(with: await request("GET", "/v1/mode")) as? [String: Any]
        return body?["mode"] as? String ?? "rule"
    }

    func setMode(_ mode: String) async throws {
        _ = try await request("POST", "/v1/mode?set=\(Self.escape(mode))")
    }

    func traffic() async throws -> Traffic {
        try JSONDecoder().decode(Traffic.self, from: await request("GET", "/v1/traffic"))
    }

    /// Only a missing endpoint enables the overall-only compatibility history.
    func stats() async throws -> TrafficStats? {
        do {
            return try JSONDecoder().decode(TrafficStats.self, from: await request("GET", "/v1/stats"))
        } catch let error as APIError where error.status == 404 {
            return nil
        }
    }

    /// Older cores only report connection events in their logs.
    func connections() async throws -> [Connection]? {
        do {
            return try JSONDecoder().decode([Connection].self, from: await request("GET", "/v1/connections"))
        } catch let error as APIError where error.status == 404 {
            return nil
        }
    }

    func dns() async throws -> DNSCache {
        try JSONDecoder().decode(DNSCache.self, from: await request("GET", "/v1/dns"))
    }

    func flushDNS() async throws -> DNSFlushResult {
        try JSONDecoder().decode(DNSFlushResult.self, from: await request("POST", "/v1/dns/flush"))
    }

    func reload() async throws {
        _ = try await request("POST", "/v1/reload")
    }

    func exportDiagnostics(to output: URL) async throws -> URL {
        struct BundlePath: Decodable { let path: String }
        let data = try await request("GET", "/v1/diag?path=\(Self.escape(output.path))", timeout: 180)
        let result = try JSONDecoder().decode(BundlePath.self, from: data)
        guard result.path.hasPrefix("/") else { throw APIError(message: "诊断导出返回了无效的文件路径。") }
        return URL(fileURLWithPath: result.path)
    }

    func route(_ target: String) async throws -> RouteResult {
        try JSONDecoder().decode(RouteResult.self, from: await request("GET", "/v1/route?target=\(Self.escape(target))"))
    }
}
