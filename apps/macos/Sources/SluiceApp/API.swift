import Foundation

struct GroupOption: Decodable, Hashable {
    let name: String
    /// nil: not tested yet; -1: last health check failed.
    let latencyMs: Int?

    enum CodingKeys: String, CodingKey {
        case name
        case latencyMs = "latency_ms"
    }
}

struct PolicyGroup: Decodable, Identifiable, Hashable {
    let group: String
    let type: String
    let selected: String
    let options: [GroupOption]

    var id: String { group }
    var isSelectable: Bool { type == "select" }
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

/// Client for the core's control API (see src/api.rs).
struct APIClient {
    let port: Int
    let session: URLSession

    init(port: Int, session: URLSession = .shared) {
        self.port = port
        self.session = session
    }

    private func url(_ path: String) -> URL {
        URL(string: "http://127.0.0.1:\(port)\(path)")!
    }

    private func request(_ method: String, _ path: String) async throws -> Data {
        var req = URLRequest(url: url(path), timeoutInterval: 15)
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
        s.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed.subtracting(CharacterSet(charactersIn: "&=+/?"))) ?? s
    }

    func policies() async throws -> [PolicyGroup] {
        try JSONDecoder().decode([PolicyGroup].self, from: await request("GET", "/v1/policies"))
    }

    func select(group: String, option: String) async throws {
        _ = try await request("POST", "/v1/policies/\(Self.escape(group))?select=\(Self.escape(option))")
    }

    func test(group: String) async throws {
        _ = try await request("POST", "/v1/policies/\(Self.escape(group))/test")
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

    func route(_ target: String) async throws -> RouteResult {
        try JSONDecoder().decode(RouteResult.self, from: await request("GET", "/v1/route?target=\(Self.escape(target))"))
    }
}
