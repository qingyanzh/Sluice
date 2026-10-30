import Foundation

/// `/v1/stats`: totals are bytes since core start; history values are bytes/second.
struct TrafficStats: Decodable {
    let up: UInt64
    let down: UInt64
    let active: Int
    let policies: [TrafficTotal]
    let nodes: [TrafficTotal]
    let history: [TrafficStatsSample]

    var policyNames: [String] {
        Set(policies.map(\.name) + history.flatMap { $0.policies.map(\.policy) }).sorted()
    }

    func rates(for policy: String?) -> [TrafficRatePoint] {
        history.map { sample in
            let rates = policy.flatMap { name in sample.policies.first { $0.policy == name } }
            return TrafficRatePoint(
                time: Date(timeIntervalSince1970: Double(sample.timeMs) / 1000),
                up: Double(policy == nil ? sample.up : rates?.up ?? 0),
                down: Double(policy == nil ? sample.down : rates?.down ?? 0)
            )
        }
    }
}

struct TrafficTotal: Decodable, Identifiable {
    let name: String
    let up: UInt64
    let down: UInt64
    var id: String { name }
}

struct TrafficStatsSample: Decodable {
    let timeMs: UInt64
    let up: UInt64
    let down: UInt64
    let policies: [PolicyRate]

    enum CodingKeys: String, CodingKey {
        case timeMs = "time_ms"
        case up, down, policies
    }
}

struct PolicyRate: Decodable {
    let policy: String
    let up: UInt64
    let down: UInt64
}

struct TrafficRatePoint: Identifiable {
    let time: Date
    let up: Double
    let down: Double
    var id: Date { time }
}

/// A memory-only, 600-second ring for older cores. Keep one observation per second
/// at most, using elapsed time between successful traffic reads (including idle reads).
/// Gaps remain gaps; a counter reset starts a new history rather than spiking a rate.
struct TrafficHistory {
    static let capacity = 600
    private var storage = [TrafficRatePoint?](repeating: nil, count: capacity)
    private var head = 0
    private var count = 0
    private var baseline: (traffic: Traffic, time: Date)?

    var samples: [TrafficRatePoint] {
        (0..<count).compactMap { storage[(head + $0) % Self.capacity] }
    }

    mutating func record(_ traffic: Traffic, at time: Date) {
        guard time.timeIntervalSince1970.isFinite else { return }
        guard let previous = baseline else {
            baseline = (traffic, time)
            return
        }
        let elapsed = time.timeIntervalSince(previous.time)
        guard elapsed > 0 else { return }
        if traffic.up < previous.traffic.up || traffic.down < previous.traffic.down {
            self = TrafficHistory()
            baseline = (traffic, time)
            return
        }
        guard elapsed >= 1 else { return }
        let sample = TrafficRatePoint(time: time,
                                      up: Double(traffic.up - previous.traffic.up) / elapsed,
                                      down: Double(traffic.down - previous.traffic.down) / elapsed)
        while count > 0, let oldest = storage[head], time.timeIntervalSince(oldest.time) >= 600 {
            storage[head] = nil
            head = (head + 1) % Self.capacity
            count -= 1
        }
        if count == Self.capacity {
            storage[head] = sample
            head = (head + 1) % Self.capacity
        } else {
            storage[(head + count) % Self.capacity] = sample
            count += 1
        }
        baseline = (traffic, time)
    }
}
