import Foundation

/// A lease is invalidated on *every* handoff, including disconnect/reconnect
/// while an HTTP request is in flight. Check it again after awaiting a response.
struct LiveRateSource {
    enum Source { case events, poll }
    struct Lease: Equatable {
        fileprivate let source: Source
        fileprivate let revision: UInt64
    }
    private(set) var connected = false
    private var revision: UInt64 = 0
    var source: Source { connected ? .events : .poll }

    mutating func setConnected(_ connected: Bool) {
        guard self.connected != connected else { return }
        self.connected = connected
        revision &+= 1
    }

    func lease(for source: Source) -> Lease? {
        source == self.source ? Lease(source: source, revision: revision) : nil
    }

    func accepts(_ lease: Lease) -> Bool {
        lease.source == source && lease.revision == revision
    }
}

/// Three-tick EMA (alpha = 2 / (3 + 1)). Idle is exact after two zero
/// observations, independently for upload and download. The first tick is seeded.
struct RateSmoother {
    private(set) var value: Double = 0
    private var seeded = false
    private var zeroTicks = 0

    @discardableResult mutating func update(_ raw: Double) -> Double {
        guard raw.isFinite else { return value }
        let sample = max(0, raw)
        zeroTicks = sample == 0 ? min(2, zeroTicks + 1) : 0
        value = !seeded || zeroTicks >= 2 ? sample : value + 0.5 * (sample - value)
        seeded = true
        return value
    }
}

struct FormattedRate: Equatable {
    let number: String
    let unit: String
    var text: String { "\(number) \(unit)/s" }
}

/// Stateful unit selection; formatting itself has no UI or clock dependency.
/// Promote at 1.0 of the next unit, demote only below 0.9 of the current unit.
struct RateUnitFormatter {
    var radix: Double = 1024
    /// KB is the smallest unit the app shows (B and B/s are never displayed).
    var minimumUnit = 1
    var fixedWidth = false
    private(set) var unitIndex = 0

    mutating func format(_ raw: Double) -> FormattedRate {
        let bytes = raw.isFinite ? max(0, raw) : 0
        unitIndex = max(minimumUnit, unitIndex)
        if bytes == 0 { unitIndex = minimumUnit }
        while unitIndex < 4, bytes >= pow(radix, Double(unitIndex + 1)) { unitIndex += 1 }
        while unitIndex > minimumUnit, bytes < 0.9 * pow(radix, Double(unitIndex)) { unitIndex -= 1 }
        let value = bytes / pow(radix, Double(unitIndex))
        let number: String
        if fixedWidth {
            // Whole numbers, at most three digits ("0", "12", "999"): the menu bar item
            // stays narrow. Capping avoids "1000" just below a unit transition.
            // The renderer right-aligns it in a fixed box; unit selection keeps hysteresis.
            number = String(format: "%.0f", locale: Locale(identifier: "en_US_POSIX"), min(999, value))
        } else {
            number = String(format: value >= 10 || value == 0 ? "%.0f" : "%.1f", value)
        }
        return FormattedRate(number: number, unit: ["B", "KB", "MB", "GB", "TB"][unitIndex])
    }

    static var menuBar: Self { Self(radix: 1000, fixedWidth: true) }
}

struct DisplayedRate {
    private var smoother = RateSmoother()
    private var formatter = RateUnitFormatter()
    private var menuFormatter = RateUnitFormatter.menuBar
    private(set) var formatted = FormattedRate(number: "0", unit: "KB")
    private(set) var menuText: String = { var formatter = RateUnitFormatter.menuBar; return formatter.format(0).text }()
    var value: Double { smoother.value }

    mutating func update(_ raw: Double) {
        let value = smoother.update(raw)
        formatted = formatter.format(value)
        menuText = menuFormatter.format(value).text
    }
}

struct DisplayedRates {
    var up = DisplayedRate()
    var down = DisplayedRate()

    mutating func update(up: Double, down: Double) {
        self.up.update(up)
        self.down.update(down)
    }
}
