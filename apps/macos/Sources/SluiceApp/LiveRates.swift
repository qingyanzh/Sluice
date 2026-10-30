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
    var minimumUnit = 0
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
            // Keep five numeric columns, including the decimal point. Capping
            // before rounding avoids "1000.0" just below a unit transition (and
            // bounds the last supported unit). Unit selection retains hysteresis.
            number = String(format: "%5.1f", locale: Locale(identifier: "en_US_POSIX"), min(999.9, value))
        } else {
            number = String(format: unitIndex == 0 || value >= 10 ? "%.0f" : "%.1f", value)
        }
        return FormattedRate(number: number, unit: ["B", "KB", "MB", "GB", "TB"][unitIndex])
    }

    static var menuBar: Self { Self(radix: 1000, fixedWidth: true) }
}

struct DisplayedRate {
    private var smoother = RateSmoother()
    private var formatter = RateUnitFormatter()
    private var menuFormatter = RateUnitFormatter.menuBar
    private(set) var formatted = FormattedRate(number: "0", unit: "B")
    private(set) var menuText = "  0.0 B/s"
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
