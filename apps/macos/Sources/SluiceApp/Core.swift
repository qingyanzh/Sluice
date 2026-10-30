import AppKit
import Foundation
import ServiceManagement

struct LogLine: Identifiable {
    let id: Int
    let time: String
    let level: String
    let message: String
}

struct Connection: Decodable, Identifiable {
    let id: Int
    let time: String
    let proto: String
    let target: String
    let policy: String
    let rule: String
    let outbound: String
    let process: String?
    let src: String?

    enum CodingKeys: String, CodingKey {
        case id, network, target, src, policy, rule, outbound, process
        case timeMs = "time_ms"
    }

    var policyChain: String { policy == outbound ? policy : "\(policy) → \(outbound)" }

    func matches(_ query: String) -> Bool {
        query.isEmpty || [target, policy, outbound, process ?? ""].contains { $0.localizedCaseInsensitiveContains(query) }
    }
}

extension Connection {
    private static let clock: DateFormatter = {
        let clock = DateFormatter()
        clock.dateFormat = "HH:mm:ss"
        return clock
    }()

    init(from decoder: Decoder) throws {
        let fields = try decoder.container(keyedBy: CodingKeys.self)
        id = try fields.decode(Int.self, forKey: .id)
        let timeMs = try fields.decode(Int64.self, forKey: .timeMs)
        time = Self.clock.string(from: Date(timeIntervalSince1970: Double(timeMs) / 1000))
        proto = try fields.decode(String.self, forKey: .network).uppercased()
        target = try fields.decode(String.self, forKey: .target)
        src = try fields.decodeIfPresent(String.self, forKey: .src)
        policy = try fields.decode(String.self, forKey: .policy)
        rule = try fields.decode(String.self, forKey: .rule)
        outbound = try fields.decode(String.self, forKey: .outbound)
        process = try fields.decodeIfPresent(String.self, forKey: .process)
    }
}

/// What the app reads from the config file itself (the core owns the rest).
struct ConfigSummary {
    var apiPort: Int?
    var apiListen: String?
    var httpListen: String?
    var socksListen: String?
    var enhancedMode = false
    /// Nodes in [Proxy] and subscription groups (policy-path) in [Proxy Group].
    var proxyCount = 0
    var subscriptionCount = 0
    var hasNodes: Bool { proxyCount + subscriptionCount > 0 }

    init(text: String) {
        var section = ""
        for raw in text.split(separator: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("[") && line.hasSuffix("]") {
                section = String(line.dropFirst().dropLast())
                continue
            }
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") { continue }
            if section == "Proxy", line.contains("=") { proxyCount += 1; continue }
            if section == "Proxy Group", line.contains("policy-path=") { subscriptionCount += 1; continue }
            guard section == "General", let eq = line.firstIndex(of: "=") else { continue }
            let key = line[..<eq].trimmingCharacters(in: .whitespaces)
            let value = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            switch key {
            case "api-listen": apiListen = value; apiPort = Int(value.split(separator: ":").last ?? "")
            case "http-listen": httpListen = value
            case "socks5-listen": socksListen = value
            case "enhanced-mode": enhancedMode = value == "true" || value == "1"
            default: break
            }
        }
    }

    func requiresRestart(comparedTo running: ConfigSummary) -> Bool {
        apiListen != running.apiListen || httpListen != running.httpListen
            || socksListen != running.socksListen || enhancedMode != running.enhancedMode
    }
}

/// Runs the Sluice core as a child process and mirrors its state for the UI.
@MainActor
final class Core: ObservableObject {
    enum State: Equatable {
        case stopped, starting, running
        case failed(String)

        var isFailed: Bool { if case .failed = self { true } else { false } }

        var label: String {
            switch self {
            case .stopped: "已停止"
            case .starting: "启动中…"
            case .running: "运行中"
            case .failed: "出错"
            }
        }
    }

    @Published private(set) var state: State = .stopped
    @Published private(set) var groups: [PolicyGroup] = []
    @Published private(set) var logs: [LogLine] = []
    @Published private(set) var connections: [Connection] = []
    @Published private(set) var activeConnections: [ActiveConnection] = []
    @Published private(set) var activeConnectionsError: String?
    @Published private(set) var eventsConnected = false
    @Published private(set) var testingNodes: Set<String> = []
    @Published private(set) var nodeTests: [String: NodeTestResult] = [:]
    @Published private(set) var nodeLatencies: [String: Int] = [:]
    @Published private(set) var summary = ConfigSummary(text: "")
    @Published var lastActionError: String?
    @Published private(set) var systemProxyOn = false
    @Published private(set) var otherSystemProxy: String?
    @Published private(set) var privileged = false
    /// Bytes per second over the last poll interval, and running totals.
    @Published private(set) var upRate: Double = 0
    @Published private(set) var downRate: Double = 0
    @Published private(set) var traffic: Traffic?
    /// Last 60 one-second samples of (up, down) bytes per second, oldest first.
    @Published private(set) var rateHistory: [(up: Double, down: Double)] = []
    @Published private(set) var stats: TrafficStats?
    @Published private(set) var statsFallback = false
    @Published private(set) var statsHistory: [TrafficRatePoint] = []
    @Published private(set) var statsError: String?
    /// Outbound mode reported by the core: "rule", "direct" or "global".
    @Published private(set) var mode = "rule"
    @Published private(set) var testingGroups: Set<String> = []
    @Published private(set) var testingTotal = 0
    @Published private(set) var reloading = false
    @Published private(set) var restarting = false
    @Published private(set) var profileNames: [String] = []
    /// A menu bar shortcut to a pane, consumed when the main window appears.
    @Published var requestedPane: Pane?
    @Published var autoStart: Bool {
        didSet { defaults.set(autoStart, forKey: "autoStart") }
    }
    @Published private(set) var configPath: String {
        didSet { defaults.set(configPath, forKey: "configPath") }
    }

    var preferences: UserDefaults { defaults }
    private let defaults: UserDefaults
    private let attachment: E2ELaunch?
    private var process: Process?
    private var profileStore: ProfileStore?
    /// Root core (enhanced mode), started by the helper or the admin prompt; followed via its log file.
    private var rootPID: Int32?
    private var rootViaHelper = false
    private var rootLog = Core.logDir.appendingPathComponent("core.log").path
    private var logOffset: UInt64 = 0
    private var stopping = false
    private var pollTask: Task<Void, Never>?
    private var eventTask: Task<Void, Never>?
    private var eventRefreshTask: Task<Void, Never>?
    private var monitoringID = UUID()
    private var systemProxyRefreshID = UUID()
    private var observingActiveConnections = false
    private var runningSummary: ConfigSummary?
    private var requestsDirty = true
    private var latencyRevision = 0
    private var pending = ""
    private var nextID = 0
    private let maxLines = 2000
    // Prefer the API until the core explicitly reports 404.
    private var usesConnectionAPI = true
    private var clearedConnectionIDs: Set<Connection.ID> = []
    private var trafficHistory = TrafficHistory()
    private var lastTrafficSampleAt: Date?

    static let defaultConfigPath: String = {
        let dir = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Sluice", isDirectory: true)
        return dir.appendingPathComponent("sluice.conf").path
    }()

    static let profilesDirectory = URL(fileURLWithPath: defaultConfigPath)
        .deletingLastPathComponent().appendingPathComponent("profiles", isDirectory: true)

    var activeProfileName: String? { profileStore?.activeName }
    var canChangeProfile: Bool { state != .starting && !reloading && !restarting }

    static let starterConfig = """
        # Sluice config created by the app. Edit it, then press Reload.
        [General]
        http-listen = 127.0.0.1:6252
        socks5-listen = 127.0.0.1:6253
        api-listen = 127.0.0.1:6170
        loglevel = info

        [Proxy]
        # HK = ss, hk.example.com, 8388, encrypt-method=aes-256-gcm, password=change-me

        [Proxy Group]
        Proxy = select, DIRECT

        [Rule]
        DOMAIN-SUFFIX,local,DIRECT
        FINAL,Proxy
        """

    init(defaults: UserDefaults = .standard, profilesDirectory: URL? = nil, attachment: E2ELaunch? = nil) {
        self.attachment = attachment
        let defaults = attachment?.preferences() ?? defaults
        self.defaults = defaults
        configPath = defaults.string(forKey: "configPath") ?? Core.defaultConfigPath
        autoStart = defaults.bool(forKey: "autoStart")
        ensureConfigExists()
        do {
            let store = try ProfileStore(baseDirectory: attachment?.config.deletingLastPathComponent() ?? profilesDirectory ?? Self.profilesDirectory, defaults: defaults,
                                         migratingFrom: URL(fileURLWithPath: configPath))
            profileStore = store
            profileNames = try store.names()
            configPath = store.url(for: store.activeName).path
        } catch {
            lastActionError = "无法载入配置列表：\(error.localizedDescription)"
        }
        refreshSummary()
        if let attachment {
            requestedPane = attachment.pane
            runningSummary = summary
            state = .starting
            if let file = attachment.nodeTests, let data = try? Data(contentsOf: file),
               let results = try? JSONDecoder().decode([NodeTestResult].self, from: data) {
                for result in results {
                    nodeTests[result.node] = result
                    nodeLatencies[result.node] = result.ok ? (result.latencyMs ?? -1) : -1
                }
            }
            appendLog(level: "APP", message: "attached to existing core at \(attachment.host):\(attachment.port)")
            // There is no child stdout/log file in attach mode. Subscribe immediately;
            // the shared monitor reconnects this stream and consumes its log events.
            if let api { eventTask = Task { await self.followEvents(api) } }
            pollTask = Task { await self.poll() }
        }
    }

    var api: APIClient? {
        if let attachment { return APIClient(port: attachment.port, host: attachment.host) }
        return (isActive ? (runningSummary ?? summary) : summary).apiPort.map { APIClient(port: $0) }
    }

    /// The core binary: bundled in the app, or $SLUICE_CORE, or the repo's release build.
    var coreBinary: URL? {
        if let bundled = Bundle.main.url(forResource: "sluice", withExtension: nil) { return bundled }
        if let env = ProcessInfo.processInfo.environment["SLUICE_CORE"] { return URL(fileURLWithPath: env) }
        let repo = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("target/release/sluice")
        return FileManager.default.isExecutableFile(atPath: repo.path) ? repo : nil
    }

    private func ensureConfigExists() {
        guard configPath == Core.defaultConfigPath, !FileManager.default.fileExists(atPath: configPath) else { return }
        let url = URL(fileURLWithPath: configPath)
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? Core.starterConfig.write(to: url, atomically: true, encoding: .utf8)
    }

    func refreshSummary() {
        summary = ConfigSummary(text: (try? String(contentsOfFile: configPath, encoding: .utf8)) ?? "")
        refreshSystemProxy()
    }

    // MARK: lifecycle

    private var autoStarted = false

    /// Starts the core once per launch if the user asked for that.
    func startIfAutoStart() {
        guard autoStart, !autoStarted, !isActive else { return }
        autoStarted = true
        start()
    }

    var isActive: Bool { attachment != nil || process != nil || rootPID != nil }

    static let logDir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/Sluice")

    func start() {
        guard !isActive else { return }
        refreshSummary()
        guard FileManager.default.fileExists(atPath: configPath) else {
            state = .failed("Config file not found: \(configPath)")
            return
        }
        guard summary.apiPort != nil else {
            state = .failed("The app controls Sluice through its API. Add `api-listen = 127.0.0.1:6170` to [General].")
            return
        }
        guard let binary = coreBinary else {
            state = .failed("Sluice core binary not found. Build it with `cargo build --release`.")
            return
        }

        usesConnectionAPI = true
        pending = ""
        startupError = nil
        resetStats()
        runningSummary = summary

        if summary.enhancedMode {
            startPrivileged(binary)
            return
        }
        let p = Process()
        p.executableURL = binary
        p.arguments = ["run", configPath]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        do {
            try p.run()
        } catch {
            state = .failed("Couldn't launch the core: \(error.localizedDescription)")
            return
        }
        process = p
        // Read through EOF before reporting exit, so short-lived startup errors are
        // always ingested before the failure is presented. The main queue preserves order.
        DispatchQueue.global(qos: .utility).async { [weak self] in
            while true {
                let data = pipe.fileHandleForReading.availableData
                if data.isEmpty { break }
                let text = String(decoding: data, as: UTF8.self)
                DispatchQueue.main.async { self?.ingest(text) }
            }
            p.waitUntilExit()
            let code = p.terminationStatus
            DispatchQueue.main.async { self?.exited(code: code) }
        }
        stopping = false
        state = .starting
        appendLog(level: "APP", message: "started core \(binary.path) with \(configPath)")
        pollTask = Task { await self.poll() }
    }

    /// Enhanced mode needs root: the privileged helper runs the core (docs/helper.md); if it
    /// can't be used, launch it detached via the admin prompt. Either way its log file is followed.
    private func startPrivileged(_ binary: URL) {
        state = .starting
        stopping = false
        logOffset = 0
        Task {
            switch HelperClient.prepare() {
            case .ready:
                do {
                    let (pid, log) = try await HelperClient.start(config: configPath)
                    rootStarted(pid: pid, log: log, viaHelper: true)
                    return
                } catch {
                    appendLog(level: "APP", message: "helper failed (\(error.localizedDescription)); using the administrator prompt")
                }
            case .needsApproval:
                appendLog(level: "APP", message: "allow Sluice in System Settings › Login Items & Extensions to skip the administrator prompt next time")
                SMAppService.openSystemSettingsLoginItems()
            case .unavailable(let why):
                appendLog(level: "APP", message: "helper unavailable (\(why)); using the administrator prompt")
            }
            startWithAdminPrompt(binary)
        }
    }

    private func startWithAdminPrompt(_ binary: URL) {
        try? FileManager.default.createDirectory(at: Core.logDir, withIntermediateDirectories: true)
        let log = Core.logDir.appendingPathComponent("core.log").path
        let pidFile = Core.logDir.appendingPathComponent("core.pid").path
        try? "".write(toFile: log, atomically: true, encoding: .utf8)
        appendLog(level: "APP", message: "asking for administrator access to start enhanced mode")
        Task {
            do {
                _ = try await Privileged.run(
                    "\(shellQuote(binary.path)) run \(shellQuote(configPath)) > \(shellQuote(log)) 2>&1 < /dev/null & echo $! > \(shellQuote(pidFile))")
                guard let pid = Int32((try? String(contentsOfFile: pidFile, encoding: .utf8))?
                    .trimmingCharacters(in: .whitespacesAndNewlines) ?? "") else {
                    throw APIError(message: "the core didn't report a PID")
                }
                rootStarted(pid: pid, log: log, viaHelper: false)
            } catch {
                state = .failed("Couldn't start enhanced mode: \(error.localizedDescription)")
            }
        }
    }

    private func rootStarted(pid: Int32, log: String, viaHelper: Bool) {
        rootPID = pid
        rootLog = log
        rootViaHelper = viaHelper
        privileged = true
        appendLog(level: "APP", message: "started core as root (pid \(pid)\(viaHelper ? ", via helper" : "")) with \(configPath)")
        pollTask = Task { await self.poll() }
    }

    /// Asks whoever started the root core to stop it. Nonisolated: `stopForQuit` blocks the
    /// main thread waiting for it, so it must never need the main actor.
    nonisolated static func stopRoot(pid: Int32, viaHelper: Bool) async throws {
        if viaHelper {
            try await HelperClient.stop()
        } else {
            _ = try await Privileged.run("kill -INT \(pid)")
        }
    }

    /// Reads whatever the root core appended to its log since last time.
    private func followLog() {
        guard let h = FileHandle(forReadingAtPath: rootLog) else { return }
        defer { try? h.close() }
        try? h.seek(toOffset: logOffset)
        let data = h.readDataToEndOfFile()
        logOffset += UInt64(data.count)
        if let text = String(data: data, encoding: .utf8), !text.isEmpty { ingest(text) }
    }

    /// kill(pid, 0) on a root process from a user process fails with EPERM while it lives.
    private static func alive(_ pid: Int32) -> Bool {
        kill(pid, 0) == 0 || errno == EPERM
    }

    func stop() {
        guard attachment == nil else { return }
        if let pid = rootPID {
            stopping = true
            Task {
                do {
                    try await Core.stopRoot(pid: pid, viaHelper: rootViaHelper)
                } catch {
                    stopping = false
                    lastActionError = "停止失败：\(error.localizedDescription)"
                }
            }
            return
        }
        guard let p = process else { return }
        stopping = true
        p.interrupt()
        let deadline = Date().addingTimeInterval(3)
        Task {
            while p.isRunning && Date() < deadline { try? await Task.sleep(for: .milliseconds(100)) }
            if p.isRunning { p.terminate() }
        }
    }

    func restart() {
        guard attachment == nil else { return }
        guard !restarting else { return }
        guard isActive else { return start() }
        restarting = true
        stop()
        Task {
            defer { restarting = false }
            let deadline = Date().addingTimeInterval(15)
            while isActive && Date() < deadline { try? await Task.sleep(for: .milliseconds(100)) }
            if !isActive { start() }
        }
    }

    /// Synchronous stop used when the app quits, so the child never outlives it.
    func stopForQuit() {
        if let attachment {
            defaults.removePersistentDomain(forName: attachment.preferenceDomain)
            pollTask?.cancel()
            eventTask?.cancel()
            eventRefreshTask?.cancel()
            return
        }
        if let pid = rootPID {
            // The helper also stops it once the app exits; the admin prompt path needs one more prompt.
            let sema = DispatchSemaphore(value: 0)
            let viaHelper = rootViaHelper
            Task.detached {
                try? await Core.stopRoot(pid: pid, viaHelper: viaHelper)
                sema.signal()
            }
            _ = sema.wait(timeout: .now() + 60)
            return
        }
        guard let p = process else { return }
        stopping = true
        p.interrupt()
        let deadline = Date().addingTimeInterval(2)
        while p.isRunning && Date() < deadline { usleep(50_000) }
        if p.isRunning { p.terminate() }
    }

    private func exited(code: Int32) {
        if !pending.isEmpty { parse(pending); pending = "" }
        pollTask?.cancel()
        eventTask?.cancel()
        eventTask = nil
        eventRefreshTask?.cancel()
        eventRefreshTask = nil
        runningSummary = nil
        eventsConnected = false
        activeConnections = []
        activeConnectionsError = nil
        nodeTests = [:]
        nodeLatencies = [:]
        process = nil
        rootPID = nil
        privileged = false
        traffic = nil
        rateHistory = []
        mode = "rule"
        upRate = 0
        downRate = 0
        resetStats()
        groups = []
        appendLog(level: "APP", message: "core exited with status \(code)")
        if stopping || code == 0 {
            state = .stopped
        } else {
            let reason = startupError ?? "the core exited with status \(code)"
            state = .failed(reason)
            Task {
                guard let message = await ListenConflict.message(for: reason),
                      state == .failed(reason), !isActive else { return }
                state = .failed(message)
            }
        }
        refreshSystemProxy()
    }

    private func resetStats() {
        stats = nil
        statsFallback = false
        statsHistory = []
        statsError = nil
        trafficHistory = TrafficHistory()
        lastTrafficSampleAt = nil
    }

    private func sampleTraffic(_ api: APIClient) async {
        guard let now = try? await api.traffic() else { return }
        guard !Task.isCancelled else { return }
        let time = Date()
        let elapsed = lastTrafficSampleAt.map { time.timeIntervalSince($0) } ?? 0
        if let prev = traffic, elapsed > 0 {
            upRate = Double(now.up >= prev.up ? now.up - prev.up : 0) / elapsed
            downRate = Double(now.down >= prev.down ? now.down - prev.down : 0) / elapsed
            rateHistory.append((upRate, downRate))
            if rateHistory.count > 60 { rateHistory.removeFirst(rateHistory.count - 60) }
        }
        traffic = now
        lastTrafficSampleAt = time
        trafficHistory.record(now, at: time)
        if statsFallback { statsHistory = trafficHistory.samples }
    }

    private func sampleStats(_ api: APIClient) async {
        guard !statsFallback else { return }
        do {
            let fresh = try await api.stats()
            guard !Task.isCancelled else { return }
            stats = fresh
            statsFallback = fresh == nil
            if statsFallback { statsHistory = trafficHistory.samples }
            statsError = nil
        } catch {
            guard !Task.isCancelled else { return }
            statsError = "统计刷新失败：\(error.localizedDescription)"
        }
    }

    private func refreshConnections(_ api: APIClient) async {
        guard usesConnectionAPI else { return }
        let generation = monitoringID
        do {
            let fresh = try await api.connections()
            guard !Task.isCancelled, state == .running, monitoringID == generation else { return }
            if let fresh {
                connections = Array(fresh.filter { !clearedConnectionIDs.contains($0.id) }.suffix(maxLines))
            } else {
                usesConnectionAPI = false
                connections = logs.compactMap { connection(from: $0) }
            }
        } catch { /* Preserve the last good snapshot on a transient failure. */ }
    }

    private func refreshActiveConnections(_ api: APIClient) async {
        let generation = monitoringID
        do {
            let fresh = try await api.activeConnections()
            guard !Task.isCancelled, state == .running, monitoringID == generation else { return }
            activeConnections = fresh
            activeConnectionsError = nil
        } catch {
            guard !Task.isCancelled, state == .running, monitoringID == generation else { return }
            activeConnectionsError = "活动连接刷新失败：\(error.localizedDescription)"
        }
    }

    private func followEvents(_ api: APIClient) async {
        var backoff: Double = 1
        while !Task.isCancelled {
            let started = Date()
            do {
                try await api.events {
                    try Task.checkCancellation()
                    self.eventsConnected = true
                    // Reconcile events missed during a disconnect before consuming new frames.
                    await self.refreshConnections(api)
                    await self.refreshActiveConnections(api)
                } receive: { frame in
                    try await self.receiveEvent(frame, api: api)
                }
            } catch {
                guard !Task.isCancelled else { return }
                // Resume at the end of the root log: SSE already delivered earlier lines.
                if rootPID != nil, eventsConnected {
                    logOffset = (try? FileManager.default.attributesOfItem(atPath: rootLog)[.size] as? NSNumber)?.uint64Value ?? logOffset
                }
                eventsConnected = false
                eventRefreshTask?.cancel()
                eventRefreshTask = nil
                requestsDirty = true
            }
            if Date().timeIntervalSince(started) > 30 { backoff = 1 }
            do { try await Task.sleep(for: .seconds(backoff)) } catch { return }
            backoff = min(backoff * 2, 30)
        }
    }

    private func receiveEvent(_ frame: SSEFrame, api: APIClient) async throws {
        try Task.checkCancellation()
        let data = Data(frame.data.utf8)
        let decoder = JSONDecoder()
        switch frame.event {
        case "traffic":
            let event = try decoder.decode(TrafficEvent.self, from: data)
            let time = Date(timeIntervalSince1970: Double(event.timeMs) / 1000)
            traffic = Traffic(up: event.totalUp, down: event.totalDown, active: event.active)
            upRate = Double(event.up)
            downRate = Double(event.down)
            lastTrafficSampleAt = time
            rateHistory.append((upRate, downRate))
            if rateHistory.count > 60 { rateHistory.removeFirst(rateHistory.count - 60) }
            if let traffic { trafficHistory.record(traffic, at: time) }
            if statsFallback { statsHistory = trafficHistory.samples }
            if let stats {
                var history = stats.history.filter { $0.timeMs < event.timeMs }
                history.append(TrafficStatsSample(timeMs: event.timeMs, up: event.up, down: event.down, policies: event.policies))
                self.stats = TrafficStats(up: event.totalUp, down: event.totalDown, active: event.active,
                                          policies: stats.policies, nodes: stats.nodes, history: Array(history.suffix(600)))
            }
            refreshEventSnapshots(api)
        case "conn_open":
            let connection = try decoder.decode(ActiveConnection.self, from: data)
            activeConnections.removeAll { $0.id == connection.id }
            activeConnections.append(connection)
            requestsDirty = true
        case "conn_close":
            let connection = try decoder.decode(ActiveConnection.self, from: data)
            activeConnections.removeAll { $0.id == connection.id }
            requestsDirty = true
        case "log":
            let log = try decoder.decode(LogEvent.self, from: data)
            let time = Self.clock.string(from: Date(timeIntervalSince1970: Double(log.timeMs) / 1000))
            appendLog(time: time, level: log.level, message: log.message)
            // Routing decisions include UDP and rejected requests, which have no
            // active TCP event. A log event invalidates that snapshot as well.
            requestsDirty = true
            if !usesConnectionAPI, let line = logs.last, let connection = connection(from: line) {
                connections.append(connection)
                if connections.count > maxLines { connections.removeFirst(connections.count - maxLines) }
            }
        default: break
        }
    }

    /// SSE carries counters at open/close only. While the activity tab is visible,
    /// fetch its rates after traffic events. Coalesce snapshot requests so a slow
    /// endpoint never blocks delivery of logs or connection events.
    private func refreshEventSnapshots(_ api: APIClient) {
        guard eventRefreshTask == nil else { return }
        let generation = monitoringID
        let refreshRequests = requestsDirty
        requestsDirty = false
        eventRefreshTask = Task {
            defer { if monitoringID == generation { eventRefreshTask = nil } }
            if observingActiveConnections { await refreshActiveConnections(api) }
            if refreshRequests { await refreshConnections(api) }
        }
    }

    func observeActiveConnections(_ observing: Bool) {
        observingActiveConnections = observing
        if observing, state == .running, let api {
            Task { await refreshActiveConnections(api) }
        }
    }

    private func poll() async {
        let generation = UUID()
        monitoringID = generation
        var tick = 0
        var lastStatsPoll = Date.distantPast
        usesConnectionAPI = true
        clearedConnectionIDs = []
        defer {
            if monitoringID == generation {
                eventTask?.cancel()
                eventTask = nil
                eventRefreshTask?.cancel()
                eventRefreshTask = nil
                eventsConnected = false
            }
        }
        while !Task.isCancelled {
            if let pid = rootPID {
                if !eventsConnected { followLog() }
                if !Core.alive(pid) {
                    followLog()
                    exited(code: stopping ? 0 : 1)
                    return
                }
            }
            if let api, state == .starting || tick % 2 == 0, await refreshPolicies(api) {
                if state == .starting { state = .running }
                if let m = try? await api.mode() { mode = m }
            }
            guard !Task.isCancelled else { return }
            if let api, state == .running {
                if eventTask == nil { eventTask = Task { await self.followEvents(api) } }
                if !eventsConnected {
                    await sampleTraffic(api)
                    await refreshConnections(api)
                    if observingActiveConnections { await refreshActiveConnections(api) }
                }
                if Date().timeIntervalSince(lastStatsPoll) >= 5 {
                    await sampleStats(api)
                    lastStatsPoll = Date()
                }
            }
            tick += 1
            // Low-frequency policy/stats maintenance; live activity uses SSE.
            try? await Task.sleep(for: .seconds(state == .starting ? 0.3 : 1))
        }
    }

    private func refreshPolicies(_ api: APIClient) async -> Bool {
        let revision = latencyRevision
        let generation = monitoringID
        guard let fresh = try? await api.policies(), !Task.isCancelled, generation == monitoringID else { return false }
        updateGroups(fresh, preferTestResults: revision != latencyRevision)
        return true
    }

    func updateGroups(_ fresh: [PolicyGroup], preferTestResults: Bool = false) {
        // A request started before a test finished must not overwrite its results.
        // Keep explicit node-test measurements aligned with the detail sheet;
        // automatic group checks may measure a different URL. A group test
        // explicitly replaces those measurements for its options.
        if !preferTestResults {
            for option in fresh.flatMap(\.options) {
                if nodeTests[option.name] == nil, let latency = option.latencyMs {
                    nodeLatencies[option.name] = latency
                }
            }
        }
        groups = fresh.map { group in
            PolicyGroup(group: group.group, type: group.type, selected: group.selected,
                        options: group.options.map { option in
                            GroupOption(name: option.name, latencyMs: nodeLatencies[option.name] ?? option.latencyMs)
                        })
        }
    }

    // MARK: actions

    private func perform(_ what: String, _ body: @escaping (APIClient) async throws -> Void) {
        guard let api else { return }
        Task {
            do {
                try await body(api)
                lastActionError = nil
                _ = await refreshPolicies(api)
            } catch {
                lastActionError = "\(what)失败：\(error.localizedDescription)"
            }
        }
    }

    func select(group: String, option: String) {
        guard state == .running,
              groups.contains(where: { $0.group == group && $0.isSelectable && $0.options.contains(where: { $0.name == option }) }) else { return }
        perform("切换到 \(option) ") { try await $0.select(group: group, option: option) }
    }

    func test(group: String) {
        guard state == .running, let api, !testingGroups.contains(group) else { return }
        testingGroups.insert(group)
        testingTotal += 1
        Task {
            defer {
                testingGroups.remove(group)
                if testingGroups.isEmpty { testingTotal = 0 }
            }
            do {
                let result = try await api.test(group: group)
                latencyRevision += 1
                for option in result.results {
                    nodeTests.removeValue(forKey: option.name)
                    nodeLatencies[option.name] = option.latencyMs ?? -1
                }
                updateGroups(groups.map { current in
                    PolicyGroup(group: current.group, type: current.type,
                                selected: current.group == result.tested ? result.selected : current.selected,
                                options: current.options)
                }, preferTestResults: true)
                lastActionError = nil
            } catch {
                lastActionError = "测试 \(group) 失败：\(error.localizedDescription)"
            }
        }
    }

    func test(node: String) {
        guard state == .running, let api, !testingNodes.contains(node) else { return }
        testingNodes.insert(node)
        Task {
            defer { testingNodes.remove(node) }
            do {
                let result = try await api.test(node: node)
                latencyRevision += 1
                nodeTests[node] = result
                nodeLatencies[node] = result.ok ? (result.latencyMs ?? -1) : -1
                updateGroups(groups, preferTestResults: true)
                lastActionError = nil
            } catch { lastActionError = "测试 \(node) 失败：\(error.localizedDescription)" }
        }
    }

    func closeConnection(_ id: UInt64) {
        guard state == .running, let api else { return }
        Task {
            do {
                try await api.closeConnection(id)
                activeConnections.removeAll { $0.id == id }
                lastActionError = nil
            } catch { lastActionError = "断开连接失败：\(error.localizedDescription)" }
        }
    }

    func closeAllConnections() {
        guard state == .running, let api else { return }
        Task {
            do {
                try await api.closeAllConnections()
                await refreshActiveConnections(api)
                lastActionError = nil
            } catch { lastActionError = "全部断开失败：\(error.localizedDescription)" }
        }
    }

    func testAll() {
        guard testingGroups.isEmpty else { return }
        // Each test starts its own async request, so groups run concurrently.
        for g in groups { test(group: g.group) }
    }

    func setMode(_ m: String) {
        guard let api else { return }
        Task {
            do {
                try await api.setMode(m)
                mode = m
                lastActionError = nil
            } catch {
                lastActionError = "切换出站模式失败：\(error.localizedDescription)"
            }
        }
    }

    func reload() {
        guard state == .running, !reloading else { return }
        Task {
            do { try await reloadAndWait(); lastActionError = nil }
            catch { lastActionError = "重载配置失败：\(error.localizedDescription)" }
        }
    }

    private func reloadAndWait() async throws {
        guard let api else { throw APIError(message: "未配置控制 API") }
        reloading = true
        defer { reloading = false }
        try await api.reload()
        nodeLatencies = [:]
        nodeTests = [:]
        refreshSummary()
        if summary.requiresRestart(comparedTo: runningSummary ?? summary) { restart() }
        else { runningSummary = summary }
        _ = await refreshPolicies(api)
    }

    func route(_ target: String) async throws -> RouteResult {
        guard let api, state == .running else { throw APIError(message: "Sluice 未运行") }
        return try await api.route(target)
    }

    // MARK: config editing

    private func profiles() throws -> ProfileStore {
        guard let profileStore else { throw APIError(message: "配置目录不可用，请检查权限后重新打开应用。") }
        return profileStore
    }

    func refreshProfiles() {
        do { profileNames = try profiles().names() }
        catch { lastActionError = "无法刷新配置列表：\(error.localizedDescription)" }
    }

    func createProfile(name: String, contents: String) throws {
        try profiles().create(name: name, contents: contents)
        refreshProfiles()
    }

    func duplicateProfile(_ name: String, as newName: String) throws {
        try profiles().duplicate(name, as: newName)
        refreshProfiles()
    }

    func renameProfile(_ name: String, to newName: String) async throws {
        let store = try profiles()
        let wasActive = store.activeName == name
        if wasActive { try requireProfileChange() }
        try store.rename(name, to: newName)
        if wasActive {
            reloading = true
            defer { reloading = false }
            do {
                if state == .running, let api { try await api.switchProfile(path: store.url(for: newName).path) }
                applyProfilePath(store)
            } catch {
                try? store.rename(newName, to: name)
                refreshProfiles()
                throw error
            }
        }
        refreshProfiles()
    }

    func deleteProfile(_ name: String) throws {
        try profiles().delete(name)
        refreshProfiles()
    }

    func switchProfile(to name: String) async throws {
        try requireProfileChange()
        let store = try profiles()
        guard name != store.activeName else { return }
        try ProfileStore.validateName(name)
        guard try store.names().contains(name) else { throw ProfileStore.StoreError.missingProfile }
        let path = store.url(for: name).path
        let next = ConfigSummary(text: try String(contentsOfFile: path, encoding: .utf8))
        let needsRestart = next.requiresRestart(comparedTo: runningSummary ?? summary)
        let wasRunning = state == .running
        reloading = true
        defer { reloading = false }
        if wasRunning {
            guard let api else { throw APIError(message: "未配置控制 API") }
            // The core validates/builds first; a 400 leaves both selections unchanged.
            try await api.switchProfile(path: path)
        }
        try store.activate(name)
        applyProfilePath(store)
        nodeTests = [:]
        nodeLatencies = [:]
        if wasRunning && needsRestart { restart() }
        else if wasRunning {
            runningSummary = next
            if let api { _ = await refreshPolicies(api) }
        }
    }

    private func requireProfileChange() throws {
        guard canChangeProfile else { throw APIError(message: "内核正在启动或应用配置，请稍后再试。") }
    }

    private func applyProfilePath(_ store: ProfileStore) {
        let path = store.url(for: store.activeName).path
        guard configPath != path else { return }
        configPath = path
        refreshSummary()
    }

    func readConfig() -> String {
        (try? String(contentsOfFile: configPath, encoding: .utf8)) ?? ""
    }

    /// Runs `sluice check` on `text` (as a sibling temp file, so relative paths still
    /// resolve); returns the error message, or nil if the config is valid.
    func validate(_ text: String) async -> String? {
        guard let binary = coreBinary else { return "找不到 Sluice 内核，请重新安装应用。" }
        let dir = URL(fileURLWithPath: configPath).deletingLastPathComponent()
        let tmp = dir.appendingPathComponent(".sluice-check-\(UUID().uuidString).conf")
        do { try text.write(to: tmp, atomically: true, encoding: .utf8) } catch { return error.localizedDescription }
        defer { try? FileManager.default.removeItem(at: tmp) }
        let (status, out) = await runTool(binary.path, ["check", tmp.path])
        // First line is for people; the core's own message follows as detail.
        if status == 0 { return nil }
        let detail = out.replacingOccurrences(of: "error: ", with: "").trimmingCharacters(in: .whitespacesAndNewlines)
        if let line = Self.errorLine(in: detail) { return "第 \(line) 行有错误，配置没有保存。\n" + detail }
        return "配置检查未通过，没有保存。\n" + detail
    }

    /// The line a `sluice check` message points at ("line 17: …"), if any.
    static func errorLine(in message: String) -> Int? {
        guard let r = message.range(of: #"line (\d+)"#, options: .regularExpression) else { return nil }
        return Int(message[r].dropFirst(5))
    }

    /// Validates, saves and (if running) reloads. Returns an error message on failure.
    @discardableResult
    func saveConfig(_ text: String, expected: String? = nil) async -> String? {
        let destination = configPath
        if let err = await validate(text) { return err }
        guard configPath == destination else { return "当前配置文件已切换，请重新保存。" }
        if let expected, readConfig() != expected {
            return "配置文件已被其他操作修改，没有覆盖。请先载入磁盘版本，或复制当前草稿保留修改。"
        }
        do {
            try text.write(toFile: configPath, atomically: true, encoding: .utf8)
        } catch {
            return error.localizedDescription
        }
        refreshSummary()
        if state == .running {
            do { try await reloadAndWait() }
            catch { return "配置已保存，但应用失败。请重试载入配置。\n\(error.localizedDescription)" }
        }
        return nil
    }

    /// Turns enhanced mode on or off in the config and restarts the core so it takes effect.
    func setEnhancedMode(_ on: Bool) async -> String? {
        let text = ConfigText.setGeneral("enhanced-mode", on ? "true" : "false", in: readConfig())
        if let err = await saveConfig(text) { return err }
        if isActive { restart() }
        return nil
    }

    private func uniqueName(_ base: String, in text: String) -> String {
        let taken = ConfigText.names(in: text)
        var name = base.isEmpty ? "Node" : base
        var i = 2
        while taken.contains(name) { name = "\(base) \(i)"; i += 1 }
        return name
    }

    /// Adds a node from a share link or a Surge `[Proxy]` line; returns an error or nil.
    func addNode(_ input: String) async -> String? {
        var line = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !line.isEmpty else { return "请先粘贴分享链接或代理行。" }
        if line.contains("://") {
            guard let binary = coreBinary else { return "找不到 Sluice 内核，请重新安装应用。" }
            let (status, out) = await runTool(binary.path, ["convert", line])
            guard status == 0 else {
                return "无法识别这个分享链接。\n" + out.replacingOccurrences(of: "error: ", with: "").trimmingCharacters(in: .whitespacesAndNewlines)
            }
            line = out.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        guard let eq = line.firstIndex(of: "=") else {
            return "格式不正确：代理行需要写成「名称 = 类型, 服务器, 端口, 参数…」，缺少「名称 =」。"
        }
        var text = readConfig()
        let name = uniqueName(line[..<eq].trimmingCharacters(in: .whitespaces), in: text)
        line = "\(name) =\(line[line.index(after: eq)...])"
        text = ConfigText.insert(line, into: "Proxy", of: text)
        text = ConfigText.addToFinalGroup(name, in: text)
        return Core.explain(await saveConfig(text), as: "这个节点无法加入配置，配置没有改动。请检查代理类型和参数是否正确。")
    }

    /// Adds a subscription as its own `select` group fed by `policy-path`.
    func addSubscription(name: String, url: String, filter: String, userAgent: String = "") async -> String? {
        let url = url.trimmingCharacters(in: .whitespaces)
        guard url.hasPrefix("http://") || url.hasPrefix("https://") else { return "订阅地址需要以 http:// 或 https:// 开头。" }
        var text = readConfig()
        let group = uniqueName(name.trimmingCharacters(in: .whitespaces).isEmpty ? "Subscription" : name, in: text)
        var line = "\(group) = select, policy-path=\(url)"
        if !filter.trimmingCharacters(in: .whitespaces).isEmpty { line += ", policy-regex-filter=\(filter)" }
        let userAgent = userAgent.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !userAgent.contains("\r"), !userAgent.contains("\n"), !userAgent.contains("\"") else {
            return "User-Agent 不能包含换行或双引号。"
        }
        if !userAgent.isEmpty { line += ", user-agent=\"\(userAgent)\"" }
        text = ConfigText.insert(line, into: "Proxy Group", of: text)
        text = ConfigText.addToFinalGroup(group, in: text)
        return Core.explain(await saveConfig(text), as: "订阅没有添加，配置没有改动。请确认地址可以访问，且内容是节点列表。")
    }

    /// Replaces the generic first line of a check failure with one that fits the action,
    /// keeping the core's message as the detail.
    static func explain(_ error: String?, as headline: String) -> String? {
        guard let error else { return nil }
        if error.hasPrefix("配置已保存") { return error }
        let detail = error.split(separator: "\n", maxSplits: 1).dropFirst().first.map(String.init) ?? error
        return headline + "\n" + detail
    }

    // MARK: system proxy

    func refreshSystemProxy() {
        guard attachment == nil else { return }
        let config = isActive ? (runningSummary ?? summary) : summary
        let refreshID = UUID()
        systemProxyRefreshID = refreshID
        Task {
            let status = await SystemProxy.status(http: config.httpListen, socks: config.socksListen)
            guard systemProxyRefreshID == refreshID else { return }
            systemProxyOn = status.isSluice
            otherSystemProxy = status.otherProxy
        }
    }

    func setSystemProxy(_ on: Bool) {
        guard attachment == nil else { return }
        let config = isActive ? (runningSummary ?? summary) : summary
        let http = SystemProxy.split(config.httpListen)
        let socks = SystemProxy.split(config.socksListen)
        guard !on || http != nil || socks != nil else {
            lastActionError = "无法开启系统代理：配置的 [General] 中没有 http-listen 或 socks5-listen。"
            return
        }
        Task {
            do {
                try await SystemProxy.set(enabled: on, http: http, socks: socks)
                lastActionError = nil
            } catch {
                lastActionError = "设置系统代理失败：\(error.localizedDescription)"
            }
            refreshSystemProxy()
        }
    }

    @Published private(set) var exportingDiagnostics = false

    /// Runs `sluice diag export` (logs, crash reports incl. the app's own from DiagnosticReports,
    /// redacted config, network snapshot) and reveals the zip in Finder.
    func exportDiagnostics() {
        guard !exportingDiagnostics else { return }
        guard let binary = coreBinary else {
            lastActionError = "导出诊断信息失败：找不到 Sluice 内核"
            return
        }
        let stamp = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
        let out = Core.logDir.appendingPathComponent("Sluice-diag-\(stamp).zip")
        let args = ["diag", "export", out.path] + (FileManager.default.fileExists(atPath: configPath) ? [configPath] : [])
        exportingDiagnostics = true
        Task.detached {
            let result = Result { () throws -> String in
                let p = Process()
                p.executableURL = binary
                p.arguments = args
                let pipe = Pipe()
                p.standardOutput = pipe
                p.standardError = pipe
                try p.run()
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                p.waitUntilExit()
                let text = String(data: data, encoding: .utf8) ?? ""
                guard p.terminationStatus == 0 else { throw APIError(message: text.trimmingCharacters(in: .whitespacesAndNewlines)) }
                return text
            }
            await MainActor.run {
                self.exportingDiagnostics = false
                switch result {
                case .success:
                    self.lastActionError = nil
                    NSWorkspace.shared.activateFileViewerSelecting([out])
                case .failure(let error):
                    self.lastActionError = "导出诊断信息失败：\(error.localizedDescription)"
                }
            }
        }
    }

    func clearLogs() { logs = [] }
    func clearConnections() {
        if usesConnectionAPI { clearedConnectionIDs.formUnion(connections.map(\.id)) }
        connections = []
    }

    // MARK: output parsing

    private var startupError: String?

    private func ingest(_ text: String) {
        pending += text
        while let nl = pending.firstIndex(of: "\n") {
            let line = String(pending[..<nl])
            pending = String(pending[pending.index(after: nl)...])
            parse(line)
        }
    }

    private static let logPattern = #/^\[(\S+)\s+(\w+)\s*\]\s(.*)$/#
    private static let connPattern = #/^(UDP )?(\S+) -> (.+) \[(.*)\] via (\S+)$/#

    private func parse(_ line: String) {
        guard !line.isEmpty else { return }
        if line.hasPrefix("error:") { startupError = line }
        guard let m = line.wholeMatch(of: Core.logPattern) else {
            appendLog(level: line.hasPrefix("error:") ? "ERROR" : "OUT", message: line)
            return
        }
        guard !eventsConnected else { return }
        let (time, level, message) = (String(m.1), String(m.2), String(m.3))
        appendLog(time: time, level: level, message: message)
        if !usesConnectionAPI, let log = logs.last, let connection = connection(from: log) {
            connections.append(connection)
            if connections.count > maxLines { connections.removeFirst(connections.count - maxLines) }
        }
    }

    private func connection(from log: LogLine) -> Connection? {
        guard let c = log.message.wholeMatch(of: Core.connPattern) else { return nil }
        return Connection(id: log.id, time: log.time, proto: c.1 == nil ? "TCP" : "UDP",
                          target: String(c.2), policy: String(c.3), rule: String(c.4), outbound: String(c.5),
                          process: nil, src: nil)
    }

    private func appendLog(time: String? = nil, level: String, message: String) {
        nextID += 1
        let t = time.map(Core.shortTime) ?? Core.clock.string(from: Date())
        logs.append(LogLine(id: nextID, time: t, level: level, message: message))
        if logs.count > maxLines { logs.removeFirst(logs.count - maxLines) }
    }

    private static let clock: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()

    /// `2026-10-29T15:16:02Z` -> local `HH:mm:ss`.
    private static func shortTime(_ iso: String) -> String {
        let parser = ISO8601DateFormatter()
        return parser.date(from: iso).map { clock.string(from: $0) } ?? iso
    }
}

/// `1536` -> "1.5 KB".
func formatBytes(_ n: Double) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"]
    var v = n
    var i = 0
    while v >= 1024 && i < units.count - 1 { v /= 1024; i += 1 }
    return i == 0 ? "\(Int(v)) B" : String(format: v < 10 ? "%.1f %@" : "%.0f %@", v, units[i])
}
