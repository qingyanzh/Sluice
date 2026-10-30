import AppKit
import Foundation
import ServiceManagement

struct LogLine: Identifiable {
    let id: Int
    let time: String
    let level: String
    let message: String
}

struct Connection: Identifiable {
    let id: Int
    let time: String
    let proto: String
    let target: String
    let policy: String
    let rule: String
    let outbound: String
}

/// What the app reads from the config file itself (the core owns the rest).
struct ConfigSummary {
    var apiPort: Int?
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
            case "api-listen": apiPort = Int(value.split(separator: ":").last ?? "")
            case "http-listen": httpListen = value
            case "socks5-listen": socksListen = value
            case "enhanced-mode": enhancedMode = value == "true" || value == "1"
            default: break
            }
        }
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
    @Published private(set) var summary = ConfigSummary(text: "")
    @Published var lastActionError: String?
    @Published private(set) var systemProxyOn = false
    @Published private(set) var privileged = false
    /// Bytes per second over the last poll interval, and running totals.
    @Published private(set) var upRate: Double = 0
    @Published private(set) var downRate: Double = 0
    @Published private(set) var traffic: Traffic?
    /// Last 60 one-second samples of (up, down) bytes per second, oldest first.
    @Published private(set) var rateHistory: [(up: Double, down: Double)] = []
    /// Outbound mode reported by the core: "rule", "direct" or "global".
    @Published private(set) var mode = "rule"
    @Published private(set) var testingGroups: Set<String> = []
    @Published private(set) var reloading = false
    /// A menu bar shortcut to a pane, consumed when the main window appears.
    @Published var requestedPane: Pane?
    @Published var autoStart: Bool {
        didSet { UserDefaults.standard.set(autoStart, forKey: "autoStart") }
    }
    @Published var configPath: String {
        didSet { UserDefaults.standard.set(configPath, forKey: "configPath") }
    }

    private var process: Process?
    /// Root core (enhanced mode), started by the helper or the admin prompt; followed via its log file.
    private var rootPID: Int32?
    private var rootViaHelper = false
    private var rootLog = Core.logDir.appendingPathComponent("core.log").path
    private var logOffset: UInt64 = 0
    private var stopping = false
    private var pollTask: Task<Void, Never>?
    private var pending = ""
    private var nextID = 0
    private let maxLines = 2000

    static let defaultConfigPath: String = {
        let dir = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Sluice", isDirectory: true)
        return dir.appendingPathComponent("sluice.conf").path
    }()

    static let starterConfig = """
        # Sluice config created by the app. Edit it, then press Reload.
        [General]
        http-listen = 127.0.0.1:6152
        socks5-listen = 127.0.0.1:6153
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

    init() {
        configPath = UserDefaults.standard.string(forKey: "configPath") ?? Core.defaultConfigPath
        autoStart = UserDefaults.standard.bool(forKey: "autoStart")
        ensureConfigExists()
        refreshSummary()
    }

    var api: APIClient? { summary.apiPort.map(APIClient.init(port:)) }

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
    }

    // MARK: lifecycle

    private var autoStarted = false

    /// Starts the core once per launch if the user asked for that.
    func startIfAutoStart() {
        guard autoStart, !autoStarted, !isActive else { return }
        autoStarted = true
        start()
    }

    var isActive: Bool { process != nil || rootPID != nil }

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
        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else { return }
            Task { @MainActor in self?.ingest(text) }
        }
        p.terminationHandler = { [weak self] proc in
            let code = proc.terminationStatus
            Task { @MainActor in self?.exited(code: code) }
        }
        do {
            try p.run()
        } catch {
            state = .failed("Couldn't launch the core: \(error.localizedDescription)")
            return
        }
        process = p
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

    /// Asks whoever started the root core to stop it.
    private static func stopRoot(pid: Int32, viaHelper: Bool) async throws {
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
        guard isActive else { return start() }
        stop()
        Task {
            let deadline = Date().addingTimeInterval(15)
            while isActive && Date() < deadline { try? await Task.sleep(for: .milliseconds(100)) }
            if !isActive { start() }
        }
    }

    /// Synchronous stop used when the app quits, so the child never outlives it.
    func stopForQuit() {
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
        pollTask?.cancel()
        process = nil
        rootPID = nil
        privileged = false
        traffic = nil
        rateHistory = []
        mode = "rule"
        upRate = 0
        downRate = 0
        groups = []
        appendLog(level: "APP", message: "core exited with status \(code)")
        if stopping || code == 0 {
            state = .stopped
        } else {
            let reason = logs.last(where: { $0.message.hasPrefix("error:") })?.message ?? "the core exited with status \(code)"
            state = .failed(reason)
        }
    }

    private func sampleTraffic(_ api: APIClient, elapsed: Double) async {
        guard let now = try? await api.traffic() else { return }
        if let prev = traffic, elapsed > 0 {
            upRate = Double(now.up >= prev.up ? now.up - prev.up : 0) / elapsed
            downRate = Double(now.down >= prev.down ? now.down - prev.down : 0) / elapsed
            rateHistory.append((upRate, downRate))
            if rateHistory.count > 60 { rateHistory.removeFirst(rateHistory.count - 60) }
        }
        traffic = now
    }

    private func poll() async {
        var tick = 0
        var last = Date()
        while !Task.isCancelled {
            if let pid = rootPID {
                followLog()
                if !Core.alive(pid) {
                    followLog()
                    exited(code: stopping ? 0 : 1)
                    return
                }
            }
            if let api, state == .starting || tick % 2 == 0, let fresh = try? await api.policies() {
                groups = fresh
                if state == .starting { state = .running }
                if let m = try? await api.mode() { mode = m }
            }
            if let api, state == .running {
                await sampleTraffic(api, elapsed: Date().timeIntervalSince(last))
                last = Date()
            }
            tick += 1
            // Policies every 2 s, traffic every 1 s; faster while starting or following a root log.
            try? await Task.sleep(for: .seconds(state == .starting || rootPID != nil ? 0.3 : 1))
        }
    }

    // MARK: actions

    private func perform(_ what: String, _ body: @escaping (APIClient) async throws -> Void) {
        guard let api else { return }
        Task {
            do {
                try await body(api)
                lastActionError = nil
                if let fresh = try? await api.policies() { groups = fresh }
            } catch {
                lastActionError = "\(what)失败：\(error.localizedDescription)"
            }
        }
    }

    func select(group: String, option: String) {
        perform("切换到 \(option) ") { try await $0.select(group: group, option: option) }
    }

    func test(group: String) {
        guard state == .running, let api, !testingGroups.contains(group) else { return }
        testingGroups.insert(group)
        Task {
            defer { testingGroups.remove(group) }
            do {
                try await api.test(group: group)
                if let fresh = try? await api.policies() { groups = fresh }
            } catch {
                lastActionError = "测试 \(group) 失败：\(error.localizedDescription)"
            }
        }
    }

    func testAll() {
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
        refreshSummary()
        if let fresh = try? await api.policies() { groups = fresh }
    }

    func route(_ target: String) async throws -> RouteResult {
        guard let api, state == .running else { throw APIError(message: "Sluice 未运行") }
        return try await api.route(target)
    }

    // MARK: config editing

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
    func addSubscription(name: String, url: String, filter: String) async -> String? {
        let url = url.trimmingCharacters(in: .whitespaces)
        guard url.hasPrefix("http://") || url.hasPrefix("https://") else { return "订阅地址需要以 http:// 或 https:// 开头。" }
        var text = readConfig()
        let group = uniqueName(name.trimmingCharacters(in: .whitespaces).isEmpty ? "Subscription" : name, in: text)
        var line = "\(group) = select, policy-path=\(url)"
        if !filter.trimmingCharacters(in: .whitespaces).isEmpty { line += ", policy-regex-filter=\(filter)" }
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
        guard let (_, port) = SystemProxy.split(summary.httpListen) else { systemProxyOn = false; return }
        Task { systemProxyOn = await SystemProxy.isPointing(atPort: port) }
    }

    func setSystemProxy(_ on: Bool) {
        let http = SystemProxy.split(summary.httpListen)
        let socks = SystemProxy.split(summary.socksListen)
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

    func clearLogs() { logs = [] }
    func clearConnections() { connections = [] }

    // MARK: output parsing

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
        guard let m = line.wholeMatch(of: Core.logPattern) else {
            appendLog(level: line.hasPrefix("error:") ? "ERROR" : "OUT", message: line)
            return
        }
        let (time, level, message) = (String(m.1), String(m.2), String(m.3))
        appendLog(time: time, level: level, message: message)
        if let c = message.wholeMatch(of: Core.connPattern) {
            nextID += 1
            connections.append(Connection(
                id: nextID, time: Core.shortTime(time), proto: c.1 == nil ? "TCP" : "UDP",
                target: String(c.2), policy: String(c.3), rule: String(c.4), outbound: String(c.5)))
            if connections.count > maxLines { connections.removeFirst(connections.count - maxLines) }
        }
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
