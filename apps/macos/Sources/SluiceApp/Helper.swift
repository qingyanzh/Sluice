import Combine
import Foundation
import ServiceManagement
import SluiceHelperShared

/// Presentation state is separate from whether enhanced mode is enabled in the config.
enum HelperStatus: Equatable {
    case notInstalled, needsApproval, ready, failed(String)

    static func resolve(bundled: Bool, status: SMAppService.Status, error: String? = nil) -> Self {
        guard bundled else { return .failed("请从完整的 Sluice.app 运行。此构建未包含增强模式辅助程序。") }
        switch status {
        case .enabled: return .ready
        case .requiresApproval: return .needsApproval
        case .notRegistered, .notFound:
            // Service Management may not know an unregistered daemon yet. Bundle
            // validation above determines whether its files are actually missing;
            // preserve a real registration failure after the user tries installing.
            return error.map { .failed($0) } ?? .notInstalled
        @unknown default:
            return .failed(error ?? "无法识别辅助程序状态，请重试。")
        }
    }

    var title: String {
        switch self {
        case .notInstalled: "未安装"
        case .needsApproval: "待批准"
        case .ready: "已就绪"
        case .failed: "错误"
        }
    }

    var action: String {
        switch self {
        case .notInstalled: "安装辅助程序"
        case .needsApproval: "打开系统设置"
        case .ready: "刷新状态"
        case .failed: "重试"
        }
    }

    var detail: String {
        switch self {
        case .notInstalled: "安装后可由辅助程序启动增强模式，减少重复的管理员授权。"
        case .needsApproval: "请在系统设置 › 通用 › 登录项与扩展中允许 Sluice 在后台运行，然后返回此处。"
        case .ready: "辅助程序已获授权。开启增强模式后，可接管不遵循系统代理的应用。"
        case .failed(let message): message
        }
    }
}

@MainActor
final class HelperSettings: ObservableObject {
    @Published private(set) var status = HelperStatus.resolve(bundled: HelperClient.bundled, status: HelperClient.service.status)
    private var registrationError: String?

    func refresh() {
        status = .resolve(bundled: HelperClient.bundled, status: HelperClient.service.status, error: registrationError)
        if status == .ready || status == .needsApproval { registrationError = nil }
    }

    func performAction() {
        switch status {
        case .needsApproval:
            SMAppService.openSystemSettingsLoginItems()
        case .ready:
            refresh()
        case .notInstalled, .failed:
            registrationError = nil
            if case .unavailable(let message) = HelperClient.prepare() { registrationError = message }
            refresh()
        }
    }
}

/// Client for the privileged helper daemon that runs the core as root (docs/helper.md).
/// Enhanced mode falls back to the administrator prompt whenever the helper isn't usable.
enum HelperClient {
    enum Readiness: Equatable {
        case ready
        /// Registered, but the user still has to allow it in Login Items & Extensions.
        case needsApproval
        case unavailable(String)
    }

    static var service: SMAppService { .daemon(plistName: SluiceHelperInfo.plistName) }

    /// Only a built Sluice.app carries the daemon plist; `swift run` doesn't.
    static var bundled: Bool {
        bundled(in: Bundle.main.bundleURL)
    }

    static func bundled(in bundle: URL) -> Bool {
        let plist = bundle.appendingPathComponent("Contents/Library/LaunchDaemons/\(SluiceHelperInfo.plistName)")
        guard let data = try? Data(contentsOf: plist),
              let info = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any],
              info["Label"] as? String == SluiceHelperInfo.machService,
              info["BundleProgram"] as? String == "Contents/MacOS/SluiceHelper" else { return false }
        return FileManager.default.isExecutableFile(atPath: bundle.appendingPathComponent("Contents/MacOS/SluiceHelper").path)
    }

    /// Registers the daemon on first use; macOS then asks the user to approve it.
    static func prepare() -> Readiness {
        guard bundled else { return .unavailable("not running from Sluice.app") }
        switch service.status {
        case .enabled: return .ready
        case .requiresApproval: return .needsApproval
        default:
            do { try service.register() } catch {
                return service.status == .requiresApproval ? .needsApproval : .unavailable(error.localizedDescription)
            }
            switch service.status {
            case .enabled: return .ready
            case .requiresApproval: return .needsApproval
            default: return .unavailable("辅助程序注册后仍不可用，请重试或重新安装 Sluice.app。")
            }
        }
    }

    /// Command-line entry used by tests and CI (`Sluice --helper <cmd>`); returns the exit status.
    static func command(_ cmd: String) -> Int32 {
        let sema = DispatchSemaphore(value: 0)
        var status: Int32 = 0
        switch cmd {
        case "status":
            print("bundled \(bundled), status \(describe(service.status))")
            status = bundled ? 0 : 1
        case "register":
            print("\(prepare()), status \(describe(service.status))")
        case "unregister":
            service.unregister { error in
                if let error { print("error: \(error.localizedDescription)"); status = 1 } else { print("unregistered") }
                sema.signal()
            }
            sema.wait()
        case "hello":
            Task.detached {
                do { let (v, uid) = try await hello(); print("helper version \(v), uid \(uid)") } catch {
                    print("error: \(error.localizedDescription)"); status = 1
                }
                sema.signal()
            }
            sema.wait()
        default:
            print("usage: Sluice --helper status|register|unregister|hello")
            status = 2
        }
        return status
    }

    private static func describe(_ s: SMAppService.Status) -> String {
        switch s {
        case .notRegistered: "notRegistered"
        case .enabled: "enabled"
        case .requiresApproval: "requiresApproval"
        case .notFound: "notFound"
        @unknown default: "unknown"
        }
    }

    // Keep the ownership connection alive for the app's lifetime. Its invalidation
    // is a second stop trigger alongside the helper's process-exit watch.
    // NSXPCConnection supports calls/invalidation from arbitrary queues. Keep that
    // thread-safety assertion local instead of adding a global Sendable conformance.
    private final class ConnectionLease: @unchecked Sendable {
        let value: NSXPCConnection
        init(_ value: NSXPCConnection) { self.value = value }
    }

    private static let connectionLock = NSLock()
    private static var connection: NSXPCConnection?

    private static func liveConnection() -> NSXPCConnection {
        connectionLock.lock()
        defer { connectionLock.unlock() }
        if let connection { return connection }
        let c = NSXPCConnection(machServiceName: SluiceHelperInfo.machService, options: .privileged)
        c.remoteObjectInterface = SluiceHelperInfo.interface()
        c.invalidationHandler = { [weak c] in
            connectionLock.lock()
            defer { connectionLock.unlock() }
            if connection === c { connection = nil }
        }
        c.resume()
        connection = c
        return c
    }

    private static func call<T>(timeout: TimeInterval = 15, _ body: @escaping (SluiceHelperProtocol, @escaping (T) -> Void) -> Void) async throws -> T {
        let c = liveConnection()
        let lease = ConnectionLease(c)
        return try await withCheckedThrowingContinuation { cont in
            let once = Once()
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                once.run {
                    cont.resume(throwing: APIError(message: "helper: timed out"))
                    DispatchQueue.global().async { lease.value.invalidate() }
                }
            }
            let proxy = c.remoteObjectProxyWithErrorHandler { error in
                once.run { cont.resume(throwing: APIError(message: "helper: \(error.localizedDescription)")) }
            } as! SluiceHelperProtocol
            body(proxy) { value in once.run { cont.resume(returning: value) } }
        }
    }

    static func status() async throws -> Int32 { try await call(timeout: 2) { p, done in p.status(reply: done) } }

    /// XPC replies arrive on its own queue, so applicationWillTerminate can wait
    /// synchronously without needing the main actor to resume an async Task.
    static func stopSynchronously() {
        let done = DispatchSemaphore(value: 0)
        let c = liveConnection()
        let proxy = c.remoteObjectProxyWithErrorHandler { _ in done.signal() } as! SluiceHelperProtocol
        proxy.stop { _ in done.signal() }
        _ = done.wait(timeout: .now() + 12)
    }

    static func hello() async throws -> (String, Int32) {
        try await call { p, done in p.hello { done(($0, $1)) } }
    }

    static func start(config: String) async throws -> (pid: Int32, log: String) {
        let (pid, log, error): (Int32, String, String?) = try await call { p, done in
            p.start(config: config, appPID: getpid()) { done(($0, $1, $2)) }
        }
        if let error { throw APIError(message: error) }
        return (pid, log)
    }

    static func stop() async throws {
        let error: String? = try await call { p, done in p.stop { done($0) } }
        if let error { throw APIError(message: error) }
    }
}

/// Guards a continuation against the reply and the error handler both firing.
private final class Once: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false
    func run(_ f: () -> Void) {
        lock.lock(); defer { lock.unlock() }
        if !done { done = true; f() }
    }
}
