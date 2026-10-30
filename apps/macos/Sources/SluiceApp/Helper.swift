import Foundation
import ServiceManagement
import SluiceHelperShared

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
        let plist = Bundle.main.bundleURL.appendingPathComponent("Contents/Library/LaunchDaemons/\(SluiceHelperInfo.plistName)")
        return FileManager.default.fileExists(atPath: plist.path)
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
            return service.status == .enabled ? .ready : .needsApproval
        }
    }

    /// Command-line entry used by tests and CI (`Sluice --helper <cmd>`); returns the exit status.
    static func command(_ cmd: String) -> Int32 {
        let sema = DispatchSemaphore(value: 0)
        var status: Int32 = 0
        switch cmd {
        case "status":
            print("bundled \(bundled), status \(describe(service.status))")
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

    /// One XPC round trip; the connection is dropped afterwards (the helper watches the app's PID,
    /// not the connection, to know when to stop the core).
    private static func call<T>(_ body: @escaping (SluiceHelperProtocol, @escaping (T) -> Void) -> Void) async throws -> T {
        let c = NSXPCConnection(machServiceName: SluiceHelperInfo.machService, options: .privileged)
        c.remoteObjectInterface = SluiceHelperInfo.interface()
        c.resume()
        defer { c.invalidate() }
        return try await withCheckedThrowingContinuation { cont in
            let once = Once()
            let proxy = c.remoteObjectProxyWithErrorHandler { error in
                once.run { cont.resume(throwing: APIError(message: "helper: \(error.localizedDescription)")) }
            } as! SluiceHelperProtocol
            body(proxy) { value in once.run { cont.resume(returning: value) } }
        }
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
