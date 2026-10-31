import Foundation
import Security
import SluiceHelperShared

// Privileged helper: a launchd daemon (registered by the app with SMAppService) that runs the
// Rust core as root for enhanced mode. See docs/helper.md for the security model.
//
//   SluiceHelper                 run as the daemon (launchd starts it this way)
//   SluiceHelper client <cmd>    talk to a running daemon: hello | status | start <config> | stop

/// Directory holding this executable (Contents/MacOS inside the app bundle).
let selfDir = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath().deletingLastPathComponent()
let env = ProcessInfo.processInfo.environment

/// The core binary: fixed by the daemon, never chosen by the caller.
let coreBinary = env["SLUICE_HELPER_CORE"]
    ?? selfDir.deletingLastPathComponent().appendingPathComponent("Resources/sluice").path
/// The only executable allowed to connect when the bundle isn't Developer ID signed.
let allowedClient = env["SLUICE_HELPER_CLIENT"] ?? selfDir.appendingPathComponent("Sluice").path

/// Where the core's output goes; overridable only through the daemon's own plist.
let coreLog = env["SLUICE_HELPER_LOG"] ?? SluiceHelperInfo.logPath
/// Configured by launchd's plist, never by an XPC caller.
let coreStageDirectory = env["SLUICE_HELPER_STAGE_DIR"] ?? "/Library/Application Support/Sluice/Helper"

func log(_ s: String) { FileHandle.standardError.write("SluiceHelper: \(s)\n".data(using: .utf8)!) }

/// Team ID this helper is signed with, nil for ad-hoc/unsigned builds.
func ownTeamID() -> String? {
    var code: SecCode?
    guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return nil }
    var staticCode: SecStaticCode?
    guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
    var info: CFDictionary?
    guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
          let dict = info as? [String: Any] else { return nil }
    return dict[kSecCodeInfoTeamIdentifier as String] as? String
}

func executablePath(of pid: pid_t) -> String? {
    var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
    guard proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 else { return nil }
    return URL(fileURLWithPath: String(cString: buf)).resolvingSymlinksInPath().path
}

// MARK: daemon

final class CoreRunner: NSObject, SluiceHelperProtocol {
    private let queue = DispatchQueue(label: "core")
    private var process: Process?
    private var appWatch: ProcessWatch?
    private var owner: UUID?
    private var stopReplies: [(String?) -> Void] = []

    func hello(reply: @escaping (String, Int32) -> Void) {
        reply(SluiceHelperInfo.version, Int32(bitPattern: getuid()))
    }

    func status(reply: @escaping (Int32) -> Void) {
        queue.async { reply(self.process.flatMap { $0.isRunning ? $0.processIdentifier : nil } ?? 0) }
    }

    func start(config: String, appPID: Int32, reply: @escaping (Int32, String, String?) -> Void) {
        startOwned(config: config, appPID: appPID, owner: nil, reply: reply)
    }

    func startOwned(config: String, appPID: Int32, owner: UUID?, reply: @escaping (Int32, String, String?) -> Void) {
        queue.async {
            guard self.stopReplies.isEmpty else { return reply(0, "", "the core is still stopping") }
            if let p = self.process, p.isRunning {
                return reply(p.processIdentifier, coreLog, "the core is already running")
            }
            let stagedCore: URL
            do {
                stagedCore = try stageCore(from: coreBinary, in: coreStageDirectory, teamID: ownTeamID())
            } catch {
                log("refused core: \(error.localizedDescription)")
                return reply(0, "", "refused core: \(error.localizedDescription)")
            }
            var launched = false
            defer { if !launched { try? FileManager.default.removeItem(at: stagedCore.deletingLastPathComponent()) } }
            let logURL = URL(fileURLWithPath: coreLog)
            let fm = FileManager.default
            try? fm.createDirectory(at: logURL.deletingLastPathComponent(), withIntermediateDirectories: true,
                                    attributes: [.posixPermissions: 0o755])
            // Recreate rather than open, so a planted symlink is never followed.
            try? fm.removeItem(at: logURL)
            guard fm.createFile(atPath: logURL.path, contents: nil, attributes: [.posixPermissions: 0o644]),
                  let out = FileHandle(forWritingAtPath: logURL.path) else {
                return reply(0, "", "can't write \(logURL.path)")
            }
            defer { try? out.close() }
            let p = Process()
            p.executableURL = stagedCore
            p.arguments = ["run", config]
            p.currentDirectoryURL = URL(fileURLWithPath: config).deletingLastPathComponent()
            p.standardInput = FileHandle.nullDevice
            p.standardOutput = out
            p.standardError = out
            p.terminationHandler = { proc in
                try? FileManager.default.removeItem(at: stagedCore.deletingLastPathComponent())
                log("core \(proc.processIdentifier) exited with \(proc.terminationStatus)")
                self.queue.async {
                    if self.process === proc { self.process = nil; self.appWatch?.cancel(); self.appWatch = nil }
                }
            }
            do { try p.run() } catch { return reply(0, "", "couldn't launch the core: \(error.localizedDescription)") }
            launched = true
            self.process = p
            self.owner = owner
            self.watch(appPID)
            log("started core \(p.processIdentifier) for app \(appPID) with \(config)")
            reply(p.processIdentifier, coreLog, nil)
        }
    }

    /// Stops the core when the app exits, crashes included, so TUN/DNS changes never outlive it.
    private func watch(_ pid: Int32) {
        appWatch?.cancel()
        appWatch = nil
        guard let watchedCore = process else { return }
        appWatch = ProcessWatch(pid: pid, queue: queue) { [weak self, weak watchedCore] in
            guard let self, let watchedCore, self.process === watchedCore else { return }
            log("app \(pid) exited; stopping the core")
            self.stopLocked { _ in }
        }
    }

    func connectionEnded(_ id: UUID) {
        queue.async {
            guard self.owner == id else { return }
            log("owner connection invalidated; stopping the core")
            self.stopLocked { _ in }
        }
    }

    func stop(reply: @escaping (String?) -> Void) {
        queue.async { self.stopLocked(reply) }
    }

    /// SIGTERM lets the core restore routes and DNS; SIGKILL only if it hangs for 10 s
    /// (the utun closes with the process and the next start restores the DNS backup).
    private func stopLocked(_ reply: @escaping (String?) -> Void) {
        appWatch?.cancel()
        appWatch = nil
        owner = nil
        if !stopReplies.isEmpty { stopReplies.append(reply); return }
        guard let p = process else { return reply(nil) }
        guard p.isRunning else { p.waitUntilExit(); process = nil; return reply(nil) }
        stopReplies.append(reply)
        p.terminate()
        DispatchQueue.global().async {
            let deadline = ContinuousClock.now + .seconds(10)
            while p.isRunning && ContinuousClock.now < deadline { usleep(50_000) }
            if p.isRunning { kill(p.processIdentifier, SIGKILL) }
            let killDeadline = ContinuousClock.now + .seconds(2)
            while p.isRunning && ContinuousClock.now < killDeadline { usleep(50_000) }
            let error = p.isRunning ? "core \(p.processIdentifier) did not exit after SIGKILL" : nil
            if error == nil { p.waitUntilExit() }
            self.queue.async {
                if error == nil, self.process === p { self.process = nil }
                let replies = self.stopReplies
                self.stopReplies = []
                for reply in replies { reply(error) }
            }
        }
    }
}

/// Only the connection that started this core owns its lifetime. Short-lived status,
/// stop and CLI connections must never stop somebody else's core on invalidation.
final class ClientSession: NSObject, SluiceHelperProtocol {
    let runner: CoreRunner
    let id = UUID()
    let pid: Int32
    init(runner: CoreRunner, pid: Int32) { self.runner = runner; self.pid = pid }
    func hello(reply: @escaping (String, Int32) -> Void) { runner.hello(reply: reply) }
    func status(reply: @escaping (Int32) -> Void) { runner.status(reply: reply) }
    func stop(reply: @escaping (String?) -> Void) { runner.stop(reply: reply) }
    func start(config: String, appPID: Int32, reply: @escaping (Int32, String, String?) -> Void) {
        // CLI can explicitly watch a separate test process; normal apps own the XPC lease.
        runner.startOwned(config: config, appPID: appPID, owner: appPID == pid ? id : nil, reply: reply)
    }
}

final class Listener: NSObject, NSXPCListenerDelegate {
    let runner = CoreRunner()
    let teamID = ownTeamID()

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection c: NSXPCConnection) -> Bool {
        if let teamID {
            // Signed build: the kernel-backed check on every message, immune to PID reuse.
            c.setCodeSigningRequirement(
                "anchor apple generic and identifier \"dev.sluice.Sluice\" and certificate leaf[subject.OU] = \"\(teamID)\"")
        } else {
            // Ad-hoc build: no identity to check, so fall back to the caller's executable path.
            // Weaker (PID reuse races, anyone able to write that path wins); see docs/helper.md.
            let path = executablePath(of: c.processIdentifier)
            guard path == URL(fileURLWithPath: allowedClient).resolvingSymlinksInPath().path else {
                log("rejected pid \(c.processIdentifier) (\(path ?? "?")), expected \(allowedClient)")
                return false
            }
        }
        c.exportedInterface = SluiceHelperInfo.interface()
        let session = ClientSession(runner: runner, pid: c.processIdentifier)
        c.exportedObject = session
        c.invalidationHandler = { [runner] in runner.connectionEnded(session.id) }
        c.interruptionHandler = { [runner] in runner.connectionEnded(session.id) }
        c.resume()
        return true
    }
}

// MARK: client (tests and CI)

func client(_ args: [String]) -> Int32 {
    // SLUICE_HELPER_USER_DOMAIN=1 talks to a copy loaded as a user agent (local tests without root).
    let options: NSXPCConnection.Options = env["SLUICE_HELPER_USER_DOMAIN"] == "1" ? [] : .privileged
    let c = NSXPCConnection(machServiceName: SluiceHelperInfo.machService, options: options)
    c.remoteObjectInterface = SluiceHelperInfo.interface()
    c.resume()
    let done = DispatchSemaphore(value: 0)
    var code: Int32 = 0
    let proxy = c.remoteObjectProxyWithErrorHandler { error in
        print("error: \(error.localizedDescription)")
        code = 1
        done.signal()
    } as! SluiceHelperProtocol
    switch args.first {
    case "hello":
        proxy.hello { version, uid in print("helper version \(version), uid \(uid)"); done.signal() }
    case "status":
        proxy.status { pid in print("core pid \(pid)"); done.signal() }
    case "start" where args.count >= 2:
        let watch = args.count >= 3 ? Int32(args[2]) ?? 0 : 0
        proxy.start(config: args[1], appPID: watch) { pid, logPath, error in
            if let error { print("error: \(error)"); code = 1 } else { print("core pid \(pid), log \(logPath)") }
            done.signal()
        }
    case "stop":
        proxy.stop { error in
            if let error { print("error: \(error)"); code = 1 } else { print("stopped") }
            done.signal()
        }
    default:
        print("usage: SluiceHelper client hello | status | start <config> [watch-pid] | stop")
        return 2
    }
    if done.wait(timeout: .now() + 30) == .timedOut { print("error: timed out"); return 1 }
    return code
}

if CommandLine.arguments.dropFirst().first == "client" {
    exit(client(Array(CommandLine.arguments.dropFirst(2))))
}
let delegate = Listener()
let listener = NSXPCListener(machServiceName: SluiceHelperInfo.machService)
listener.delegate = delegate
listener.resume()
log("listening on \(SluiceHelperInfo.machService) (core \(coreBinary), \(delegate.teamID.map { "team \($0)" } ?? "ad-hoc: client \(allowedClient)"))")
dispatchMain()
