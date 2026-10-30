import Foundation

/// The XPC interface between the app and the privileged helper (docs/helper.md).
@objc public protocol SluiceHelperProtocol {
    /// Handshake: the helper's version and the uid it runs as.
    func hello(reply: @escaping (_ version: String, _ uid: Int32) -> Void)
    /// Runs `sluice run <config>` as root. The core binary is fixed by the helper (never chosen
    /// by the caller); `appPID` is watched and the core is stopped when that process exits.
    /// Replies with the core's PID and the log file it writes to, or an error message.
    func start(config: String, appPID: Int32, reply: @escaping (_ pid: Int32, _ log: String, _ error: String?) -> Void)
    /// Stops the core with SIGINT so it restores routes and DNS; replies once it has exited.
    func stop(reply: @escaping (_ error: String?) -> Void)
    /// PID of the running core, or 0.
    func status(reply: @escaping (_ pid: Int32) -> Void)
}

public enum SluiceHelperInfo {
    public static let machService = "dev.sluice.Sluice.helper"
    public static let plistName = "dev.sluice.Sluice.helper.plist"
    public static let version = "1"
    public static let logPath = "/Library/Logs/Sluice/core.log"

    public static func interface() -> NSXPCInterface {
        NSXPCInterface(with: SluiceHelperProtocol.self)
    }
}
