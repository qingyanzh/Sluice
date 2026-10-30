import AppKit
import Foundation

/// CI-only screenshot controls, including release builds produced by build-app.sh.
/// Both GITHUB_ACTIONS=true and SLUICE_E2E=1 are required; ordinary launches ignore
/// every argument below. No Accessibility permission or generated UI data is used.
/// -SluiceE2EAPI host:port attaches without owning/stopping the existing core.
/// -SluiceE2EConfig /absolute/profile.conf uses that directory's real profiles.
/// -SluiceE2EPane selects a pane/subpane (see `destinations`).
/// -SluiceE2EReady /absolute/file.json reports a populated, positioned window.
/// SLUICE_E2E_NODE_TESTS points to saved /v1/nodes/<name>/test responses, since
/// GET snapshots expose health latency but not the detailed test response.
struct E2ELaunch {
    static let destinations: [String: Pane] = [
        "activity": .activity, "requests": .requests, "requests-recent": .requests,
        "requests-active": .requests, "policy": .policy, "policies": .policy,
        "nodes": .nodes, "rule": .rule, "rules": .rule, "dns": .dns,
        "stats": .activity, "profile": .profile, "profiles": .profile,
        "editor-rules": .profile, "editor-policies": .profile,
        "settings": .overview, "settings-maintenance": .overview, "logs": .logs,
    ]
    static let current = parse(arguments: CommandLine.arguments, environment: ProcessInfo.processInfo.environment)

    let host: String
    let port: Int
    let config: URL
    let destination: String
    let ready: URL
    let nodeTests: URL?
    let preferenceDomain = "dev.sluice.e2e.\(UUID().uuidString)"
    var pane: Pane { Self.destinations[destination]! }
    var editorMode: String {
        destination == "editor-rules" ? "规则" : destination == "editor-policies" ? "策略组" : "文本"
    }

    static func parse(arguments: [String], environment: [String: String]) -> Self? {
        guard environment["GITHUB_ACTIONS"] == "true", environment["SLUICE_E2E"] == "1" else { return nil }
        func value(_ flag: String) -> String? {
            guard let index = arguments.firstIndex(of: flag), arguments.indices.contains(index + 1) else { return nil }
            return arguments[index + 1]
        }
        guard let address = value("-SluiceE2EAPI"),
              let components = URLComponents(string: "http://\(address)"),
              let host = components.host, ["127.0.0.1", "localhost", "[::1]", "::1"].contains(host),
              let port = components.port, (1...65535).contains(port),
              components.user == nil, components.password == nil, components.path.isEmpty,
              components.query == nil, components.fragment == nil,
              let config = value("-SluiceE2EConfig"), config.hasPrefix("/"),
              let destination = value("-SluiceE2EPane"), destinations[destination] != nil,
              let ready = value("-SluiceE2EReady"), ready.hasPrefix("/") else { return nil }
        return Self(host: host, port: port, config: URL(fileURLWithPath: config), destination: destination,
                    ready: URL(fileURLWithPath: ready),
                    nodeTests: environment["SLUICE_E2E_NODE_TESTS"].map { URL(fileURLWithPath: $0) })
    }

    /// No normal app preferences are read or written by a screenshot launch.
    func preferences() -> UserDefaults {
        let defaults = UserDefaults(suiteName: preferenceDomain)!
        // Argument/registration volatile domains are shared across UserDefaults
        // instances. A unique suite keeps this fixture isolated even in unit tests.
        defaults.set(config.path, forKey: "configPath")
        defaults.set(config.deletingPathExtension().lastPathComponent, forKey: ProfileStore.activeNameKey)
        defaults.set(false, forKey: "autoStart")
        defaults.set("light", forKey: "appearance")
        return defaults
    }

    @MainActor
    func prepareWindow(core: Core) async {
        let deadline = Date().addingTimeInterval(40)
        while Date() < deadline, !Task.isCancelled {
            if let window = NSApp.windows.first(where: { $0.isVisible && $0.canBecomeMain && $0.level == .normal }) {
                window.setContentSize(NSSize(width: 1120, height: 860))
                window.center()
                window.title = "Sluice E2E — \(destination)"
                window.makeKeyAndOrderFront(nil)
                if core.state == .running, core.traffic != nil, core.stats != nil,
                   !core.connections.isEmpty, core.rateHistory.count >= 4,
                   destination != "requests-active" || !core.activeConnections.isEmpty {
                    // Let pane-local DNS/rules loads, scrolling and entrance animations settle.
                    try? await Task.sleep(for: .seconds(3))
                    let report: [String: Any] = [
                        "pane": destination, "window": window.windowNumber,
                        "requests": core.connections.count, "active": core.activeConnections.count,
                        "groups": core.groups.count, "latencies": core.nodeLatencies.count,
                        "config": core.configPath,
                    ]
                    do { try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys]).write(to: ready, options: .atomic) }
                    catch { fputs("E2E readiness: \(error)\n", stderr) }
                    return
                }
            }
            try? await Task.sleep(for: .milliseconds(250))
        }
        fputs("E2E window/data readiness timed out for \(destination)\n", stderr)
    }
}
