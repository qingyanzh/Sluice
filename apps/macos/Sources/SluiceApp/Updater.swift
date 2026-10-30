import Sparkle
import SwiftUI

struct UpdateInfo: Equatable {
    let version: String
    let channel: String

    init(info: [String: Any], feedURL: URL?) {
        let release = info["CFBundleShortVersionString"] as? String
        let build = info["CFBundleVersion"] as? String
        version = release.map { version in
            build.map { "\(version) (\($0))" } ?? version
        } ?? "开发版本"
        if let feedURL {
            channel = feedURL.scheme == "https"
                && feedURL.host == "github.com"
                && feedURL.path == "/qingyanzh/Sluice/releases/latest/download/appcast.xml"
                && feedURL.query == nil ? "稳定版" : "自定义"
        } else {
            channel = "未配置"
        }
    }
}

/// Sparkle 2 updater. The feed URL, public EdDSA key and daily check interval come from
/// Info.plist (written by scripts/build-app.sh); it only starts inside a real app bundle.
@MainActor
final class Updater: ObservableObject {
    static let shared = Updater()

    private let controller: SPUStandardUpdaterController?
    @Published private(set) var canCheck = false
    @Published private(set) var lastCheck: Date?
    @Published private(set) var sessionInProgress = false

    var isAvailable: Bool { controller != nil }
    var info: UpdateInfo {
        UpdateInfo(info: Bundle.main.infoDictionary ?? [:], feedURL: controller?.updater.feedURL)
    }

    private init() {
        guard E2ELaunch.current == nil, Bundle.main.object(forInfoDictionaryKey: "SUFeedURL") != nil else {
            controller = nil
            return
        }
        let controller = SPUStandardUpdaterController(startingUpdater: true, updaterDelegate: nil, userDriverDelegate: nil)
        self.controller = controller
        controller.updater.publisher(for: \.canCheckForUpdates).assign(to: &$canCheck)
        controller.updater.publisher(for: \.lastUpdateCheckDate).assign(to: &$lastCheck)
        controller.updater.publisher(for: \.sessionInProgress).assign(to: &$sessionInProgress)
    }

    func checkForUpdates() { controller?.checkForUpdates(nil) }
}

struct CheckForUpdatesButton: View {
    @ObservedObject private var updater = Updater.shared

    var body: some View {
        Button("检查更新…", systemImage: "arrow.down.circle") { updater.checkForUpdates() }
            .disabled(!updater.canCheck)
    }
}
