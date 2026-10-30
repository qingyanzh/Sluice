import Sparkle
import SwiftUI

/// Sparkle 2 updater. The feed URL, public EdDSA key and daily check interval come from
/// Info.plist (written by scripts/build-app.sh); it only starts inside a real app bundle.
@MainActor
final class Updater: ObservableObject {
    static let shared = Updater()

    private let controller: SPUStandardUpdaterController?
    @Published private(set) var canCheck = false

    private init() {
        guard Bundle.main.object(forInfoDictionaryKey: "SUFeedURL") != nil else {
            controller = nil
            return
        }
        let controller = SPUStandardUpdaterController(startingUpdater: true, updaterDelegate: nil, userDriverDelegate: nil)
        self.controller = controller
        controller.updater.publisher(for: \.canCheckForUpdates).assign(to: &$canCheck)
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
