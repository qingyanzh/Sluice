import Foundation

/// Owned by the window, so navigating away never discards an editor draft.
@MainActor
final class ConfigDraft: ObservableObject {
    @Published var editorMode = E2ELaunch.current?.editorMode ?? "文本"
    @Published var text = ""
    @Published var saved = ""
    @Published var path = ""
    @Published var message: (String, Bool)?
    @Published var busy = false
    @Published var changedOnDisk = false
    var hasChanges: Bool { text != saved }

    func refresh(path: String, disk: String) {
        if self.path != path || !hasChanges {
            self.path = path
            text = disk
            saved = disk
            changedOnDisk = false
        } else {
            changedOnDisk = disk != saved
        }
    }

    func restore(_ disk: String) {
        text = disk
        saved = disk
        changedOnDisk = false
        message = nil
    }
}
