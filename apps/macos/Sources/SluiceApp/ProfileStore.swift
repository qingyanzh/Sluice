import Foundation

/// File names are profile names plus `.conf`. All file operations stay in this directory.
final class ProfileStore {
    static let activeNameKey = "activeProfileName"
    let baseDirectory: URL
    private let defaults: UserDefaults
    private let files = FileManager.default
    private(set) var activeName: String

    enum StoreError: LocalizedError {
        case invalidName, duplicateName, missingProfile, activeProfile

        var errorDescription: String? {
            switch self {
            case .invalidName: "名称不能为空、以点开头或结尾、包含路径或特殊字符，也不能以 .conf 结尾（扩展名会自动添加）。"
            case .duplicateName: "已存在同名配置，请使用其他名称。"
            case .missingProfile: "找不到这个配置文件，请刷新列表。"
            case .activeProfile: "不能删除当前使用的配置，请先切换到其他配置。"
            }
        }
    }

    /// By default, migrate the legacy `sluice.conf` beside the profiles directory.
    init(baseDirectory: URL, defaults: UserDefaults = .standard, migratingFrom source: URL? = nil) throws {
        self.baseDirectory = baseDirectory
        self.defaults = defaults
        activeName = ""
        try files.createDirectory(at: baseDirectory, withIntermediateDirectories: true)
        if try names().isEmpty {
            try validateAvailableName("Default")
            let source = source ?? baseDirectory.deletingLastPathComponent().appendingPathComponent("sluice.conf")
            // Copy the bytes rather than the file entry, so even a legacy symlink
            // becomes an independent profile. The original is never modified.
            try Data(contentsOf: source).write(to: url(for: "Default"), options: .withoutOverwriting)
        }
        let available = try names()
        let saved = defaults.string(forKey: Self.activeNameKey)
        guard let selected = available.first(where: { $0 == saved }) ?? available.first else {
            throw StoreError.missingProfile
        }
        activeName = selected
        defaults.set(activeName, forKey: Self.activeNameKey)
    }

    static func validateName(_ name: String) throws {
        let forbidden = CharacterSet(charactersIn: "/\\:<>\"|?*").union(.controlCharacters)
        guard !name.isEmpty, name == name.trimmingCharacters(in: .whitespacesAndNewlines),
              !name.hasPrefix("."), !name.hasSuffix("."),
              !name.lowercased().hasSuffix(".conf"), name.utf8.count <= 240,
              name.rangeOfCharacter(from: forbidden) == nil else { throw StoreError.invalidName }
    }

    func names() throws -> [String] {
        try files.contentsOfDirectory(at: baseDirectory, includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey])
            .filter { url in
                guard url.pathExtension == "conf",
                      (try? Self.validateName(url.deletingPathExtension().lastPathComponent)) != nil else { return false }
                let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
                return values.isRegularFile == true && values.isSymbolicLink != true
            }
            .map { $0.deletingPathExtension().lastPathComponent }
            .sorted { $0.localizedStandardCompare($1) == .orderedAscending }
    }

    func url(for name: String) -> URL {
        baseDirectory.appendingPathComponent(name).appendingPathExtension("conf")
    }

    func validateAvailableName(_ name: String) throws {
        try Self.validateName(name)
        let filename = name + ".conf"
        guard try !files.contentsOfDirectory(atPath: baseDirectory.path).contains(where: {
            $0.caseInsensitiveCompare(filename) == .orderedSame
        }) else { throw StoreError.duplicateName }
    }

    private func existingURL(_ name: String) throws -> URL {
        try Self.validateName(name)
        guard try names().contains(name) else { throw StoreError.missingProfile }
        return url(for: name)
    }

    func create(name: String, contents: String) throws {
        try validateAvailableName(name)
        try Data(contents.utf8).write(to: url(for: name), options: .withoutOverwriting)
    }

    func duplicate(_ name: String, as newName: String) throws {
        let source = try existingURL(name)
        try validateAvailableName(newName)
        try files.copyItem(at: source, to: url(for: newName))
    }

    func read(_ name: String) throws -> String {
        try String(contentsOf: existingURL(name), encoding: .utf8)
    }

    func replace(_ name: String, contents: String, expected: String) throws {
        let destination = try existingURL(name)
        guard try String(contentsOf: destination, encoding: .utf8) == expected else {
            throw APIError(message: "目标配置已被其他操作修改，没有覆盖。请刷新后重试。")
        }
        try contents.write(to: destination, atomically: true, encoding: .utf8)
    }

    func rename(_ name: String, to newName: String) throws {
        let source = try existingURL(name)
        if name == newName { return }
        try validateAvailableName(newName)
        try files.moveItem(at: source, to: url(for: newName))
        if activeName == name {
            activeName = newName
            defaults.set(newName, forKey: Self.activeNameKey)
        }
    }

    func delete(_ name: String) throws {
        let source = try existingURL(name)
        guard name != activeName else { throw StoreError.activeProfile }
        try files.removeItem(at: source)
    }

    func activate(_ name: String) throws {
        let source = try existingURL(name)
        // The editor and core both require a readable UTF-8 configuration.
        _ = try String(contentsOf: source, encoding: .utf8)
        activeName = name
        defaults.set(name, forKey: Self.activeNameKey)
    }
}
