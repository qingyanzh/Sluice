import XCTest
@testable import SluiceApp

final class ProfileStoreTests: XCTestCase {
    private var directory: URL!
    private var source: URL!
    private var defaults: UserDefaults!
    private var suite: String!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        source = directory.appendingPathComponent("original.conf")
        try "[General]\napi-listen = 127.0.0.1:6170\n".write(to: source, atomically: true, encoding: .utf8)
        suite = "ProfileStoreTests.\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: suite)!
    }

    override func tearDownWithError() throws {
        defaults.removePersistentDomain(forName: suite)
        try FileManager.default.removeItem(at: directory)
    }

    private func makeStore() throws -> ProfileStore {
        try ProfileStore(baseDirectory: directory.appendingPathComponent("profiles"),
                         defaults: defaults, migratingFrom: source)
    }

    func testMigrationCopiesOriginalAndDoesNotRepeat() throws {
        let store = try makeStore()
        XCTAssertEqual(try store.names(), ["Default"])
        XCTAssertEqual(store.activeName, "Default")
        XCTAssertEqual(try Data(contentsOf: store.url(for: "Default")), Data(contentsOf: source))
        XCTAssertTrue(FileManager.default.fileExists(atPath: source.path))
        try "changed original".write(to: source, atomically: true, encoding: .utf8)
        let reopened = try makeStore()
        XCTAssertEqual(try reopened.names(), ["Default"])
        XCTAssertNotEqual(try Data(contentsOf: reopened.url(for: "Default")), Data(contentsOf: source))
    }

    func testCreateAndDuplicatePreserveContentsAndActiveSelection() throws {
        let store = try makeStore()
        let text = "# 工作配置\n[Rule]\nFINAL,DIRECT\n"
        try store.create(name: "工作", contents: text)
        try store.duplicate("工作", as: "Home")
        XCTAssertEqual(try String(contentsOf: store.url(for: "工作"), encoding: .utf8), text)
        XCTAssertEqual(try String(contentsOf: store.url(for: "Home"), encoding: .utf8), text)
        XCTAssertEqual(Set(try store.names()), Set(["Default", "工作", "Home"]))
        XCTAssertEqual(store.activeName, "Default")
    }

    func testSwitchPersistsAndMissingSwitchKeepsCurrentSelection() throws {
        let store = try makeStore()
        try store.create(name: "Work", contents: "work")
        try store.activate("Work")
        XCTAssertEqual(store.activeName, "Work")
        XCTAssertEqual(defaults.string(forKey: ProfileStore.activeNameKey), "Work")
        XCTAssertEqual(try makeStore().activeName, "Work")
        XCTAssertThrowsError(try store.activate("missing"))
        XCTAssertThrowsError(try store.activate("../original"))
        XCTAssertEqual(store.activeName, "Work")
        XCTAssertEqual(defaults.string(forKey: ProfileStore.activeNameKey), "Work")
    }

    func testRenameActiveUpdatesSelectionAndPreservesFile() throws {
        let store = try makeStore()
        let original = try Data(contentsOf: store.url(for: "Default"))
        try store.rename("Default", to: "Work")
        XCTAssertFalse(FileManager.default.fileExists(atPath: store.url(for: "Default").path))
        XCTAssertEqual(try Data(contentsOf: store.url(for: "Work")), original)
        XCTAssertEqual(store.activeName, "Work")
        XCTAssertEqual(try makeStore().activeName, "Work")
        try store.rename("Work", to: "Work")
        XCTAssertEqual(store.activeName, "Work")
    }

    func testRenameInactiveAndDeleteDoNotChangeActiveProfile() throws {
        let store = try makeStore()
        try store.create(name: "Work", contents: "work")
        try store.rename("Work", to: "Home")
        XCTAssertEqual(try String(contentsOf: store.url(for: "Home"), encoding: .utf8), "work")
        XCTAssertEqual(store.activeName, "Default")
        try store.delete("Home")
        XCTAssertEqual(try store.names(), ["Default"])
        XCTAssertThrowsError(try store.delete("Default"))
        XCTAssertThrowsError(try store.delete("missing"))
        XCTAssertTrue(FileManager.default.fileExists(atPath: store.url(for: "Default").path))
    }

    func testCanDeleteFormerActiveProfileAfterSwitching() throws {
        let store = try makeStore()
        try store.create(name: "Work", contents: "work")
        try store.activate("Work")
        try store.delete("Default")
        XCTAssertEqual(try store.names(), ["Work"])
        XCTAssertEqual(try makeStore().activeName, "Work")
    }

    func testDuplicateNamesNeverOverwriteExistingFiles() throws {
        let store = try makeStore()
        try store.create(name: "Work", contents: "keep me")
        XCTAssertThrowsError(try store.create(name: "work", contents: "replacement"))
        XCTAssertThrowsError(try store.duplicate("Default", as: "WORK"))
        XCTAssertThrowsError(try store.rename("Default", to: "Work"))
        XCTAssertEqual(try String(contentsOf: store.url(for: "Work"), encoding: .utf8), "keep me")
        XCTAssertEqual(store.activeName, "Default")
    }

    func testNameValidationRejectsUnsafeAndAmbiguousNames() throws {
        let store = try makeStore()
        let invalid = ["", " ", " Work", "Work ", ".", "..", ".hidden", "Work.", "../escape",
                       "folder/name", "folder\\name", "a:b", "a\nb", "a\u{0}b", "a\tb", "a?b",
                       "a*b", "a|b", "a\"b", "<name>", "Work.conf", "Work.CONF", String(repeating: "a", count: 241)]
        for name in invalid {
            XCTAssertThrowsError(try ProfileStore.validateName(name), name)
            XCTAssertThrowsError(try store.create(name: name, contents: "bad"), name)
            XCTAssertThrowsError(try store.rename("Default", to: name), name)
            XCTAssertThrowsError(try store.duplicate("Default", as: name), name)
        }
        for name in ["Work", "工作", "Home 2", "Office-v2", "v1.2", String(repeating: "a", count: 240)] {
            XCTAssertNoThrow(try ProfileStore.validateName(name), name)
        }
        XCTAssertEqual(try store.names(), ["Default"])
        XCTAssertFalse(FileManager.default.fileExists(atPath: directory.appendingPathComponent("escape.conf").path))
    }

    func testListingIgnoresNonConfigsDirectoriesAndSymlinks() throws {
        let store = try makeStore()
        try "notes".write(to: store.baseDirectory.appendingPathComponent("notes.txt"), atomically: true, encoding: .utf8)
        try FileManager.default.createDirectory(at: store.url(for: "Folder"), withIntermediateDirectories: false)
        try FileManager.default.createSymbolicLink(at: store.url(for: "Link"), withDestinationURL: source)
        XCTAssertEqual(try store.names(), ["Default"])
        XCTAssertThrowsError(try store.activate("Link"))
        XCTAssertThrowsError(try store.create(name: "Link", contents: "overwrite"))
        XCTAssertThrowsError(try store.delete("../original"))
        XCTAssertTrue(FileManager.default.fileExists(atPath: source.path))
    }

    func testMissingSavedSelectionFallsBackToExistingProfile() throws {
        let store = try makeStore()
        try store.create(name: "Work", contents: "work")
        try store.activate("Work")
        try FileManager.default.removeItem(at: store.url(for: "Work"))
        XCTAssertEqual(try makeStore().activeName, "Default")
        XCTAssertEqual(defaults.string(forKey: ProfileStore.activeNameKey), "Default")
    }

    func testExistingProfilesDoNotRequireLegacyFile() throws {
        let store = try makeStore()
        try FileManager.default.removeItem(at: source)
        XCTAssertEqual(try makeStore().activeName, store.activeName)
    }
}
