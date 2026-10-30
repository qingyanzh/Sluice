import XCTest
@testable import SluiceApp

final class CoreProfileTests: XCTestCase {
    private var directory: URL!
    private var source: URL!
    private var defaults: UserDefaults!
    private var suite: String!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        source = directory.appendingPathComponent("legacy.conf")
        try "[General]\napi-listen = 127.0.0.1:6170\n".write(to: source, atomically: true, encoding: .utf8)
        suite = "CoreProfileTests.\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: suite)!
        defaults.set(source.path, forKey: "configPath")
    }

    override func tearDownWithError() throws {
        defaults.removePersistentDomain(forName: suite)
        try FileManager.default.removeItem(at: directory)
    }

    @MainActor
    private func makeCore() -> Core {
        Core(defaults: defaults, profilesDirectory: directory.appendingPathComponent("profiles"))
    }

    @MainActor
    func testMigrationSwitchAndRelaunchUseSelectedFileAndSummary() throws {
        let core = makeCore()
        XCTAssertNil(core.lastActionError)
        XCTAssertEqual(core.activeProfileName, "Default")
        XCTAssertEqual(core.profileNames, ["Default"])
        XCTAssertEqual(URL(fileURLWithPath: core.configPath).deletingLastPathComponent().lastPathComponent, "profiles")
        XCTAssertTrue(FileManager.default.fileExists(atPath: source.path))

        let work = "[General]\napi-listen = 127.0.0.1:6180\nhttp-listen = 127.0.0.1:6182\n"
        try core.createProfile(name: "Work", contents: work)
        try core.switchProfile(to: "Work")
        XCTAssertEqual(core.activeProfileName, "Work")
        XCTAssertEqual(core.readConfig(), work)
        XCTAssertEqual(core.summary.apiPort, 6180)
        XCTAssertEqual(core.summary.httpListen, "127.0.0.1:6182")
        XCTAssertEqual(core.state, .stopped)
        XCTAssertEqual(defaults.string(forKey: "configPath"), core.configPath)
        XCTAssertEqual(defaults.string(forKey: ProfileStore.activeNameKey), "Work")

        let reopened = makeCore()
        XCTAssertEqual(reopened.configPath, core.configPath)
        XCTAssertEqual(reopened.activeProfileName, "Work")
        XCTAssertEqual(reopened.readConfig(), work)
    }

    @MainActor
    func testRenameActiveUpdatesCorePathAndDeleteProtection() throws {
        let core = makeCore()
        let original = core.readConfig()
        let oldPath = core.configPath
        try core.renameProfile("Default", to: "Home")
        XCTAssertEqual(core.activeProfileName, "Home")
        XCTAssertEqual(URL(fileURLWithPath: core.configPath).lastPathComponent, "Home.conf")
        XCTAssertFalse(FileManager.default.fileExists(atPath: oldPath))
        XCTAssertEqual(core.readConfig(), original)
        XCTAssertEqual(core.profileNames, ["Home"])
        XCTAssertEqual(makeCore().activeProfileName, "Home")
        XCTAssertThrowsError(try core.deleteProfile("Home"))

        try core.duplicateProfile("Home", as: "Copy")
        try core.switchProfile(to: "Copy")
        try core.deleteProfile("Home")
        XCTAssertEqual(core.profileNames, ["Copy"])
        XCTAssertEqual(core.readConfig(), original)
    }

    @MainActor
    func testFailedSwitchLeavesCorePathAndSelectionUnchanged() throws {
        let core = makeCore()
        let path = core.configPath
        XCTAssertThrowsError(try core.switchProfile(to: "missing"))
        XCTAssertEqual(core.configPath, path)
        XCTAssertEqual(core.activeProfileName, "Default")
        XCTAssertEqual(core.summary.apiPort, 6170)
        XCTAssertEqual(defaults.string(forKey: ProfileStore.activeNameKey), "Default")
    }
}
