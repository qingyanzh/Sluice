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

    func testOnlyListenerAndEnhancedModeChangesRequireRestart() {
        let base = "[General]\napi-listen = 127.0.0.1:6170\nhttp-listen = 127.0.0.1:6252\nsocks5-listen = 127.0.0.1:6253\nenhanced-mode = false\n"
        let running = ConfigSummary(text: base)
        XCTAssertFalse(ConfigSummary(text: base + "[Proxy]\nHK = direct\n[Rule]\nFINAL,HK\n").requiresRestart(comparedTo: running))
        for change in [
            base.replacingOccurrences(of: "127.0.0.1:6170", with: "127.0.0.2:6170"),
            base.replacingOccurrences(of: "127.0.0.1:6252", with: "127.0.0.1:6154"),
            base.replacingOccurrences(of: "socks5-listen = 127.0.0.1:6253\n", with: ""),
            base.replacingOccurrences(of: "enhanced-mode = false", with: "enhanced-mode = true")
        ] {
            XCTAssertTrue(ConfigSummary(text: change).requiresRestart(comparedTo: running))
        }
    }

    @MainActor
    private func makeCore() -> Core {
        Core(defaults: defaults, profilesDirectory: directory.appendingPathComponent("profiles"))
    }

    @MainActor
    func testMigrationSwitchAndRelaunchUseSelectedFileAndSummary() async throws {
        let core = makeCore()
        XCTAssertNil(core.lastActionError)
        XCTAssertEqual(core.activeProfileName, "Default")
        XCTAssertEqual(core.profileNames, ["Default"])
        XCTAssertEqual(URL(fileURLWithPath: core.configPath).deletingLastPathComponent().lastPathComponent, "profiles")
        XCTAssertTrue(FileManager.default.fileExists(atPath: source.path))

        let work = "[General]\napi-listen = 127.0.0.1:6180\nhttp-listen = 127.0.0.1:6182\n"
        try core.createProfile(name: "Work", contents: work)
        try await core.switchProfile(to: "Work")
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
    func testRenameActiveUpdatesCorePathAndDeleteProtection() async throws {
        let core = makeCore()
        let original = core.readConfig()
        let oldPath = core.configPath
        try await core.renameProfile("Default", to: "Home")
        XCTAssertEqual(core.activeProfileName, "Home")
        XCTAssertEqual(URL(fileURLWithPath: core.configPath).lastPathComponent, "Home.conf")
        XCTAssertFalse(FileManager.default.fileExists(atPath: oldPath))
        XCTAssertEqual(core.readConfig(), original)
        XCTAssertEqual(core.profileNames, ["Home"])
        XCTAssertEqual(makeCore().activeProfileName, "Home")
        XCTAssertThrowsError(try core.deleteProfile("Home"))

        try core.duplicateProfile("Home", as: "Copy")
        try await core.switchProfile(to: "Copy")
        try core.deleteProfile("Home")
        XCTAssertEqual(core.profileNames, ["Copy"])
        XCTAssertEqual(core.readConfig(), original)
    }

    @MainActor
    func testFailedSwitchLeavesCorePathAndSelectionUnchanged() async throws {
        let core = makeCore()
        let path = core.configPath
        do {
            try await core.switchProfile(to: "missing")
            XCTFail("Missing profile must fail")
        } catch {}
        XCTAssertEqual(core.configPath, path)
        XCTAssertEqual(core.activeProfileName, "Default")
        XCTAssertEqual(core.summary.apiPort, 6170)
        XCTAssertEqual(defaults.string(forKey: ProfileStore.activeNameKey), "Default")
    }
}

extension CoreProfileTests {
    @MainActor
    func testCopyDraftSwitchWritesTargetAndPreservesSourceOnDiskAndRelaunch() async throws {
        let core = makeCore()
        let sourcePath = core.configPath
        let original = core.readConfig()
        try core.createProfile(name: "Work", contents: "[Rule]\nFINAL,REJECT\n")
        let draft = original + "[Rule]\nDOMAIN,edited.example,DIRECT\nFINAL,DIRECT\n"
        try await core.copyDraftAndSwitch(to: "Work", text: draft, check: { _ in nil })
        XCTAssertEqual(core.activeProfileName, "Work")
        XCTAssertEqual(core.readConfig(), draft)
        XCTAssertEqual(try String(contentsOfFile: sourcePath, encoding: .utf8), original)
        XCTAssertEqual(makeCore().readConfig(), draft)
    }

    @MainActor
    func testInvalidDraftDoesNotOverwriteEitherProfileOrChangeSelection() async throws {
        let core = makeCore()
        let sourcePath = core.configPath
        let original = core.readConfig()
        let target = "[Rule]\nFINAL,REJECT\n"
        try core.createProfile(name: "Work", contents: target)
        do {
            try await core.copyDraftAndSwitch(to: "Work", text: "invalid", check: { _ in "line 1: invalid rule" })
            XCTFail("Invalid draft must fail")
        } catch { XCTAssertEqual(error.localizedDescription, "line 1: invalid rule") }
        XCTAssertEqual(core.configPath, sourcePath)
        XCTAssertEqual(core.readConfig(), original)
        XCTAssertEqual(try String(contentsOf: directory.appendingPathComponent("profiles/Work.conf"), encoding: .utf8), target)
    }

    @MainActor
    func testStartupValidationFailureShowsBannerAndAppLogWithoutLaunching() async {
        let core = makeCore()
        await core.startValidated { _, path in
            XCTAssertEqual(path, core.configPath)
            XCTAssertTrue(core.validatingStart)
            return "error: line 7: unknown policy Missing"
        }
        XCTAssertFalse(core.isActive)
        XCTAssertFalse(core.validatingStart)
        XCTAssertEqual(core.lastActionError, "启动失败：error: line 7: unknown policy Missing")
        XCTAssertEqual(core.logs.last?.level, "ERROR")
        XCTAssertEqual(core.logs.last?.message, core.lastActionError)
    }

    @MainActor
    func testProxySwitchIsOptimisticPreventsOverlapAndRollsBackFailure() async {
        try? "[General]\nhttp-listen = 127.0.0.1:6252\n".write(to: source, atomically: true, encoding: .utf8)
        let core = makeCore()
        await core.applySystemProxy(true, readStatus: { _, _, _ in .init(isSluice: true) }) { on, _, _ in
            XCTAssertTrue(on)
            XCTAssertTrue(core.systemProxyOn)
            XCTAssertTrue(core.settingSystemProxy)
            await core.applySystemProxy(false) { _, _, _ in XCTFail("Must not overlap") }
        }
        XCTAssertTrue(core.systemProxyOn)
        await core.applySystemProxy(false) { on, _, _ in
            XCTAssertFalse(on)
            XCTAssertFalse(core.systemProxyOn, "Banner reacts before networksetup completes")
            XCTAssertTrue(core.settingSystemProxy)
            throw APIError(message: "permission denied")
        }
        XCTAssertTrue(core.systemProxyOn)
        XCTAssertFalse(core.settingSystemProxy)
        XCTAssertEqual(core.lastActionError, "设置系统代理失败：permission denied")
    }
}
