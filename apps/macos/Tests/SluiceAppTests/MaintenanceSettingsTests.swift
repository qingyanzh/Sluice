import ServiceManagement
import XCTest
@testable import SluiceApp

final class MaintenanceSettingsTests: XCTestCase {
    func testHelperMapsRegistrationAndApprovalToActionableStates() {
        let unregistered = HelperStatus.resolve(bundled: true, status: .notRegistered)
        XCTAssertEqual(unregistered, .notInstalled)
        XCTAssertEqual(unregistered.title, "未安装")
        XCTAssertEqual(unregistered.action, "安装辅助程序")

        let approval = HelperStatus.resolve(bundled: true, status: .requiresApproval)
        XCTAssertEqual(approval, .needsApproval)
        XCTAssertEqual(approval.title, "待批准")
        XCTAssertEqual(approval.action, "打开系统设置")
        XCTAssertTrue(approval.detail.contains("登录项与扩展"))

        let ready = HelperStatus.resolve(bundled: true, status: .enabled)
        XCTAssertEqual(ready, .ready)
        XCTAssertEqual(ready.title, "已就绪")
    }

    func testHelperErrorsDoNotHideApprovalOrSuccessfulExternalRecovery() {
        let error = "注册失败"
        let failed = HelperStatus.resolve(bundled: true, status: .notRegistered, error: error)
        XCTAssertEqual(failed, .failed(error))
        XCTAssertEqual(failed.title, "错误")
        XCTAssertEqual(failed.action, "重试")
        XCTAssertEqual(failed.detail, error)
        XCTAssertEqual(HelperStatus.resolve(bundled: true, status: .enabled, error: error), .ready)
        XCTAssertEqual(HelperStatus.resolve(bundled: true, status: .requiresApproval, error: error), .needsApproval)
        XCTAssertEqual(HelperStatus.resolve(bundled: true, status: .notFound), .notInstalled)
        XCTAssertEqual(HelperStatus.resolve(bundled: true, status: .notFound, error: error), .failed(error))
        if case .failed(let message) = HelperStatus.resolve(bundled: false, status: .enabled) {
            XCTAssertTrue(message.contains("Sluice.app"))
        } else { XCTFail("An unbundled app cannot advertise a ready helper") }
    }

    func testHelperLookupValidatesBothPlistAndExecutable() throws {
        let bundle = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".app")
        defer { try? FileManager.default.removeItem(at: bundle) }
        let plist = bundle.appendingPathComponent("Contents/Library/LaunchDaemons/dev.sluice.Sluice.helper.plist")
        let binary = bundle.appendingPathComponent("Contents/MacOS/SluiceHelper")
        try FileManager.default.createDirectory(at: plist.deletingLastPathComponent(), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: binary.deletingLastPathComponent(), withIntermediateDirectories: true)
        let info = ["Label": "dev.sluice.Sluice.helper", "BundleProgram": "Contents/MacOS/SluiceHelper"]
        try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0).write(to: plist)
        XCTAssertFalse(HelperClient.bundled(in: bundle), "A plist alone does not constitute a packaged helper")
        try Data("helper".utf8).write(to: binary)
        XCTAssertFalse(HelperClient.bundled(in: bundle), "The daemon must be executable")
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: binary.path)
        XCTAssertTrue(HelperClient.bundled(in: bundle))
    }

    func testUpdateInfoUsesFeedRatherThanInstalledVersionForChannel() {
        let official = URL(string: "https://github.com/qingyanzh/Sluice/releases/latest/download/appcast.xml")!
        let info = ["CFBundleShortVersionString": "1.0-beta1", "CFBundleVersion": "42"]
        XCTAssertEqual(UpdateInfo(info: info, feedURL: official).version, "1.0-beta1 (42)")
        XCTAssertEqual(UpdateInfo(info: info, feedURL: official).channel, "稳定版")
        XCTAssertEqual(UpdateInfo(info: info, feedURL: URL(string: "https://updates.example.com/beta.xml")).channel, "自定义")
        XCTAssertEqual(UpdateInfo(info: info, feedURL: URL(string: "https://github.com/other/project/releases/latest/download/appcast.xml")).channel, "自定义")
        XCTAssertEqual(UpdateInfo(info: [:], feedURL: nil).channel, "未配置")
        XCTAssertEqual(UpdateInfo(info: [:], feedURL: nil).version, "开发版本")
        XCTAssertEqual(UpdateInfo(info: ["CFBundleShortVersionString": "1.0"], feedURL: official).version, "1.0")
    }

    @MainActor
    func testDiagnosticsReportsFailureAndCanRetryToAFile() async {
        let file = URL(fileURLWithPath: "/tmp/diagnostics.zip")
        var attempts = 0
        let exporter = DiagnosticsExporter { _, _, _, _ in
            attempts += 1
            if attempts == 1 { throw APIError(message: "磁盘空间不足") }
            return file
        }
        XCTAssertEqual(exporter.state, .idle)
        await exporter.export(api: nil, binary: nil, configPath: "")
        XCTAssertEqual(exporter.state, .failed("磁盘空间不足"))
        await exporter.export(api: nil, binary: nil, configPath: "")
        XCTAssertEqual(exporter.state, .exported(file))
    }

    @MainActor
    func testDiagnosticsShowsProgressAndPreventsOverlappingMenuAndSettingsExports() async {
        let started = expectation(description: "Export started")
        var continuation: CheckedContinuation<URL, Error>?
        var calls = 0
        let exporter = DiagnosticsExporter { _, _, _, _ in
            calls += 1
            return try await withCheckedThrowingContinuation {
                continuation = $0
                started.fulfill()
            }
        }
        let task = Task { await exporter.export(api: nil, binary: nil, configPath: "") }
        await fulfillment(of: [started], timeout: 2)
        XCTAssertEqual(exporter.state, .exporting)
        XCTAssertTrue(exporter.state.isExporting)
        await exporter.export(api: nil, binary: nil, configPath: "")
        XCTAssertEqual(calls, 1)
        let file = URL(fileURLWithPath: "/tmp/diagnostics.zip")
        continuation?.resume(returning: file)
        await task.value
        XCTAssertEqual(exporter.state, .exported(file))
        XCTAssertFalse(exporter.state.isExporting)
    }
}
