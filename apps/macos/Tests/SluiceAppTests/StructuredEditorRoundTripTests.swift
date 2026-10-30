import XCTest
@testable import SluiceApp

/// Uses the same Rule/Group mutations and persistent text draft as the structured UI.
final class StructuredEditorRoundTripTests: XCTestCase {
    private let ruleLine = "DOMAIN,e2e-editor.test,DIRECT"
    private let groupLine = "E2E-Group = select, DIRECT"
    private var repository: URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
    }

    @MainActor
    private func editAndSave(_ file: URL) throws {
        let original = try String(contentsOf: file, encoding: .utf8)
        let draft = ConfigDraft()
        draft.refresh(path: file.path, disk: original)
        let before = StructuredConfig(draft.text)
        XCTAssertFalse(before.policies.contains("E2E-Group"), "Fixture already contains the editor group")
        XCTAssertFalse(before.rules.contains { $0.value.value == "e2e-editor.test" })

        // Fill the fields as the sheets do, then commit each edit to the shared draft.
        var rule = StructuredConfig.Rule()
        rule.type = "DOMAIN"
        rule.value = " e2e-editor.test "
        rule.policy = " DIRECT "
        rule.normalise()
        var document = StructuredConfig(draft.text)
        document.setRule(rule)
        draft.text = document.serialise()

        var group = StructuredConfig.Group()
        group.name = "E2E-Group"
        group.members.append("DIRECT")
        document = StructuredConfig(draft.text)
        document.setGroup(group)
        draft.text = document.serialise()
        XCTAssertTrue(draft.hasChanges)
        // Navigating back to the editor must retain both pending changes.
        draft.refresh(path: file.path, disk: original)
        XCTAssertEqual(draft.saved, original)
        XCTAssertFalse(draft.changedOnDisk)
        try draft.text.write(to: file, atomically: true, encoding: .utf8)
        let saved = try String(contentsOf: file, encoding: .utf8)
        XCTAssertEqual(saved, draft.text)
        // ConfigView acknowledges the submitted version after saveConfig succeeds.
        draft.saved = saved
        draft.refresh(path: file.path, disk: saved)
        XCTAssertFalse(draft.hasChanges)

        let after = StructuredConfig(saved)
        XCTAssertEqual(after.rules.map(\.value).filter { $0 != rule }, before.rules.map(\.value))
        XCTAssertEqual(after.groups.map(\.value).filter { $0 != group }, before.groups.map(\.value))
        XCTAssertEqual(after.rules.filter { $0.value == rule }.count, 1)
        XCTAssertEqual(after.groups.filter { $0.value == group }.count, 1)
        if let final = after.rules.firstIndex(where: { $0.value.isFinal }),
           let added = after.rules.firstIndex(where: { $0.value == rule }) {
            XCTAssertLessThan(added, final, "New rule must be reachable before FINAL")
        }
        XCTAssertTrue(after.policies.contains(group.name))
        XCTAssertEqual(after.serialise(), saved)
    }

    @MainActor
    private func withSavedSample(_ check: (URL) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("sample.conf")
        // No subscriptions, remote rule sets or automatic groups: `check` stays offline.
        let original = "# 配置 — preserve spacing and line endings\r\n[General]\r\nloglevel = info\r\n[Proxy]\r\nLocal = ss, 127.0.0.1, 18388, encrypt-method=aes-256-gcm, password=sample\r\n[Proxy Group]\r\n  Existing = select, Local, DIRECT\r\n; group comment\n[Rule]\r\n\tDOMAIN,untouched.test,Existing\r\n# final comment\r\nFINAL,Existing\r\n[Host]\r\nkept.test = 127.0.0.1"
        try original.write(to: file, atomically: true, encoding: .utf8)
        try editAndSave(file)
        let expected = original
            .replacingOccurrences(of: "[Rule]", with: groupLine + "\r\n[Rule]")
            .replacingOccurrences(of: "FINAL,Existing", with: ruleLine + "\r\nFINAL,Existing")
        XCTAssertEqual(try Data(contentsOf: file), Data(expected.utf8),
                       "Only the two inserted lines may change; untouched bytes must survive saving")
        try check(file)
    }

    @MainActor
    func testRuleAndGroupSavePreservesUntouchedContent() throws {
        try withSavedSample { _ in }
    }

    @MainActor
    func testSavedOutputPassesCoreCheckWhenBinaryExists() throws {
        guard let binary = ["release", "debug"].map({
            repository.appendingPathComponent("target/\($0)/sluice")
        }).first(where: { FileManager.default.isExecutableFile(atPath: $0.path) }) else {
            throw XCTSkip("Build target/release/sluice or target/debug/sluice to validate saved output")
        }
        try withSavedSample { file in
            let process = Process()
            process.executableURL = binary
            process.arguments = ["check", file.path]
            try process.run()
            process.waitUntilExit()
            XCTAssertEqual(process.terminationReason, .exit)
            XCTAssertEqual(process.terminationStatus, 0, "sluice check must accept the editor's saved output")
        }
    }

    /// CI passes a disposable sibling copy of the active profile; this test does no networking.
    @MainActor
    func testEditCIProfile() throws {
        guard let path = ProcessInfo.processInfo.environment["SLUICE_E2E_CONFIG"], !path.isEmpty else {
            throw XCTSkip("Only the e2e editor hook supplies SLUICE_E2E_CONFIG")
        }
        try editAndSave(URL(fileURLWithPath: path))
        print("SLUICE_E2E_EDIT_SAVED")
    }
}
