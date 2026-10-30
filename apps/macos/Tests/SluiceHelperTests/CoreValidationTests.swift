import Darwin
import Foundation
import Security
import XCTest
@testable import SluiceHelper

final class CoreValidationTests: XCTestCase {
    private var work: URL!

    override func setUpWithError() throws {
        // Keep all ancestors non-writable by other users (the system temp dir isn't).
        work = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent(".build/helper-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
    }

    override func tearDownWithError() throws {
        try FileManager.default.removeItem(at: work)
    }

    private func run(_ executable: String, _ args: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = args
        try process.run()
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0)
    }

    private func fixture() throws -> (URL, Set<String>) {
        let source = work.appendingPathComponent("core.c")
        let core = work.appendingPathComponent("core")
        try Data("int main(void) { return 0; }\n".utf8).write(to: source)
        try run("/usr/bin/clang", [source.path, "-o", core.path])
        try run("/usr/bin/codesign", ["-f", "-s", "-", "--identifier", "dev.sluice.core", core.path])
        var code: SecStaticCode?
        XCTAssertEqual(SecStaticCodeCreateWithPath(core as CFURL, [], &code), errSecSuccess)
        var info: CFDictionary?
        XCTAssertEqual(SecCodeCopySigningInformation(try XCTUnwrap(code), [], &info), errSecSuccess)
        let dict = try XCTUnwrap(info as? [String: Any])
        let hash = try XCTUnwrap(dict[kSecCodeInfoUnique as String] as? Data)
        return (core, [hash.map { String(format: "%02x", $0) }.joined()])
    }

    func testAdHocHashAndEmptySlotRejections() throws {
        let (core, hashes) = try fixture()
        XCTAssertNoThrow(try validateCore(at: core, teamID: nil, expectedHashes: hashes))
        XCTAssertThrowsError(try validateCore(at: core, teamID: nil, expectedHashes: [])) {
            XCTAssertTrue($0.localizedDescription.contains("no core cdhashes embedded"))
        }
        XCTAssertThrowsError(try validateCore(at: core, teamID: nil, expectedHashes: [String(repeating: "0", count: 40)])) {
            XCTAssertTrue($0.localizedDescription.contains("cdhash does not match"))
        }
        XCTAssertThrowsError(try validateCore(at: core, teamID: "UNTRUSTED", expectedHashes: hashes))
    }

    func testCopyRemainsTrustedAfterSourceReplacement() throws {
        let (core, hashes) = try fixture()
        let stage = work.appendingPathComponent("stage")
        let copy = try stageCore(from: core.path, in: stage.path, teamID: nil, expectedHashes: hashes)
        XCTAssertNotEqual(copy.path, core.path)
        var st = stat()
        XCTAssertEqual(lstat(copy.path, &st), 0)
        XCTAssertEqual(st.st_uid, geteuid())
        XCTAssertEqual(st.st_mode & 0o777, 0o500)
        try FileManager.default.removeItem(at: core)
        try FileManager.default.copyItem(atPath: "/usr/bin/true", toPath: core.path)
        XCTAssertNoThrow(try validateCore(at: copy, teamID: nil, expectedHashes: hashes))
        XCTAssertThrowsError(try stageCore(from: core.path, in: stage.path, teamID: nil, expectedHashes: hashes))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: stage.path).count, 1,
                       "rejected copies must be removed")
    }

    func testTamperedSignatureIsRejected() throws {
        let (core, hashes) = try fixture()
        var bytes = try Data(contentsOf: core)
        // Alter an executable page without changing the Mach-O header or signature blob.
        bytes[1024] ^= 1
        try bytes.write(to: core, options: .atomic)
        XCTAssertThrowsError(try validateCore(at: core, teamID: nil, expectedHashes: hashes)) {
            XCTAssertTrue($0.localizedDescription.contains("signature validation failed"))
        }
    }

    func testUnsafeStagingDirectoriesAreRejected() throws {
        let directory = work.appendingPathComponent("stage")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        for mode: mode_t in [0o775, 0o757] {
            XCTAssertEqual(chmod(directory.path, mode), 0)
            XCTAssertThrowsError(try prepareStageDirectory(directory.path))
        }
        XCTAssertEqual(chmod(directory.path, 0o700), 0)
        XCTAssertNoThrow(try prepareStageDirectory(directory.path))
        let link = work.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: directory)
        XCTAssertThrowsError(try prepareStageDirectory(link.path))
        let file = work.appendingPathComponent("file")
        try Data().write(to: file)
        XCTAssertThrowsError(try prepareStageDirectory(file.path))
        if geteuid() != 0 {
            XCTAssertThrowsError(try prepareStageDirectory("/Library"), "staging must belong to the helper's effective user")
        }
        XCTAssertThrowsError(try prepareStageDirectory("relative/stage"))
        XCTAssertThrowsError(try prepareStageDirectory("/"))
    }
}
