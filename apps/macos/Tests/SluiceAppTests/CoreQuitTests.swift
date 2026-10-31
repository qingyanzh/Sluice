import XCTest
@testable import SluiceApp

final class CoreQuitTests: XCTestCase {
    func testExitWaitDoesNotTreatShutdownRequestAsExit() async throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sleep")
        process.arguments = ["0.4"]
        try process.run()
        defer { if process.isRunning { process.terminate() }; process.waitUntilExit() }
        do {
            try await Core.waitForExit(pid: process.processIdentifier, timeout: .milliseconds(50))
            XCTFail("A live core must prevent a restart")
        } catch {
            XCTAssertTrue(process.isRunning)
        }
        try await Core.waitForExit(pid: process.processIdentifier, timeout: .seconds(3))
        XCTAssertFalse(process.isRunning)
    }

    func testExitWaitRejectsInvalidPID() async {
        for pid in [Int32(0), -1] {
            do {
                try await Core.waitForExit(pid: pid)
                XCTFail("Invalid PIDs must never probe a process group")
            } catch {
                XCTAssertEqual((error as? APIError)?.message, "invalid core PID: \(pid)")
            }
        }
    }

    /// `stopForQuit` blocks the main thread on a semaphore while a detached task runs
    /// `stopRoot`; if that needed the main actor it would hang until the timeout.
    func testStopRootRunsWhileMainThreadIsBlocked() {
        XCTAssertTrue(Thread.isMainThread)
        let sema = DispatchSemaphore(value: 0)
        Task.detached {
            // Invalid PIDs are rejected before contacting any installed helper.
            try? await Core.stopRoot(pid: 0, viaHelper: true)
            sema.signal()
        }
        XCTAssertEqual(sema.wait(timeout: .now() + 20), .success)
    }

    func testInvalidRootPIDsAreRejectedForBothStopPaths() async {
        for pid in [Int32(0), -1] {
            for viaHelper in [false, true] {
                do {
                    try await Core.stopRoot(pid: pid, viaHelper: viaHelper)
                    XCTFail("An invalid PID must never reach a stop operation")
                } catch {
                    XCTAssertEqual((error as? APIError)?.message, "invalid core PID: \(pid)")
                }
            }
        }
    }
}
