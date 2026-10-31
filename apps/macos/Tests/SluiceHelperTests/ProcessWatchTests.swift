import Foundation
import XCTest
@testable import SluiceHelper

final class ProcessWatchTests: XCTestCase {
    func testExitAndAlreadyExitedPID() throws {
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/bin/sleep")
        child.arguments = ["30"]
        try child.run()
        let exited = expectation(description: "exit event")
        exited.assertForOverFulfill = false
        let queue = DispatchQueue(label: "watch-test")
        let watch = ProcessWatch(pid: child.processIdentifier, queue: queue) { exited.fulfill() }
        child.terminate()
        wait(for: [exited], timeout: 3)
        child.waitUntilExit()
        watch?.cancel()
        let gone = expectation(description: "already exited")
        gone.assertForOverFulfill = false
        let lateWatch = ProcessWatch(pid: child.processIdentifier, queue: queue) { gone.fulfill() }
        wait(for: [gone], timeout: 3)
        lateWatch?.cancel()
        XCTAssertNil(ProcessWatch(pid: 0, queue: queue) {})
    }
}
