import XCTest
@testable import SluiceApp

final class CoreQuitTests: XCTestCase {
    /// `stopForQuit` blocks the main thread on a semaphore while a detached task runs
    /// `stopRoot`; if that needed the main actor it would hang until the timeout.
    func testStopRootRunsWhileMainThreadIsBlocked() {
        XCTAssertTrue(Thread.isMainThread)
        let sema = DispatchSemaphore(value: 0)
        Task.detached {
            // No helper is registered here, so the XPC call fails quickly.
            try? await Core.stopRoot(pid: 0, viaHelper: true)
            sema.signal()
        }
        XCTAssertEqual(sema.wait(timeout: .now() + 20), .success)
    }
}
