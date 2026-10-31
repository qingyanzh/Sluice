import Foundation

/// Retains the kqueue process source and handles exit before registration as well.
final class ProcessWatch {
    private let source: DispatchSourceProcess

    init?(pid: Int32, queue: DispatchQueue, onExit: @escaping () -> Void) {
        guard pid > 0 else { return nil }
        source = DispatchSource.makeProcessSource(identifier: pid, eventMask: .exit, queue: queue)
        source.setEventHandler(handler: onExit)
        source.resume()
        if kill(pid, 0) != 0 && errno == ESRCH { queue.async(execute: onExit) }
    }

    func cancel() { source.cancel() }
    deinit { source.cancel() }
}
