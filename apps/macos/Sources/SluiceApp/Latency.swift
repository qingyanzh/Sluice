/// The control API uses nil for untested nodes and negative values for failed checks.
enum LatencyClassification: Equatable {
    case untested, good, ok, slow, timeout

    init(milliseconds: Int?) {
        switch milliseconds {
        case nil: self = .untested
        case .some(..<0): self = .timeout
        case .some(0..<200): self = .good
        case .some(200..<500): self = .ok
        default: self = .slow
        }
    }
}

func latencyText(_ milliseconds: Int?) -> String {
    guard let milliseconds else { return "未测试" }
    return milliseconds < 0 ? "超时" : "\(milliseconds) ms"
}
