import Foundation

/// Turns raw core, network and system errors into a sentence a user can act on.
/// The raw text stays available as detail; it is never the headline.
struct FriendlyError: Equatable {
    let headline: String
    var hint: String?
    var detail: String?

    static func explain(_ raw: String) -> FriendlyError {
        let lines = raw.split(separator: "\n", maxSplits: 1).map(String.init)
        let first = lines.first ?? raw
        let rest = lines.count > 1 ? lines[1] : nil
        // Messages the app already wrote for people pass through unchanged.
        if isReadable(first) {
            return FriendlyError(headline: first, hint: rest.map(explain)?.hint, detail: rest)
        }
        let text = raw.lowercased()
        for (patterns, headline, hint) in rules where patterns.contains(where: { text.contains($0) }) {
            return FriendlyError(headline: headline, hint: hint, detail: raw)
        }
        if let line = Core.errorLine(in: raw) {
            return FriendlyError(headline: "配置第 \(line) 行有误", hint: "在「配置 · 文本」中检查该行的拼写和格式", detail: raw)
        }
        return FriendlyError(headline: "操作没有完成", hint: "可展开详细信息查看原因，或在「日志」页查看内核输出", detail: raw)
    }

    /// The hint for a raw reason, used under an app-written headline.
    private static func explain(_ raw: String) -> FriendlyError? {
        let text = raw.lowercased()
        return rules.first { $0.0.contains(where: { text.contains($0) }) }.map { FriendlyError(headline: $0.1, hint: $0.2) }
    }

    /// Chinese text without obvious machine tokens reads as already written for people.
    private static func isReadable(_ line: String) -> Bool {
        let hasChinese = line.unicodeScalars.contains { (0x4E00...0x9FFF).contains($0.value) }
        let machine = ["error", "failed", "http ", "os error", "errno", "0x", "::", "{", "panicked"]
        return hasChinese && !machine.contains { line.lowercased().contains($0) }
    }

    private static let rules: [([String], String, String)] = [
        (["http 401", "http 403", "status 401", "status 403", "forbidden"], "订阅服务器拒绝了访问", "订阅链接可能已过期或被重置，请在服务商处重新复制订阅地址"),
        (["http 404", "status 404", "not found"], "订阅地址不存在", "请确认订阅地址完整无误"),
        (["http 429", "too many requests"], "请求过于频繁", "稍等几分钟后再更新"),
        (["http 5", "status 5", "bad gateway", "service unavailable"], "订阅服务器暂时不可用", "稍后再试；已下载的节点仍可继续使用"),
        (["timed out", "timeout", "deadline"], "连接超时", "检查网络是否可用；如订阅需要代理才能访问，可先启动 Sluice 再更新"),
        (["certificate", "tls", "ssl", "handshake"], "安全连接失败", "服务器证书无效或网络被拦截，请确认地址正确或更换网络"),
        (["dns", "lookup", "resolve", "nodename nor servname"], "无法解析服务器地址", "检查网络连接，或确认域名拼写正确"),
        (["connection refused", "connect error", "network is unreachable", "no route"], "无法连接到服务器", "检查网络连接，或稍后再试"),
        (["address already in use", "addrinuse"], "端口已被其他程序占用", "在「设置」中更换监听端口，或退出占用端口的程序"),
        (["permission denied", "operation not permitted"], "没有足够的权限", "增强模式需要管理员授权，请在「设置」中重新授权"),
        (["unknown subscription"], "策略组引用了不存在的订阅", "在「策略」页编辑该组，移除已删除的订阅"),
        (["unknown policy", "unknown proxy", "refers to", "no such group"], "引用了不存在的节点或策略组", "在「策略」或「规则」页把它替换为现有的策略组"),
        (["regex", "regular expression"], "过滤规则不是有效的正则表达式", "例如：香港|HK|日本"),
        (["no such file", "not exist"], "找不到文件", "文件可能已被移动或删除"),
        (["restart required", "listen or enhanced-mode"], "需要重启内核才能生效", "修改了监听端口或增强模式，请点击「重启内核」"),
        (["no proxies", "no nodes", "empty"], "没有可用节点", "订阅内容为空，或节点过滤条件过严"),
    ]
}
