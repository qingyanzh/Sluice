import Foundation

/// Quotes `s` for a POSIX shell.
func shellQuote(_ s: String) -> String {
    "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
}

/// Runs a command and returns (status, combined output).
func runTool(_ path: String, _ args: [String]) async -> (Int32, String) {
    await Task.detached(priority: .utility) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        do {
            try p.run()
            // Drain while the child is running; waiting for termination first can
            // deadlock once check/diagnostics output fills the pipe buffer.
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            return (p.terminationStatus, String(decoding: data, as: UTF8.self))
        } catch {
            return (Int32(-1), error.localizedDescription)
        }
    }.value
}

enum ConfigValidation {
    static func check(binary: URL?, path: String) async -> String? {
        guard let binary else { return "找不到 Sluice 内核，请重新安装应用。" }
        let (status, output) = await runTool(binary.path, ["check", path])
        guard status != 0 else { return nil }
        let detail = output.trimmingCharacters(in: .whitespacesAndNewlines)
        return detail.isEmpty ? "配置检查失败（退出码 \(status)）。" : detail
    }
}

enum Privileged {
    /// Runs a shell command as root behind the standard macOS administrator prompt.
    static func run(_ command: String) async throws -> String {
        let escaped = command.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        let script = "do shell script \"\(escaped)\" with administrator privileges"
        let (status, out) = await runTool("/usr/bin/osascript", ["-e", script])
        if status != 0 {
            if out.contains("-128") { throw APIError(message: "Cancelled") }
            throw APIError(message: out.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        return out
    }
}

enum SystemProxy {
    static let defaultHTTP = "127.0.0.1:6252"
    static let defaultSOCKS = "127.0.0.1:6253"

    struct Status: Equatable {
        var isSluice = false
        var otherAddresses: [String] = []
        var otherOwners: [String] = []

        var otherProxy: String? {
            otherAddresses.isEmpty ? nil : "其他代理 (\((otherOwners + otherAddresses).joined(separator: ", ")))"
        }
    }

    static func services() async -> [String] {
        let (_, out) = await runTool("/usr/sbin/networksetup", ["-listallnetworkservices"])
        return out.split(separator: "\n").dropFirst().map(String.init).filter { !$0.hasPrefix("*") && !$0.isEmpty }
    }

    static func status(http: String?, socks: String?, coreRunning: Bool) async -> Status {
        let (_, out) = await runTool("/usr/sbin/scutil", ["--proxy"])
        var listenerOutput: [Int: String] = [:]
        if !coreRunning {
            let ports = Set([split(http ?? defaultHTTP)?.1, split(socks ?? defaultSOCKS)?.1].compactMap { $0 })
            for port in ports { listenerOutput[port] = await ListenConflict.output(port: port) }
        }
        return parseStatus(out, http: http, socks: socks, coreRunning: coreRunning, listenerOutput: listenerOutput)
    }

    /// Every enabled proxy must match its corresponding listener, including the host.
    static func parseStatus(_ output: String, http: String?, socks: String?, coreRunning: Bool = true,
                            listenerOutput: [Int: String] = [:]) -> Status {
        var values: [String: String] = [:]
        for line in output.split(separator: "\n") {
            guard let colon = line.firstIndex(of: ":") else { continue }
            values[line[..<colon].trimmingCharacters(in: .whitespaces)] =
                line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
        }
        var enabled = 0
        var other: [String] = []
        var owners: [String] = []
        for (kind, listener) in [("HTTP", http ?? defaultHTTP), ("HTTPS", http ?? defaultHTTP), ("SOCKS", socks ?? defaultSOCKS)] {
            guard values["\(kind)Enable"] == "1" else { continue }
            enabled += 1
            let host = values["\(kind)Proxy"] ?? "?"
            let port = Int(values["\(kind)Port"] ?? "")
            if let expected = split(listener), host == expected.0, port == expected.1 {
                let foreign = coreRunning ? [] : ListenConflict.parseOwners(listenerOutput[expected.1] ?? "")
                    .filter { $0.process != "sluice" }
                if foreign.isEmpty { continue }
                for owner in foreign where !owners.contains(owner.process) { owners.append(owner.process) }
            }
            let address = "\(host.contains(":") ? "[\(host)]" : host):\(values["\(kind)Port"] ?? "?")"
            if !other.contains(address) { other.append(address) }
        }
        return Status(isSluice: enabled > 0 && other.isEmpty, otherAddresses: other, otherOwners: owners)
    }

    /// Points (or stops pointing) every network service's HTTP, HTTPS and SOCKS proxy at Sluice.
    static func set(enabled: Bool, http: (String, Int)?, socks: (String, Int)?) async throws {
        var cmds: [String] = []
        for s in await services() {
            let q = shellQuote(s)
            if enabled {
                if let (host, port) = http {
                    cmds.append("networksetup -setwebproxy \(q) \(host) \(port)")
                    cmds.append("networksetup -setsecurewebproxy \(q) \(host) \(port)")
                }
                if let (host, port) = socks {
                    cmds.append("networksetup -setsocksfirewallproxy \(q) \(host) \(port)")
                }
            } else {
                cmds.append("networksetup -setwebproxystate \(q) off")
                cmds.append("networksetup -setsecurewebproxystate \(q) off")
                cmds.append("networksetup -setsocksfirewallproxystate \(q) off")
            }
        }
        _ = try await Privileged.run(cmds.joined(separator: " && "))
    }

    /// `127.0.0.1:6252` -> ("127.0.0.1", 6252); a bare port means localhost.
    static func split(_ listen: String?) -> (String, Int)? {
        guard let listen = listen?.trimmingCharacters(in: .whitespaces) else { return nil }
        let colon = listen.lastIndex(of: ":")
        let portText = colon.map { String(listen[listen.index(after: $0)...]) } ?? listen
        guard let port = Int(portText), (1...65535).contains(port) else { return nil }
        let host = colon.map { String(listen[..<$0]) } ?? "127.0.0.1"
        let unbracketed = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        return (unbracketed == "0.0.0.0" ? "127.0.0.1" : unbracketed == "::" ? "::1" : unbracketed, port)
    }
}

enum ListenConflict {
    struct Owner: Equatable {
        let process: String
        let pid: Int

        func message(port: Int) -> String { "端口 \(port) 已被 \(process)(\(pid)) 占用" }
    }

    /// Parses the standard `lsof -nP -iTCP:<port> -sTCP:LISTEN` table.
    static func parseOwners(_ output: String) -> [Owner] {
        var owners: [Owner] = []
        for line in output.split(separator: "\n") {
            let fields = line.split(whereSeparator: \.isWhitespace)
            guard fields.count >= 3, let pid = Int(fields[1]), pid > 0,
                  fields.last == "(LISTEN)" else { continue }
            let owner = Owner(process: String(fields[0]), pid: pid)
            if !owners.contains(owner) { owners.append(owner) }
        }
        return owners
    }

    /// Rust includes a stable error kind and the exact failing listener in its message.
    static func port(in error: String) -> Int? {
        guard error.contains("AddrInUse"), let start = error.range(of: " on "),
              let end = error.range(of: ": AddrInUse", range: start.upperBound..<error.endIndex) else { return nil }
        return SystemProxy.split(String(error[start.upperBound..<end.lowerBound]))?.1
    }

    static func message(for error: String) async -> String? {
        guard let port = port(in: error) else { return nil }
        let messages = parseOwners(await output(port: port)).map { $0.message(port: port) }
        return messages.isEmpty ? nil : messages.joined(separator: "\n")
    }

    static func output(port: Int) async -> String {
        let (_, output) = await runTool("/usr/sbin/lsof", ["-nP", "-iTCP:\(port)", "-sTCP:LISTEN"])
        return output
    }
}

/// Line-level edits to a Surge-style config, kept as text so comments survive.
enum ConfigText {
    /// Appends `line` at the end of `[section]`, creating the section if needed.
    static func insert(_ line: String, into section: String, of text: String) -> String {
        var lines = text.components(separatedBy: "\n")
        guard let header = lines.firstIndex(where: { $0.trimmingCharacters(in: .whitespaces) == "[\(section)]" }) else {
            return text.trimmingCharacters(in: .newlines) + "\n\n[\(section)]\n\(line)\n"
        }
        var end = lines[(header + 1)...].firstIndex { $0.trimmingCharacters(in: .whitespaces).hasPrefix("[") } ?? lines.count
        while end > header + 1 && lines[end - 1].trimmingCharacters(in: .whitespaces).isEmpty { end -= 1 }
        lines.insert(line, at: end)
        return lines.joined(separator: "\n")
    }

    /// Sets `key = value` in [General], replacing an existing line for that key.
    static func setGeneral(_ key: String, _ value: String, in text: String) -> String {
        var lines = text.components(separatedBy: "\n")
        var section = ""
        for (i, raw) in lines.enumerated() {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("[") { section = line; continue }
            if section == "[General]", let eq = line.firstIndex(of: "="), line[..<eq].trimmingCharacters(in: .whitespaces) == key {
                lines[i] = "\(key) = \(value)"
                return lines.joined(separator: "\n")
            }
        }
        return insert("\(key) = \(value)", into: "General", of: text)
    }

    /// Names already used in [Proxy] and [Proxy Group].
    static func names(in text: String) -> Set<String> {
        var section = ""
        var out: Set<String> = []
        for raw in text.components(separatedBy: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("[") { section = line; continue }
            if (section == "[Proxy]" || section == "[Proxy Group]"), let eq = line.firstIndex(of: "="), !line.hasPrefix("#") {
                out.insert(line[..<eq].trimmingCharacters(in: .whitespaces))
            }
        }
        return out
    }

    /// Lines of one section, without comments or blanks.
    static func lines(of section: String, in text: String) -> [String] {
        var current = ""
        var out: [String] = []
        for raw in text.components(separatedBy: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("[") && line.hasSuffix("]") { current = String(line.dropFirst().dropLast()); continue }
            if current == section && !line.isEmpty && !line.hasPrefix("#") && !line.hasPrefix(";") { out.append(line) }
        }
        return out
    }

    /// Removes the `name = …` line from `[section]` and drops `name` from every group's
    /// member list, so nothing keeps pointing at the removed node or subscription.
    static func remove(_ name: String, from section: String, of text: String) -> String {
        var lines = text.components(separatedBy: "\n")
        var current = ""
        var out: [String] = []
        for raw in lines {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("[") && line.hasSuffix("]") { current = String(line.dropFirst().dropLast()); out.append(raw); continue }
            if let eq = line.firstIndex(of: "="), !line.hasPrefix("#") {
                let key = line[..<eq].trimmingCharacters(in: .whitespaces)
                if current == section && key == name { continue }
                if current == "Proxy Group" {
                    let fields = raw[raw.index(after: raw.firstIndex(of: "=")!)...].split(separator: ",", omittingEmptySubsequences: false)
                    let kept = fields.filter { $0.trimmingCharacters(in: .whitespaces) != name }
                    if kept.count != fields.count {
                        out.append("\(raw[..<raw.firstIndex(of: "=")!])=" + kept.joined(separator: ","))
                        continue
                    }
                }
            }
            out.append(raw)
        }
        lines = out
        return lines.joined(separator: "\n")
    }

    /// Adds `option` to the `select` group the FINAL rule points at, so new nodes show up
    /// where traffic goes by default. Returns the text unchanged if there's no such group.
    static func addToFinalGroup(_ option: String, in text: String) -> String {
        guard let final = lines(of: "Rule", in: text).last(where: { $0.uppercased().hasPrefix("FINAL") }),
              let policy = final.split(separator: ",").dropFirst().first?.trimmingCharacters(in: .whitespaces)
        else { return text }
        var lines = text.components(separatedBy: "\n")
        guard let i = lines.firstIndex(where: {
            let l = $0.trimmingCharacters(in: .whitespaces)
            return l.hasPrefix("\(policy) ") || l.hasPrefix("\(policy)=")
        }), lines[i].contains("select") else { return text }
        lines[i] += ", \(option)"
        return lines.joined(separator: "\n")
    }
}
