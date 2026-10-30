import Foundation

/// Quotes `s` for a POSIX shell.
func shellQuote(_ s: String) -> String {
    "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
}

/// Runs a command and returns (status, combined output).
func runTool(_ path: String, _ args: [String]) async -> (Int32, String) {
    await withCheckedContinuation { cont in
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        p.terminationHandler = { proc in
            let out = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            cont.resume(returning: (proc.terminationStatus, out))
        }
        do { try p.run() } catch { cont.resume(returning: (-1, error.localizedDescription)) }
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
    static func services() async -> [String] {
        let (_, out) = await runTool("/usr/sbin/networksetup", ["-listallnetworkservices"])
        return out.split(separator: "\n").dropFirst().map(String.init).filter { !$0.hasPrefix("*") && !$0.isEmpty }
    }

    /// Whether the system HTTP proxy currently points at `port` on localhost.
    static func isPointing(atPort port: Int) async -> Bool {
        let (_, out) = await runTool("/usr/sbin/scutil", ["--proxy"])
        func value(_ key: String) -> String? {
            out.split(separator: "\n").first { $0.trimmingCharacters(in: .whitespaces).hasPrefix("\(key) :") }
                .map { $0.split(separator: ":").last!.trimmingCharacters(in: .whitespaces) }
        }
        return value("HTTPEnable") == "1" && value("HTTPPort") == String(port)
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

    /// `127.0.0.1:6152` -> ("127.0.0.1", 6152); a bare port means localhost.
    static func split(_ listen: String?) -> (String, Int)? {
        guard let listen else { return nil }
        let parts = listen.split(separator: ":")
        guard let port = parts.last.flatMap({ Int($0) }) else { return nil }
        let host = parts.count > 1 ? parts.dropLast().joined(separator: ":") : "127.0.0.1"
        return (host == "0.0.0.0" ? "127.0.0.1" : host, port)
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
