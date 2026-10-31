import AppKit
import Combine
import UniformTypeIdentifiers

enum DiagnosticsExportState: Equatable {
    case idle
    case exporting
    case exported(URL)
    case failed(String)

    var isExporting: Bool { self == .exporting }
}

/// Shared by Settings and the menu so feedback survives pane navigation.
@MainActor
final class DiagnosticsExporter: ObservableObject {
    static let shared = DiagnosticsExporter()
    @Published private(set) var state: DiagnosticsExportState = .idle

    typealias Export = (APIClient?, URL?, String, URL) async throws -> URL
    typealias Present = (URL) async throws -> URL
    private let write: Export
    private let present: Present

    init(present: @escaping Present = DiagnosticsExporter.saveBundle,
         write: @escaping Export = DiagnosticsExporter.writeBundle) {
        self.write = write
        self.present = present
    }

    func export(api: APIClient?, binary: URL?, configPath: String) async {
        guard !state.isExporting else { return }
        state = .exporting
        let stamp = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
        let output = Core.logDir.appendingPathComponent("Sluice-diag-\(stamp)-\(UUID().uuidString.prefix(6)).zip")
        do {
            let file = try await write(api, binary, configPath, output)
            state = .exported(try await present(file))
        } catch {
            state = .failed(error.localizedDescription)
        }
    }

    private nonisolated static func writeBundle(api: APIClient?, binary: URL?, configPath: String, output: URL) async throws -> URL {
        try await Task.detached(priority: .utility) {
            try FileManager.default.createDirectory(at: output.deletingLastPathComponent(), withIntermediateDirectories: true)
            return try await collectBundle(api: api, binary: binary, configPath: configPath, output: output)
        }.value
    }

    private nonisolated static func collectBundle(api: APIClient?, binary: URL?, configPath: String, output: URL) async throws -> URL {
        let file: URL
        if let api {
            do {
                file = try await api.exportDiagnostics(to: output)
            } catch let error as APIError where error.status == 404 {
                // Older cores have CLI export but no diagnostics endpoint.
                file = try await exportWithCLI(binary: binary, configPath: configPath, output: output)
            }
        } else {
            file = try await exportWithCLI(binary: binary, configPath: configPath, output: output)
        }
        guard FileManager.default.isReadableFile(atPath: file.path) else {
            throw APIError(message: "导出完成，但无法读取诊断文件。请重试。")
        }
        return file
    }

    private static func saveBundle(_ file: URL) async throws -> URL {
        let panel = NSSavePanel()
        panel.title = "导出诊断信息"
        panel.nameFieldStringValue = file.lastPathComponent
        panel.allowedContentTypes = [.zip]
        panel.canCreateDirectories = true
        let response = await withCheckedContinuation { continuation in
            panel.begin { continuation.resume(returning: $0) }
        }
        guard response == .OK, let destination = panel.url else {
            NSWorkspace.shared.activateFileViewerSelecting([file])
            return file
        }
        do { return try await moveBundle(file, to: destination) }
        catch {
            NSWorkspace.shared.activateFileViewerSelecting([file])
            throw error
        }
    }

    nonisolated static func moveBundle(_ file: URL, to destination: URL) async throws -> URL {
        try await Task.detached(priority: .utility) {
            guard file.standardizedFileURL != destination.standardizedFileURL else { return file }
            if FileManager.default.fileExists(atPath: destination.path) {
                _ = try FileManager.default.replaceItemAt(destination, withItemAt: file)
            } else {
                try FileManager.default.moveItem(at: file, to: destination)
            }
            return destination
        }.value
    }

    private nonisolated static func exportWithCLI(binary: URL?, configPath: String, output: URL) async throws -> URL {
        guard let binary else { throw APIError(message: "找不到 Sluice 内核，请重新安装完整的 Sluice.app。") }
        return try await Task.detached {
            let process = Process()
            process.executableURL = binary
            process.arguments = ["diag", "export", output.path]
                + (FileManager.default.fileExists(atPath: configPath) ? [configPath] : [])
            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = pipe
            try process.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else {
                let message = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                throw APIError(message: message.isEmpty ? "诊断导出失败（退出码 \(process.terminationStatus)）。" : message)
            }
            return output
        }.value
    }
}
