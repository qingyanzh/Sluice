import AppKit
import SwiftUI

struct UpdateSettingsCard: View {
    @ObservedObject private var updater = Updater.shared

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                IconTile(symbol: "arrow.down.circle", size: 28)
                Text("软件更新").font(DS.heading)
                Spacer(minLength: 8)
                StatusBadge(text: "更新渠道：\(updater.info.channel)", tone: DS.off)
            }
            Text("当前版本：\(updater.info.version)").font(DS.label).textSelection(.enabled)
            Text(updater.isAvailable ? "通过当前更新渠道获取 Sluice 新版本。" : "请从完整的 Sluice.app 运行以检查更新。")
                .font(DS.small).foregroundStyle(DS.ink2)
            Spacer(minLength: 0)
            ViewThatFits(in: .horizontal) {
                HStack(spacing: 12) { checkButton; lastCheck }
                VStack(alignment: .leading, spacing: 8) { checkButton; lastCheck }
            }
        }
        .frame(minHeight: DS.settingsCardHeight, alignment: .topLeading)
        .card()
    }

    private var checkButton: some View {
        Button("检查更新…", systemImage: "arrow.down.circle") { updater.checkForUpdates() }
            .glassButton(prominent: true)
            .disabled(!updater.canCheck)
            .help(updater.isAvailable ? "打开软件更新窗口" : "此构建未配置软件更新")
    }

    private var lastCheck: some View {
        VStack(alignment: .leading, spacing: 3) {
            if let date = updater.lastCheck {
                Text("上次检查：\(date.formatted(date: .abbreviated, time: .shortened))").monospacedDigit()
            } else {
                Text("尚未检查更新")
            }
            if updater.sessionInProgress { Text("软件更新正在进行，请查看更新窗口") }
        }
        .font(DS.caption).foregroundStyle(DS.ink3)
    }
}

struct HelperSettingsCard: View {
    @EnvironmentObject private var core: Core
    @StateObject private var helper = HelperSettings()

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                IconTile(symbol: "lock.shield", size: 28)
                Text("增强模式辅助程序").font(DS.heading)
                Spacer(minLength: 8)
                StatusBadge(text: helper.status.title, tone: tone)
            }
            Text(helper.status.detail).font(DS.small).foregroundStyle(DS.ink2)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
            Button(helper.status.action) { helper.performAction() }
                .glassButton(prominent: helper.status != .ready)
        }
        .frame(minHeight: DS.settingsCardHeight, alignment: .topLeading)
        .card()
        .onAppear { helper.refresh() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in helper.refresh() }
        .onChange(of: core.state) { _, _ in helper.refresh() }
    }

    private var tone: Color {
        switch helper.status {
        case .notInstalled: DS.off
        case .needsApproval: DS.warn
        case .ready: DS.ok
        case .failed: DS.fail
        }
    }
}

struct DiagnosticsSettingsCard: View {
    @EnvironmentObject private var core: Core
    @ObservedObject private var exporter = DiagnosticsExporter.shared

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            ViewThatFits(in: .horizontal) {
                HStack(spacing: 16) { heading; Spacer(minLength: 8); exportButton }
                VStack(alignment: .leading, spacing: 12) { heading; exportButton }
            }
            Text("收集日志、崩溃报告、已脱敏的配置与网络快照，保存为本地 ZIP 文件。分享前请检查文件内容。")
                .font(DS.small).foregroundStyle(DS.ink2).fixedSize(horizontal: false, vertical: true)
            switch exporter.state {
            case .idle:
                Text("无需启动内核，也可以导出诊断信息")
                    .font(DS.caption).foregroundStyle(DS.ink3)
            case .exporting:
                HStack(spacing: 10) {
                    ProgressView().controlSize(.small)
                    Text("正在收集并打包诊断信息…").font(DS.label).foregroundStyle(DS.ink2)
                }
                .accessibilityElement(children: .combine)
            case .exported(let file):
                Divider()
                ViewThatFits(in: .horizontal) {
                    HStack(spacing: 12) { fileLabel(file); Spacer(minLength: 8); revealButton(file) }
                    VStack(alignment: .leading, spacing: 12) { fileLabel(file); revealButton(file) }
                }
            case .failed(let message):
                Label {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("导出失败").font(DS.label.weight(.medium))
                        Text(message).font(DS.small).textSelection(.enabled)
                    }
                } icon: {
                    Image(systemName: "exclamationmark.triangle")
                }
                .foregroundStyle(DS.fail).fixedSize(horizontal: false, vertical: true)
            }
        }
        .card()
    }

    private var heading: some View {
        HStack(spacing: 10) {
            IconTile(symbol: "stethoscope", size: 28)
            Text("诊断信息").font(DS.heading)
        }
    }

    private var exportButton: some View {
        Button(exporter.state.isExporting ? "正在导出…" : "导出诊断信息…", systemImage: "square.and.arrow.up") {
            if core.lastActionError?.hasPrefix("导出诊断信息失败：") == true { core.lastActionError = nil }
            Task {
                await exporter.export(api: core.state == .running ? core.api : nil,
                                      binary: core.coreBinary, configPath: core.configPath)
            }
        }
        .glassButton(prominent: true).disabled(exporter.state.isExporting)
    }

    private func fileLabel(_ file: URL) -> some View {
        HStack(spacing: 10) {
            Image(systemName: "checkmark.circle.fill").foregroundStyle(DS.ok)
            VStack(alignment: .leading, spacing: 4) {
                Text("已导出 · \(file.lastPathComponent)").font(DS.label).lineLimit(2).textSelection(.enabled)
                Text(file.deletingLastPathComponent().path).font(DS.caption).foregroundStyle(DS.ink3)
                    .lineLimit(1).truncationMode(.middle).help(file.path)
            }
        }
    }

    private func revealButton(_ file: URL) -> some View {
        Button("在 Finder 中显示", systemImage: "folder") { NSWorkspace.shared.activateFileViewerSelecting([file]) }
            .glassButton()
    }
}
