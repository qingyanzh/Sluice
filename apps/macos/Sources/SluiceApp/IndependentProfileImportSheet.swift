import AppKit
import SwiftUI

struct PreparedProfileImport {
    let text: String
    let nodes: Int
    let groups: Int
    let rules: Int
}

struct IndependentProfileImportSheet: View {
    @EnvironmentObject var core: Core
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var source = ""
    @State private var prepared: PreparedProfileImport?
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            SheetHeader(icon: "doc.badge.plus", title: "导入独立配置", detail: "创建一套单独的订阅、策略组和规则，当前运行方案保持不变。")
            SheetField(label: "配置名称", prompt: "例如 工作、旅行", text: $name)
            HStack(alignment: .bottom) {
                SheetField(label: "订阅或配置地址", prompt: "https://… 或 file://…", text: $source)
                Button("选择文件…", action: chooseFile).glassButton()
            }
            Text("Surge/Clash 导入节点、支持的策略组及规则，本机监听设置沿用当前配置。原生 Sluice 配置保留自己的设置。导入后需在策略页切换并启用。")
                .font(DS.small).foregroundStyle(DS.ink2)
            if let prepared {
                HStack(spacing: 20) {
                    Text("\(prepared.nodes) 个节点")
                    Text("\(prepared.groups) 个策略组")
                    Text("\(prepared.rules) 条规则")
                }.font(DS.label).foregroundStyle(DS.accent)
                Text("校验通过。订阅节点和组随来源更新，规则保存为可编辑快照。").font(DS.small).foregroundStyle(DS.ink2)
            }
            SheetFooter(error: error, primary: busy ? "处理中…" : prepared == nil ? "读取并检查" : "创建配置", enabled: !busy && !source.isEmpty && !name.isEmpty,
                        cancel: { dismiss() }, action: submit)
        }
        .padding(28).frame(width: 600).disabled(busy).interactiveDismissDisabled(busy)
        .onChange(of: source) { prepared = nil; error = nil }
    }

    private func chooseFile() {
        let panel = NSOpenPanel(); panel.canChooseDirectories = false; panel.allowsMultipleSelection = false
        panel.title = "选择配置或订阅文件"
        if panel.runModal() == .OK, let url = panel.url {
            source = url.absoluteString
            if name.isEmpty { name = url.deletingPathExtension().lastPathComponent }
        }
    }
    private func submit() {
        busy = true; error = nil
        Task {
            defer { busy = false }
            do {
                try ProfileStore.validateName(name)
                if let prepared { try await core.importProfile(name: name, text: prepared.text); dismiss() }
                else { prepared = try await core.prepareProfileImport(source) }
            } catch { self.error = error.localizedDescription }
        }
    }
}
