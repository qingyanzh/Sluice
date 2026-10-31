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
            SheetHeader(icon: "doc.badge.plus", title: "导入配置", detail: "导入节点、策略组和规则，生成一份新配置，当前配置保持不变")
            SheetField(label: "配置名称", prompt: "例如 工作、旅行", text: $name)
            Text("导入的订阅默认使用相同名称；之后可在订阅页修改。原生配置保留已有订阅名称。")
                .font(DS.small).foregroundStyle(DS.ink2)
            HStack(alignment: .bottom) {
                SheetField(label: "订阅或配置地址", prompt: "https://… 或 file://…", text: $source)
                Button("选择文件…", action: chooseFile).glassButton()
            }
            VStack(alignment: .leading, spacing: 6) {
                importPoint("link", "节点作为订阅导入，随来源自动更新")
                importPoint("square.stack.3d.up", "策略组和规则复制为你自己的，可以随意编辑")
                importPoint("gearshape", "监听端口等本机设置沿用当前配置")
            }
            if let prepared {
                HStack(spacing: 20) {
                    Text("\(prepared.nodes) 个节点")
                    Text("\(prepared.groups) 个策略组")
                    Text("\(prepared.rules) 条规则")
                }.font(DS.label).foregroundStyle(DS.accent)
                Text("检查通过，创建后可在配置列表中切换使用").font(DS.small).foregroundStyle(DS.ink2)
            }
            SheetFooter(error: error, primary: busy ? "处理中…" : prepared == nil ? "读取并检查" : "创建配置", enabled: !busy && !source.isEmpty && !name.isEmpty,
                        cancel: { dismiss() }, action: submit)
        }
        .padding(28).frame(width: 600).disabled(busy).interactiveDismissDisabled(busy)
        .onChange(of: source) { prepared = nil; error = nil }
        .onChange(of: name) { prepared = nil; error = nil }
    }

    private func importPoint(_ icon: String, _ text: String) -> some View {
        Label { Text(text).font(DS.small).foregroundStyle(DS.ink2) } icon: {
            Image(systemName: icon).foregroundStyle(DS.accent).frame(width: 16)
        }
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
                else { prepared = try await core.prepareProfileImport(source, name: name) }
            } catch { self.error = error.localizedDescription }
        }
    }
}
