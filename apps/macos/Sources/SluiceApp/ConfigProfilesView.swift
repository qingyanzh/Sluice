import SwiftUI

enum ProfileEdit: Identifiable {
    case create, duplicate(String), rename(String)

    var id: String {
        switch self {
        case .create: "create"
        case .duplicate(let name): "duplicate:\(name)"
        case .rename(let name): "rename:\(name)"
        }
    }

    var title: String {
        switch self {
        case .create: "从当前新建配置"
        case .duplicate: "复制配置"
        case .rename: "重命名配置"
        }
    }

    var initialName: String {
        switch self {
        case .create: ""
        case .duplicate(let name): "\(name) 副本"
        case .rename(let name): name
        }
    }
}

struct ConfigProfileList: View {
    @EnvironmentObject var core: Core
    let busy: Bool
    let switchProfile: (String) -> Void
    let edit: (ProfileEdit) -> Void
    let delete: (String) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("本地配置").font(DS.heading)
                Spacer()
                Button { core.refreshProfiles() } label: {
                    Image(systemName: "arrow.clockwise").font(DS.label)
                }
                .buttonStyle(.plain).foregroundStyle(DS.ink2)
                .disabled(busy).help("刷新配置列表")
                .accessibilityLabel("刷新配置列表")
            }
            ScrollView {
                VStack(spacing: 4) {
                    if core.profileNames.isEmpty {
                        Text("没有可用的本地配置。请检查配置文件夹后刷新列表。")
                            .font(DS.small).foregroundStyle(DS.ink2)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    ForEach(core.profileNames, id: \.self) { name in
                        let active = name == core.activeProfileName
                        HStack(spacing: 6) {
                            Button { switchProfile(name) } label: {
                                HStack(spacing: 8) {
                                    Image(systemName: active ? "checkmark.circle.fill" : "doc.text")
                                        .foregroundStyle(active ? DS.accent : DS.ink3)
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text(name).font(DS.label.weight(active ? .semibold : .regular))
                                            .lineLimit(2)
                                        if active { Text("当前使用").font(DS.caption).foregroundStyle(DS.accent) }
                                    }
                                    Spacer(minLength: 0)
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .disabled(busy || !core.canChangeProfile)
                            .accessibilityLabel("\(name)\(active ? "，当前使用" : "，切换配置")")
                            Menu {
                                Button("复制…") { edit(.duplicate(name)) }
                                Button("重命名…") { edit(.rename(name)) }
                                    .disabled(active && !core.canChangeProfile)
                                Divider()
                                Button("删除…", role: .destructive) { delete(name) }.disabled(active)
                            } label: {
                                Image(systemName: "ellipsis").font(DS.label).foregroundStyle(DS.ink2)
                            }
                            .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
                            .disabled(busy)
                            .accessibilityLabel("\(name) 的操作")
                        }
                        .padding(.horizontal, 10).padding(.vertical, 12)
                        .background(active ? DS.accent.opacity(0.08) : .clear,
                                    in: RoundedRectangle(cornerRadius: DS.smallRadius))
                    }
                }
            }
            Text("切换整套订阅、策略组和规则，并恢复该配置的节点选择。监听地址或增强模式变化时会重启。")
                .font(DS.small).foregroundStyle(DS.ink2)
        }
        .frame(maxHeight: .infinity, alignment: .top)
        .card()
        .frame(width: 260)
    }
}

struct ProfileNameSheet: View {
    let action: ProfileEdit
    let submit: (String) async throws -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var name: String
    @State private var error: String?
    @State private var busy = false
    @FocusState private var focused: Bool

    init(action: ProfileEdit, submit: @escaping (String) async throws -> Void) {
        self.action = action
        self.submit = submit
        _name = State(initialValue: action.initialName)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            SheetHeader(icon: "doc.text", title: action.title,
                        detail: "配置保存在本地 profiles 文件夹中，文件扩展名 .conf 会自动添加。")
            SheetField(label: "配置名称", prompt: "例如 工作、家庭", text: $name)
                .focused($focused).disabled(busy)
                .onSubmit(save)
            if case .create = action {
                Text("包含编辑器中尚未保存的修改。新建后可在列表中切换。")
                    .font(DS.small).foregroundStyle(DS.ink2)
            }
            SheetFooter(error: error, primary: "保存", enabled: !name.isEmpty && !busy,
                        cancel: { dismiss() }, action: save)
        }
        .padding(28).frame(width: 460)
        .onAppear { focused = true }
    }

    private func save() {
        guard !busy else { return }
        busy = true
        Task {
            defer { busy = false }
            do {
                try await submit(name)
                dismiss()
            } catch { self.error = error.localizedDescription }
        }
    }
}
