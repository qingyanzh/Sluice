import AppKit
import ServiceManagement
import SwiftUI

enum Pane: String, CaseIterable, Identifiable {
    case overview = "Overview", policies = "Policies", nodes = "Nodes", connections = "Connections"
    case logs = "Logs", route = "Route Test", config = "Config"
    var id: String { rawValue }
    var icon: String {
        switch self {
        case .overview: "gauge.with.dots.needle.33percent"
        case .policies: "arrow.triangle.branch"
        case .nodes: "server.rack"
        case .connections: "point.3.connected.trianglepath.dotted"
        case .logs: "text.alignleft"
        case .route: "signpost.right"
        case .config: "doc.text"
        }
    }
}

struct MainView: View {
    @EnvironmentObject var core: Core
    @State private var pane: Pane? = .overview

    var body: some View {
        NavigationSplitView {
            List(Pane.allCases, selection: $pane) { p in
                Label(p.rawValue, systemImage: p.icon).tag(p)
            }
            .navigationSplitViewColumnWidth(min: 170, ideal: 190)
            .safeAreaInset(edge: .bottom) { StatusFooter().padding(10) }
        } detail: {
            VStack(spacing: 0) {
                if let err = core.lastActionError {
                    ErrorBanner(message: err) { core.lastActionError = nil }
                }
                switch pane ?? .overview {
                case .overview: OverviewView()
                case .policies: PoliciesView()
                case .nodes: NodesView()
                case .connections: ConnectionsView()
                case .logs: LogsView()
                case .route: RouteView()
                case .config: ConfigView()
                }
            }
            .navigationTitle(pane?.rawValue ?? "Sluice")
        }
        .frame(minWidth: 820, minHeight: 520)
        .onAppear {
            core.refreshSystemProxy()
            core.startIfAutoStart()
        }
    }
}

// MARK: shared bits

struct StatusDot: View {
    let state: Core.State
    var color: Color {
        switch state {
        case .running: .green
        case .starting: .orange
        case .stopped: .secondary
        case .failed: .red
        }
    }
    var body: some View { Circle().fill(color).frame(width: 9, height: 9) }
}

struct StatusFooter: View {
    @EnvironmentObject var core: Core
    var body: some View {
        HStack {
            StatusDot(state: core.state)
            Text(core.state.label).font(.callout)
            if core.privileged { Text("root").font(.caption2).padding(.horizontal, 4).background(.orange.opacity(0.25), in: Capsule()) }
            Spacer()
            StartStopButton(compact: true)
        }
    }
}

struct StartStopButton: View {
    @EnvironmentObject var core: Core
    var compact = false
    var body: some View {
        if core.isActive {
            Button { core.stop() } label: { Label("Stop", systemImage: "stop.fill") }
                .labelStyle(compact ? AnyLabelStyle(.iconOnly) : AnyLabelStyle(.titleAndIcon))
                .help("Stop Sluice")
        } else {
            Button { core.start() } label: { Label("Start", systemImage: "play.fill") }
                .labelStyle(compact ? AnyLabelStyle(.iconOnly) : AnyLabelStyle(.titleAndIcon))
                .keyboardShortcut(compact ? nil : .defaultAction)
                .help("Start Sluice")
        }
    }
}

struct AnyLabelStyle: LabelStyle {
    private let make: (Configuration) -> AnyView
    init<S: LabelStyle>(_ style: S) { make = { AnyView(style.makeBody(configuration: $0)) } }
    func makeBody(configuration: Configuration) -> some View { make(configuration) }
}

struct ErrorBanner: View {
    let message: String
    let dismiss: () -> Void
    var body: some View {
        HStack(alignment: .top) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red)
            Text(message).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
            Button(action: dismiss) { Image(systemName: "xmark") }.buttonStyle(.borderless)
        }
        .padding(10)
        .background(.red.opacity(0.1))
    }
}

struct LatencyBadge: View {
    let latency: Int?
    var body: some View {
        let (text, color): (String, Color) = {
            guard let ms = latency else { return ("–", .secondary) }
            if ms < 0 { return ("fail", .red) }
            return ("\(ms) ms", ms < 200 ? .green : ms < 500 ? .orange : .red)
        }()
        Text(text).font(.caption.monospacedDigit()).foregroundStyle(color)
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(color.opacity(0.12), in: Capsule())
    }
}

// MARK: overview

struct OverviewView: View {
    @EnvironmentObject var core: Core

    var body: some View {
        Form {
            Section("Status") {
                HStack(spacing: 10) {
                    StatusDot(state: core.state)
                    Text(core.state.label).font(.title3.weight(.semibold))
                    if core.privileged { Text("enhanced mode (root)").foregroundStyle(.orange) }
                    Spacer()
                    StartStopButton()
                    Button("Restart") { core.restart() }.disabled(!core.isActive)
                    Button("Reload Config") { core.reload() }.disabled(core.state != .running)
                }
                if case .failed(let why) = core.state {
                    Text(why).foregroundStyle(.red).textSelection(.enabled)
                }
            }
            Section("Config") {
                LabeledContent("File") { Text(core.configPath).textSelection(.enabled).lineLimit(1).truncationMode(.middle) }
                LabeledContent("HTTP proxy", value: core.summary.httpListen ?? "off")
                LabeledContent("SOCKS5 proxy", value: core.summary.socksListen ?? "off")
                LabeledContent("Control API", value: core.summary.apiPort.map { "127.0.0.1:\($0)" } ?? "off (required by the app)")
                LabeledContent("Enhanced mode", value: core.summary.enhancedMode ? "on (asks for an administrator password)" : "off")
            }
            Section("System proxy") {
                Toggle(isOn: Binding(get: { core.systemProxyOn }, set: { core.setSystemProxy($0) })) {
                    VStack(alignment: .leading) {
                        Text("Use Sluice as the system proxy")
                        Text("Points every network service's HTTP, HTTPS and SOCKS proxy at Sluice. macOS asks for an administrator password.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                .disabled(core.summary.httpListen == nil && core.summary.socksListen == nil)
            }
            Section("Traffic") {
                HStack(spacing: 24) {
                    RateView(label: "Upload", systemImage: "arrow.up", rate: core.upRate, total: core.traffic?.up)
                    RateView(label: "Download", systemImage: "arrow.down", rate: core.downRate, total: core.traffic?.down)
                    VStack(alignment: .leading) {
                        Text("Open connections").font(.caption).foregroundStyle(.secondary)
                        Text("\(core.traffic?.active ?? 0)").font(.title3.monospacedDigit())
                    }
                    Spacer()
                }
            }
            Section("General") {
                Toggle("Start Sluice when the app opens", isOn: $core.autoStart)
                LoginItemToggle()
            }
            Section("Activity") {
                LabeledContent("Policy groups", value: "\(core.groups.count)")
                LabeledContent("Connections seen", value: "\(core.connections.count)")
                LabeledContent("Rejected", value: "\(core.connections.filter { $0.outbound == "REJECT" }.count)")
            }
        }
        .formStyle(.grouped)
    }
}

struct RateView: View {
    let label: String
    let systemImage: String
    let rate: Double
    let total: UInt64?
    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Label(label, systemImage: systemImage).font(.caption).foregroundStyle(.secondary)
            Text("\(formatBytes(rate))/s").font(.title3.monospacedDigit())
            Text("\(formatBytes(Double(total ?? 0))) total").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
        }
    }
}

/// "Open at login" via SMAppService; only works for the bundled app (dist/Sluice.app).
struct LoginItemToggle: View {
    @State private var enabled = SMAppService.mainApp.status == .enabled
    @State private var error: String?
    var body: some View {
        VStack(alignment: .leading) {
            Toggle("Open Sluice at login", isOn: Binding(get: { enabled }, set: set))
            if let error { Text(error).font(.caption).foregroundStyle(.red) }
            if SMAppService.mainApp.status == .requiresApproval {
                Text("Allow Sluice in System Settings › General › Login Items.").font(.caption).foregroundStyle(.secondary)
            }
        }
    }
    private func set(_ on: Bool) {
        do {
            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
        enabled = SMAppService.mainApp.status == .enabled
    }
}

// MARK: policies

struct PoliciesView: View {
    @EnvironmentObject var core: Core

    var body: some View {
        Group {
            if core.groups.isEmpty {
                ContentUnavailableView(core.state == .running ? "No policy groups" : "Sluice isn't running",
                                       systemImage: "arrow.triangle.branch",
                                       description: Text(core.state == .running ? "Add groups under [Proxy Group] in the config." : "Start Sluice to see and switch its policy groups."))
            } else {
                List {
                    ForEach(core.groups) { g in
                        Section {
                            // Rows are keyed by group too: the same option (name and latency)
                            // appears in several groups, and duplicate IDs make List reuse rows.
                            ForEach(g.options, id: \.name) { o in
                                OptionRow(group: g, option: o).id("\(g.group)/\(o.name)")
                            }
                        } header: {
                            HStack {
                                Text(g.group).font(.headline)
                                Text(g.type).font(.caption).foregroundStyle(.secondary)
                                Spacer()
                                if !g.isSelectable {
                                    Button("Test") { core.test(group: g.group) }.controlSize(.small)
                                }
                            }
                        }
                    }
                }
            }
        }
        .toolbar {
            Button { core.testAll() } label: { Label("Test All", systemImage: "speedometer") }
                .disabled(core.groups.allSatisfy(\.isSelectable))
        }
    }
}

struct OptionRow: View {
    @EnvironmentObject var core: Core
    let group: PolicyGroup
    let option: GroupOption

    var body: some View {
        let chosen = group.selected == option.name
        HStack {
            Image(systemName: chosen ? "checkmark.circle.fill" : "circle")
                .foregroundStyle(chosen ? Color.accentColor : .secondary)
            Text(option.name)
            Spacer()
            LatencyBadge(latency: option.latencyMs)
        }
        .contentShape(Rectangle())
        .onTapGesture { if group.isSelectable && !chosen { core.select(group: group.group, option: option.name) } }
        .help(group.isSelectable ? "Use \(option.name)" : "\(group.type) picks automatically")
    }
}

// MARK: nodes

struct NodesView: View {
    @EnvironmentObject var core: Core
    @State private var showAddNode = false
    @State private var showAddSub = false
    @State private var text = ""

    var body: some View {
        let proxies = ConfigText.lines(of: "Proxy", in: text)
        let subs = ConfigText.lines(of: "Proxy Group", in: text).filter { $0.contains("policy-path=") }
        List {
            Section("Nodes (\(proxies.count))") {
                if proxies.isEmpty { Text("No nodes yet").foregroundStyle(.secondary) }
                ForEach(proxies, id: \.self) { NodeRow(line: $0) }
            }
            Section("Subscriptions (\(subs.count))") {
                if subs.isEmpty { Text("No subscriptions yet").foregroundStyle(.secondary) }
                ForEach(subs, id: \.self) { NodeRow(line: $0) }
            }
        }
        .toolbar {
            Button { showAddNode = true } label: { Label("Add Node", systemImage: "plus") }
            Button { showAddSub = true } label: { Label("Add Subscription", systemImage: "link.badge.plus") }
        }
        .sheet(isPresented: $showAddNode, onDismiss: refresh) { AddNodeSheet() }
        .sheet(isPresented: $showAddSub, onDismiss: refresh) { AddSubscriptionSheet() }
        .onAppear(perform: refresh)
    }

    private func refresh() { text = core.readConfig() }
}

struct NodeRow: View {
    let line: String
    var body: some View {
        let (name, rest) = line.firstIndex(of: "=").map {
            (line[..<$0].trimmingCharacters(in: .whitespaces), line[line.index(after: $0)...].trimmingCharacters(in: .whitespaces))
        } ?? (line, "")
        let parts = rest.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        HStack {
            Text(name).fontWeight(.medium)
            if let kind = parts.first { Text(kind).font(.caption).foregroundStyle(.secondary) }
            Spacer()
            // Server and port only; credentials stay out of the list.
            Text(parts.dropFirst().prefix(2).filter { !$0.contains("=") }.joined(separator: ":"))
                .font(.callout.monospaced()).foregroundStyle(.secondary)
        }
    }
}

struct AddNodeSheet: View {
    @EnvironmentObject var core: Core
    @Environment(\.dismiss) private var dismiss
    @State private var input = ""
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Add Node").font(.title2.bold())
            Text("Paste a share link (ss://, vmess://, vless://, trojan://, hysteria2://) or a proxy line such as `HK = ss, hk.example.com, 8388, encrypt-method=aes-256-gcm, password=…`.")
                .foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            TextField("Share link or proxy line", text: $input, axis: .vertical)
                .lineLimit(3...6).textFieldStyle(.roundedBorder).font(.body.monospaced())
            if let error { Text(error).foregroundStyle(.red).textSelection(.enabled) }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(busy ? "Checking…" : "Add") {
                    busy = true
                    Task {
                        error = await core.addNode(input)
                        busy = false
                        if error == nil { dismiss() }
                    }
                }
                .keyboardShortcut(.defaultAction).disabled(busy || input.isEmpty)
            }
        }
        .padding(20).frame(width: 520)
    }
}

struct AddSubscriptionSheet: View {
    @EnvironmentObject var core: Core
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var url = ""
    @State private var filter = ""
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Add Subscription").font(.title2.bold())
            Form {
                TextField("Name", text: $name, prompt: Text("Subscription"))
                TextField("URL", text: $url, prompt: Text("https://…"))
                TextField("Name filter (regex, optional)", text: $filter, prompt: Text("e.g. 香港|HK"))
            }
            Text("The nodes are downloaded and checked before the config is saved.").font(.caption).foregroundStyle(.secondary)
            if let error { Text(error).foregroundStyle(.red).textSelection(.enabled) }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(busy ? "Downloading…" : "Add") {
                    busy = true
                    Task {
                        error = await core.addSubscription(name: name, url: url, filter: filter)
                        busy = false
                        if error == nil { dismiss() }
                    }
                }
                .keyboardShortcut(.defaultAction).disabled(busy || url.isEmpty)
            }
        }
        .padding(20).frame(width: 520)
    }
}

// MARK: connections

struct ConnectionsView: View {
    @EnvironmentObject var core: Core
    @State private var filter = ""

    var body: some View {
        let rows = core.connections.reversed().filter {
            filter.isEmpty || $0.target.localizedCaseInsensitiveContains(filter) || $0.outbound.localizedCaseInsensitiveContains(filter)
                || $0.policy.localizedCaseInsensitiveContains(filter)
        }
        Table(rows) {
            TableColumn("Time", value: \.time).width(min: 70, ideal: 90)
            TableColumn("", value: \.proto).width(36)
            TableColumn("Target", value: \.target).width(min: 160, ideal: 240)
            TableColumn("Policy", value: \.policy).width(min: 70, ideal: 90)
            TableColumn("Rule", value: \.rule).width(min: 100, ideal: 180)
            TableColumn("Via") { c in
                Text(c.outbound).foregroundStyle(c.outbound == "REJECT" ? .red : .primary)
            }
            .width(min: 70, ideal: 100)
        }
        .overlay {
            if core.connections.isEmpty {
                ContentUnavailableView("No connections yet", systemImage: "point.3.connected.trianglepath.dotted",
                                       description: Text("Connections through Sluice appear here as they're made."))
            }
        }
        .searchable(text: $filter, prompt: "Filter by host, policy or outbound")
        .toolbar { Button { core.clearConnections() } label: { Label("Clear", systemImage: "trash") } }
    }
}

// MARK: logs

struct LogsView: View {
    @EnvironmentObject var core: Core
    @State private var filter = ""
    @State private var follow = true

    var body: some View {
        let lines = core.logs.filter { filter.isEmpty || $0.message.localizedCaseInsensitiveContains(filter) || $0.level.localizedCaseInsensitiveContains(filter) }
        ScrollViewReader { proxy in
            List(lines) { l in
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text(l.time).foregroundStyle(.secondary)
                    Text(l.level).foregroundStyle(color(l.level)).frame(width: 44, alignment: .leading)
                    Text(l.message).textSelection(.enabled)
                }
                .font(.system(.callout, design: .monospaced))
                .id(l.id)
            }
            .onChange(of: core.logs.count) {
                if follow, let last = lines.last { proxy.scrollTo(last.id, anchor: .bottom) }
            }
        }
        .searchable(text: $filter, prompt: "Filter logs")
        .toolbar {
            Toggle(isOn: $follow) { Label("Follow", systemImage: "arrow.down.to.line") }
            Button { core.clearLogs() } label: { Label("Clear", systemImage: "trash") }
        }
    }

    private func color(_ level: String) -> Color {
        switch level {
        case "ERROR": .red
        case "WARN": .orange
        case "APP": .accentColor
        default: .secondary
        }
    }
}

// MARK: route test

struct RouteView: View {
    @EnvironmentObject var core: Core
    @State private var target = "www.google.com"
    @State private var result: RouteResult?
    @State private var error: String?

    var body: some View {
        Form {
            Section {
                HStack {
                    TextField("Host or host:port", text: $target).onSubmit(check)
                    Button("Check", action: check).disabled(target.isEmpty)
                }
            } footer: {
                Text("Shows which rule a destination matches and which outbound it would use, without connecting.")
            }
            if let result {
                Section("Result") {
                    LabeledContent("Target", value: result.target)
                    LabeledContent("Rule", value: result.rule)
                    LabeledContent("Policy", value: result.policy)
                    LabeledContent("Outbound") { Text(result.outbound).foregroundStyle(result.outbound == "REJECT" ? .red : .primary).bold() }
                }
            }
            if let error { Section { Text(error).foregroundStyle(.red) } }
        }
        .formStyle(.grouped)
    }

    private func check() {
        Task {
            do {
                result = try await core.route(target)
                error = nil
            } catch {
                result = nil
                self.error = error.localizedDescription
            }
        }
    }
}

// MARK: config

struct ConfigView: View {
    @EnvironmentObject var core: Core
    @State private var text = ""
    @State private var saved = ""
    @State private var message: (String, Bool)?
    @State private var busy = false

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text(core.configPath).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                Spacer()
                Button("Choose…", action: choose)
                Button("Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: core.configPath)]) }
            }
            .padding(8)
            Divider()
            TextEditor(text: $text)
                .font(.system(.body, design: .monospaced))
                .autocorrectionDisabled()
            Divider()
            HStack {
                if let (msg, ok) = message {
                    Image(systemName: ok ? "checkmark.circle.fill" : "xmark.octagon.fill").foregroundStyle(ok ? .green : .red)
                    Text(msg).textSelection(.enabled).lineLimit(3)
                }
                Spacer()
                Button("Revert") { load() }.disabled(text == saved)
                Button(busy ? "Checking…" : "Check") { run(save: false) }.disabled(busy)
                Button("Save & Apply") { run(save: true) }.keyboardShortcut("s").disabled(busy || text == saved)
            }
            .padding(8)
        }
        .onAppear(perform: load)
    }

    private func load() {
        text = core.readConfig()
        saved = text
        message = nil
    }

    private func run(save: Bool) {
        busy = true
        Task {
            if save {
                if let err = await core.saveConfig(text) {
                    message = (err, false)
                } else {
                    saved = text
                    message = (core.state == .running ? "Saved and applied" : "Saved", true)
                }
            } else {
                let err = await core.validate(text)
                message = err.map { ($0, false) } ?? ("Config is valid", true)
            }
            busy = false
        }
    }

    private func choose() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.message = "Choose a Sluice config file"
        if panel.runModal() == .OK, let url = panel.url {
            core.configPath = url.path
            core.refreshSummary()
            load()
        }
    }
}
