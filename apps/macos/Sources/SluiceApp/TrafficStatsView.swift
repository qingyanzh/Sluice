import Charts
import SwiftUI

struct TrafficStatsView: View {
    @EnvironmentObject private var core: Core
    @State private var policy: String?

    private struct TotalRow: Identifiable {
        let name: String?
        let up: UInt64
        let down: UInt64
        var id: String? { name }
    }

    private var policyNames: [String] { core.stats?.policyNames ?? [] }
    private var selectedPolicy: String? {
        policy.flatMap { policyNames.contains($0) ? $0 : nil }
    }
    private var samples: [TrafficRatePoint] {
        core.statsFallback ? core.statsHistory : core.stats?.rates(for: selectedPolicy) ?? []
    }
    private var totals: [TotalRow] {
        if let stats = core.stats {
            return [TotalRow(name: nil, up: stats.up, down: stats.down)]
                + stats.policies.sorted { $0.name < $1.name }.map {
                    TotalRow(name: $0.name, up: $0.up, down: $0.down)
                }
        }
        if core.statsFallback, let traffic = core.traffic {
            return [TotalRow(name: nil, up: traffic.up, down: traffic.down)]
        }
        return []
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("统计").font(DS.heading)
                Spacer()
                Text("最近 10 分钟 · 每秒采样").font(DS.small).foregroundStyle(DS.ink3)
            }
            VStack(alignment: .leading, spacing: DS.gap) {
                ViewThatFits(in: .horizontal) {
                    HStack {
                        CardTitle(text: core.statsFallback ? "总体流量" : "策略流量", icon: "chart.xyaxis.line")
                        Spacer(minLength: 16)
                        policyPicker.frame(width: 240)
                    }
                    VStack(alignment: .leading, spacing: 12) {
                        CardTitle(text: core.statsFallback ? "总体流量" : "策略流量", icon: "chart.xyaxis.line")
                        policyPicker
                    }
                }
                if core.state != .running {
                    EmptyState(icon: "chart.xyaxis.line", title: core.state == .starting ? "Sluice 启动中" : "Sluice 未运行",
                               detail: "内核运行后可查看策略速率和累计流量。",
                               action: core.isActive ? nil : ("启动 Sluice", { core.requestStart() }))
                        .frame(height: 180)
                } else {
                    if core.statsFallback {
                        Text("当前内核不支持策略统计，仅显示应用运行期间采集的总体流量；历史只保存在内存中。")
                            .font(DS.small).foregroundStyle(DS.ink2)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if let error = core.statsError {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(error).foregroundStyle(DS.fail)
                            Text("每 5 秒自动重试；已有数据保留至下次刷新成功。")
                                .foregroundStyle(DS.ink2)
                        }.font(DS.small)
                    }
                    rateLegend
                    rateChart
                    if !totals.isEmpty {
                        Text("累计流量 · 自内核启动").font(DS.small).foregroundStyle(DS.ink2)
                        totalsTable
                    }
                }
            }.card()
        }
        .onChange(of: policyNames) { _, names in
            if let policy, !names.contains(policy) { self.policy = nil }
        }
    }

    private var policyPicker: some View {
        Picker("策略", selection: $policy) {
            Text("全部流量").tag(nil as String?)
            ForEach(policyNames, id: \.self) { name in
                Text(name).tag(Optional(name))
            }
        }
        .font(DS.label).disabled(core.statsFallback || core.stats == nil)
    }

    private var rateLegend: some View {
        HStack(spacing: 24) {
            SampleRateLabel(title: "下载", icon: "arrow.down", sample: samples.last, upload: false)
                .foregroundStyle(DS.accent)
            SampleRateLabel(title: "上传", icon: "arrow.up", sample: samples.last, upload: true)
                .foregroundStyle(DS.ink2)
        }.font(DS.small.monospacedDigit())
            .id(selectedPolicy)
    }

    private var rateChart: some View {
        let end = samples.last?.time ?? Date()
        let peak = samples.map { max($0.up, $0.down) }.max() ?? 0
        return Chart(samples) { sample in
            LineMark(x: .value("时间", sample.time), y: .value("字节/秒", sample.down),
                     series: .value("方向", "下载"))
                .foregroundStyle(DS.accent).lineStyle(StrokeStyle(lineWidth: 1.5))
            LineMark(x: .value("时间", sample.time), y: .value("字节/秒", sample.up),
                     series: .value("方向", "上传"))
                .foregroundStyle(DS.ink2).lineStyle(StrokeStyle(lineWidth: 1.5, dash: [4, 3]))
            if samples.count == 1 {
                PointMark(x: .value("时间", sample.time), y: .value("字节/秒", sample.down))
                    .foregroundStyle(DS.accent)
                PointMark(x: .value("时间", sample.time), y: .value("字节/秒", sample.up))
                    .foregroundStyle(DS.ink2)
            }
        }
        .chartXScale(domain: end.addingTimeInterval(-600)...end)
        .chartYScale(domain: 0...max(1024, peak * 1.1))
        .chartPlotStyle { plot in plot.clipped() }
        .chartXAxis {
            AxisMarks(values: .automatic(desiredCount: 5)) { _ in
                AxisGridLine()
                AxisValueLabel(format: .dateTime.hour().minute().second(),
                               collisionResolution: .greedy,
                               horizontalSpacing: 4)
                    .foregroundStyle(DS.ink3)
            }
        }
        .chartYAxis {
            AxisMarks(position: .leading, values: .automatic(desiredCount: 4)) { value in
                AxisGridLine()
                AxisValueLabel {
                    if let bytes = value.as(Double.self) {
                        Text("\(formatBytes(bytes))/s").font(DS.caption).monospacedDigit().foregroundStyle(DS.ink3)
                    }
                }
            }
        }
        // Leave room for the endpoint timestamp, including locales with AM/PM.
        .padding(.trailing, 40)
        .frame(height: 200)
        .overlay {
            if samples.isEmpty {
                Text(core.statsError == nil ? "等待速率采样…" : "暂时无法读取速率")
                    .font(DS.small).foregroundStyle(DS.ink2)
            }
        }
        .accessibilityLabel("\(selectedPolicy ?? "全部流量")，最近 10 分钟的上传与下载速率")
    }

    private var totalsTable: some View {
        Table(totals) {
            TableColumn("策略") { row in
                Text(row.name ?? "全部流量").font(DS.label).lineLimit(1).help(row.name ?? "全部流量")
            }.width(min: 100, ideal: 240)
            TableColumn("上传") { row in
                Text(formatBytes(Double(row.up))).font(DS.label.monospacedDigit())
            }.width(min: 90, ideal: 130)
            TableColumn("下载") { row in
                Text(formatBytes(Double(row.down))).font(DS.label.monospacedDigit())
            }.width(min: 90, ideal: 130)
        }
        .frame(height: CGFloat(min(totals.count, 8)) * 30 + 32)
        .scrollContentBackground(.hidden)
        .accessibilityLabel("每个策略的累计上传与下载流量")
    }
}

/// Smooth only the numeric legend. The chart consumes the original samples.
private struct SampleRateLabel: View {
    let title: String
    let icon: String
    let sample: TrafficRatePoint?
    let upload: Bool
    @State private var rate = DisplayedRate()

    var body: some View {
        Label {
            HStack(spacing: 4) {
                Text(title)
                Text(rate.formatted.text).monospacedDigit().frame(width: 100, alignment: .trailing)
            }
        } icon: { Image(systemName: icon) }
        .onChange(of: sample?.id, initial: true) {
            if let sample { rate.update(upload ? sample.up : sample.down) }
            else { rate = DisplayedRate() }
        }
    }
}
