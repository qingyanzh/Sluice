# Sluice 完整测试矩阵

范围：当前检出版本的全部 `apps/macos/Sources/SluiceApp/*.swift`、`src/main.rs` 的命令分派与实际帮助输出，以及 `src/api.rs` 顶部文档中的全部端点和行为查询参数。本文是待执行用例清单，所有“结果”单元格留空；源码与帮助核对不等于功能测试通过。

计数规则：一个交互入口、菜单、弹窗、按钮、输入、行为参数或快捷键各占一行；`ForEach` 生成的同类项只列一行模板，在该行测试所有值。共享组件先列定义行为，再列页面实例；同一行列出调用点和组件定义以便追踪。数量是测试项数，不是运行时控件实例数。图标按钮使用源码的中文 Label、help 或 accessibilityLabel；无文字、系统控件和动态名称明确注明。CLI/API 保留原始命令和参数拼写。

## 执行环境与本地夹具

- “需外网”表示该行指定的测试是否需要公网；“否”不表示可以在有 Surge 的机器上改动系统网络。“需无Surge机器”是执行条件，不能以关闭界面代替隔离机器。涉及系统代理、增强模式/TUN、辅助程序安装，或真实代理节点/公网订阅的测试必须带此标记执行。
- 本地只用 DIRECT/REJECT 出站、loopback、`python3 -m http.server 18080 --bind 127.0.0.1 --directory <临时目录>` 和 `file://` 订阅；HTTP API 请求显式使用 `curl --noproxy '*'`，避免环境代理。配置、日志、证书与导出文件放临时目录；测试不得改动个人配置。依赖安装/构建联网不计入用例“需外网”。
- 普通本地基线：HTTP `127.0.0.1:18081`、SOCKS5 `127.0.0.1:18082`、API `127.0.0.1:18083`，无 enhanced-mode、无系统代理。端口占用时统一改为其他空闲 loopback 端口。所有组的 `url` 必须显式指向 loopback，包含手动组；否则默认健康检查地址在公网。

```ini
[General]
http-listen = 127.0.0.1:18081
socks5-listen = 127.0.0.1:18082
api-listen = 127.0.0.1:18083
[Proxy Group]
Local = select, DIRECT, REJECT, url=http://127.0.0.1:18080/, interval=600
Auto = url-test, DIRECT, REJECT, url=http://127.0.0.1:18080/, interval=600
[Rule]
DOMAIN,blocked.test,REJECT
IP-CIDR,127.0.0.0/8,Local,no-resolve
FINAL,REJECT
```

- 第二份 `.conf` 保持相同监听，将 FINAL 改为 DIRECT；用于切换/热重载对照。规则上下文测试可用 `tests/fixtures/local-check/rules.conf` 及同目录规则集；所有出站仍为 DIRECT/REJECT。
- 本地订阅文件可只含 `[Proxy]`、`DIRECT = direct`、`REJECT = reject`。当前解析器会跳过这两个内置类型，因此预期导入 **0 个真实节点**、无内联成员的订阅组回退 REJECT；不得把这当成真实节点导入成功。非空代理列表、代理类别、真实节点详情及公网连通成功在需无Surge机器上验证。`convert` 的假凭据 loopback 分享链接只做离线解析，不运行生成的节点配置。
- DNS 测试用独立 loopback DNS 服务（可参考 `scripts/ci/e2e_api.py` 的 DNSHandler），配置 `dns-server = 127.0.0.1:<本地DNS端口>`，仅解析测试域名到 loopback。不要为填充缓存查询公网。活动连接用本地大文件限速下载或保持 TCP 流；普通快速 HTTP 响应通常不足以留住连接。
- GUI 单节点测速没有 URL 输入，会使用 API 默认公网地址 `http://www.gstatic.com/generate_204`；即使组 URL 已改为 loopback，也不能据此把单节点成功测试列为纯本地。组测速可以使用配置内的 loopback URL。API 单节点测速必须显式传 `url=` 才能本地成功测试。
- 本地读界面可参考 E2E 附着模式，它不拥有内核且抑制部分系统操作，因此不能验证真实启动/停止、更新、系统代理、TUN 或 helper 成功。不要设置伪造的 CI 环境变量运行仓库限定 CI 的网络脚本。
- 增强模式启动当前会尝试 `apple.com` 的出站自检（`src/main.rs:58`）；本表该类功能本身不要求公网成功，因此标“否”，在需无Surge机器上允许自检失败并核对警告；如需验证自检成功则需外网。

## A. GUI

### 逐文件扫描记录

对以下 24 个 Swift 文件逐一运行 `rg -n`（grep）检查原生控件、菜单、弹窗、输入、快捷键、手势、删除/移动、拖放、导航和 AppKit 控件；同时追踪 SearchField、GlassSegmented、SheetField、SheetFooter、FeatureCard、EmptyState 等包装器的调用点。

| 文件（均位于 apps/macos/Sources/SluiceApp/） | 扫描结论 |
| --- | --- |
| API.swift | 数据/API 客户端，无交互控件 |
| ActiveRequestsView.swift | 活动连接、右键菜单、确认框及按钮 |
| ActivityView.swift | 活动控制、跳页事实卡片和排行切换 |
| ConfigDraft.swift | 草稿状态，无交互控件 |
| ConfigProfilesView.swift | 本地配置行、菜单和命名表单 |
| Core.swift | 动作实现与状态，无控件声明；用于核对预期行为 |
| DNSView.swift | 搜索、刷新、清空、复制菜单与空状态动作 |
| DiagnosticsExport.swift | 导出实现，无控件声明 |
| E2ELaunch.swift | CI 参数与附着状态，无控件声明 |
| Helper.swift | 辅助程序状态和动态中文动作标签，无控件声明 |
| Latency.swift | 延迟分类，无交互控件 |
| LiveAPI.swift | 事件/API 数据，无交互控件 |
| MaintenanceSettingsView.swift | 更新、helper、诊断按钮 |
| MenuBar.swift | 全部菜单栏菜单、开关、按钮和快捷键 |
| NodeBrowser.swift | 节点列表、菜单、三个 sheet、详情动作 |
| ProfileStore.swift | 配置文件管理，无交互控件 |
| SluiceApp.swift | Window、CommandGroup、MenuBarExtra 入口 |
| StructuredConfig.swift | 结构化配置数据，无交互控件 |
| StructuredConfigEditors.swift | 两类编辑表、手势、菜单、sheet及表单 |
| System.swift | 系统代理实现，无控件声明 |
| TrafficStats.swift | 统计数据，无交互控件 |
| TrafficStatsView.swift | 策略 Picker 与启动空状态动作 |
| Updater.swift | 共享检查更新按钮 |
| Views.swift | 主窗口、共享控件、设置、策略、请求、规则、日志、配置及 NSTextView |

当前没有 `SecureField`、SwiftUI `TextEditor`、`Stepper`、`.alert`、`.onDelete`、`.onMove`、`swipeActions`、显式拖放 API、`NavigationSplitView`、`NavigationLink` 或 `CommandMenu`。侧栏用自定义 Button，排序/删除用按钮，配置文本编辑用 AppKit `NSTextView`，均已列入。`.confirmationDialog` 的 SwiftUI 自动取消项也单列。系统自动生成的标准应用菜单和 Sparkle 内部窗口不属于这些文件声明的控件；已列出自定义应用菜单命令及调用入口。

### 全局、侧栏与共享交互

| ID | 页面 | 控件（界面显示的中文标签） | 源码 file:line | 预期行为 | 需外网 | 测试方法 | 结果 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| G-001 | 主窗口侧栏 | 活动／请求／策略／节点／规则／日志／DNS 缓存／配置（ForEach 模板） | `apps/macos/Sources/SluiceApp/Views.swift:125`<br>`apps/macos/Sources/SluiceApp/Views.swift:108` | 点击对应项切换页面并显示选中态；八个标签均可达 | 否 | 逐项点击，核对页面标题；往返配置页保留未保存草稿 |  |
| G-002 | 主窗口侧栏 | 设置（固定项） | `apps/macos/Sources/SluiceApp/Views.swift:115`<br>`apps/macos/Sources/SluiceApp/Views.swift:125` | 打开设置页；固定在侧栏底部 | 否 | 点击底部设置，确认与上方八项独立 |  |
| G-003 | 主窗口快捷键 | 切换页面（隐藏 Button，ForEach 模板） | `apps/macos/Sources/SluiceApp/Views.swift:198` | 按侧栏顺序切换到对应页面 | 否 | 触发隐藏按钮对应的九个键位，检查选择态 |  |
| G-004 | 主窗口快捷键 | ⌘1…⌘9 | `apps/macos/Sources/SluiceApp/Views.swift:199` | 依次打开活动、请求、策略、节点、规则、日志、DNS 缓存、配置、设置 | 否 | 逐一按键，包括编辑器有焦点时 |  |
| G-005 | 主窗口异常提示 | 关闭系统代理 | `apps/macos/Sources/SluiceApp/Views.swift:216` | 内核停止但系统代理开启时可关闭代理并消除警告 | 否 | 需无Surge机器；构造代理开启、内核停止状态，点击后核对系统代理恢复 |  |
| G-006 | 主窗口异常提示 | 启动 Sluice | `apps/macos/Sources/SluiceApp/Views.swift:217` | 启动内核并解除无监听端口的代理警告 | 否 | 需无Surge机器；仅用本地配置重现警告，启动后访问本地 HTTP 服务 |  |
| G-007 | 主窗口工具栏 | 系统代理 | `apps/macos/Sources/SluiceApp/Views.swift:246`<br>`apps/macos/Sources/SluiceApp/Views.swift:386` | 切换系统 HTTP/HTTPS/SOCKS 代理；未配置监听地址时禁用；异常状态显示警告 | 否 | 需无Surge机器；开启、关闭，核对 networksetup 与恢复行为 |  |
| G-008 | 主窗口工具栏 | 增强模式 | `apps/macos/Sources/SluiceApp/Views.swift:404`<br>`apps/macos/Sources/SluiceApp/Views.swift:386` | 切换增强模式；忙碌期间禁用，失败显示错误 | 否 | 需无Surge机器；测试管理员授权、取消、开启/关闭与路由/DNS恢复；启动自检可能访问 apple.com |  |
| G-009 | 活动／侧栏底部 | 停止 | `apps/macos/Sources/SluiceApp/Views.swift:442`<br>`apps/macos/Sources/SluiceApp/Views.swift:429`<br>`apps/macos/Sources/SluiceApp/ActivityView.swift:104` | 运行或启动状态显示停止；点击停止内核 | 否 | 本地配置启动后停止，核对端口释放；涉及系统代理或 TUN 时需无Surge机器 |  |
| G-010 | 活动／侧栏底部 | 启动 | `apps/macos/Sources/SluiceApp/Views.swift:446`<br>`apps/macos/Sources/SluiceApp/Views.swift:429`<br>`apps/macos/Sources/SluiceApp/ActivityView.swift:104` | 停止时显示启动；图标版与文字版行为一致 | 否 | 本地配置启动，核对状态、端口和启动失败提示；涉及系统代理或 TUN 时需无Surge机器 |  |
| G-011 | 主窗口错误横幅 | 关闭（×） | `apps/macos/Sources/SluiceApp/Views.swift:476` | 清除 lastActionError 并隐藏横幅 | 否 | 用无效配置触发错误，点击关闭，后续错误仍可显示 |  |
| G-012 | 共享搜索框 | 搜索输入（各页面的提示词见对应行） | `apps/macos/Sources/SluiceApp/Views.swift:628` | 输入绑定到页面筛选；空值显示提示词 | 否 | 输入中文、大小写、空格、无匹配内容，再清空 |  |
| G-013 | 共享搜索框 | 清除搜索（×） | `apps/macos/Sources/SluiceApp/Views.swift:633` | 非空时显示；点击清空搜索文本 | 否 | 各搜索页输入内容后点击，检查完整列表恢复 |  |
| G-014 | 共享搜索框 | 搜索（隐藏 Button） | `apps/macos/Sources/SluiceApp/Views.swift:638` | 将焦点移至当前页面搜索框 | 否 | 从列表区域触发，输入后确认作用于当前页 |  |
| G-015 | 共享搜索框 | ⌘F | `apps/macos/Sources/SluiceApp/Views.swift:638` | 聚焦当前页面的搜索框 | 否 | 在节点、策略、请求、规则、日志、DNS 页分别按 ⌘F |  |
| G-016 | 共享搜索框 | Esc（退出搜索） | `apps/macos/Sources/SluiceApp/Views.swift:630` | 清空搜索并移除焦点 | 否 | 输入后按 Esc，核对筛选与焦点恢复 |  |
| G-017 | 共享分段控件 | 分段选项（ForEach 模板） | `apps/macos/Sources/SluiceApp/Views.swift:660` | 点击标题更新 selection 并移动选中标识 | 否 | 遍历对应页面行列出的全部选项；禁用时点击无效 |  |
| G-018 | 添加节点／订阅／配置命名 | 多行输入（分享链接或代理行） | `apps/macos/Sources/SluiceApp/Views.swift:1334` | 多行文本绑定到表单，显示 4–8 行 | 否 | 粘贴长文本、换行、清空，核对不被截断；具体提交见表单行 |  |
| G-019 | 添加订阅／配置命名 | 单行输入（标签见各表单行） | `apps/macos/Sources/SluiceApp/Views.swift:1340` | 单行输入绑定对应字段并显示占位词 | 否 | 测试中文、空值、长字符串；逐个字段核对绑定 |  |
| G-020 | 添加节点／订阅／配置命名 | 取消（共享页脚） | `apps/macos/Sources/SluiceApp/Views.swift:1366` | 关闭当前 sheet，取消尚未提交的表单 | 否 | 分别在三个表单修改后取消，核对磁盘配置未变 |  |
| G-021 | 添加节点／订阅／配置命名 | Esc（取消） | `apps/macos/Sources/SluiceApp/Views.swift:1366` | 触发页脚的取消动作 | 否 | 三个表单内分别按 Esc |  |
| G-022 | 添加节点／订阅／配置命名 | 主操作（添加／保存，共享页脚） | `apps/macos/Sources/SluiceApp/Views.swift:1367` | 调用对应表单提交；enabled 为 false 时禁用 | 否 | 具体成功/失败、网络与机器要求见各表单提交行 |  |
| G-023 | 共享错误详情 | 复制示例 | `apps/macos/Sources/SluiceApp/Views.swift:1660` | 格式错误且有示例时复制正确示例 | 否 | 在添加节点输入缺少等号的内容，点击复制并粘贴比对 |  |
| G-024 | 共享错误详情 | 详细信息（DisclosureGroup） | `apps/macos/Sources/SluiceApp/Views.swift:1670` | 多行错误可展开／折叠原始详情 | 否 | 触发含两行以上的校验错误，展开、选中复制、折叠 |  |
| G-025 | 共享空状态 | 主操作按钮（标签见各页面行） | `apps/macos/Sources/SluiceApp/Views.swift:1704` | 仅 action 非空时出现并执行页面指定动作 | 否 | 逐个触发下列启动、重试、清除筛选、添加等空状态入口 |  |
| G-026 | 共享空状态 | 次操作按钮（添加节点） | `apps/macos/Sources/SluiceApp/Views.swift:1705`<br>`apps/macos/Sources/SluiceApp/NodeBrowser.swift:97` | 节点空列表提供次操作，打开添加节点 sheet | 否 | 清空测试配置的节点列表，点击次操作 |  |

### 活动与统计

| ID | 页面 | 控件（界面显示的中文标签） | 源码 file:line | 预期行为 | 需外网 | 测试方法 | 结果 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| G-027 | 活动 | 重载配置 | `apps/macos/Sources/SluiceApp/ActivityView.swift:93` | 运行中重载配置，显示进度，停止或正在重载时禁用 | 否 | 编辑本地规则后点击；检查无效配置报错且旧路由仍有效；TUN 配置需无Surge机器 |  |
| G-028 | 活动 | 重启内核 | `apps/macos/Sources/SluiceApp/ActivityView.swift:100` | 活动状态可重启，停止时禁用 | 否 | 本地配置重启，核对状态与端口；涉及系统代理或增强模式时需无Surge机器 |  |
| G-029 | 活动／无节点提示 | 添加节点 | `apps/macos/Sources/SluiceApp/ActivityView.swift:112` | 切到节点页并自动打开添加节点 sheet | 否 | 无节点配置下点击，核对目标页面和弹窗 |  |
| G-030 | 活动／无节点提示 | 添加订阅 | `apps/macos/Sources/SluiceApp/ActivityView.swift:113` | 切到节点页并自动打开添加订阅 sheet | 否 | 无节点配置下点击，取消后再次进入 |  |
| G-031 | 活动／路由概览 | 出站模式 | `apps/macos/Sources/SluiceApp/ActivityView.swift:123`<br>`apps/macos/Sources/SluiceApp/ActivityView.swift:155` | 打开策略页 | 否 | 点击整个事实卡片，检查策略页选中 |  |
| G-032 | 活动／路由概览 | 当前节点 | `apps/macos/Sources/SluiceApp/ActivityView.swift:128`<br>`apps/macos/Sources/SluiceApp/ActivityView.swift:155` | 有节点时打开策略页，无节点时打开节点页 | 否 | 使用无节点配置验证节点页；有真实节点的分支需无Surge机器 |  |
| G-033 | 活动／路由概览 | 系统代理 | `apps/macos/Sources/SluiceApp/ActivityView.swift:131`<br>`apps/macos/Sources/SluiceApp/ActivityView.swift:155` | 点击打开设置页 | 否 | 普通与警告文案下点击均进入设置；制造系统代理警告需无Surge机器 |  |
| G-034 | 活动／请求排行 | 域名 | `apps/macos/Sources/SluiceApp/ActivityView.swift:243`<br>`apps/macos/Sources/SluiceApp/ActivityView.swift:284` | 按目标主机统计前三项 | 否 | 本地请求产生不同目标记录，切换并核对数量和排序 |  |
| G-035 | 活动／请求排行 | 策略 | `apps/macos/Sources/SluiceApp/ActivityView.swift:245`<br>`apps/macos/Sources/SluiceApp/ActivityView.swift:284` | 按策略统计前三项 | 否 | DIRECT/REJECT 规则产生记录，核对排行分组变化 |  |
| G-036 | 活动／请求排行 | 全部请求 | `apps/macos/Sources/SluiceApp/ActivityView.swift:247` | 打开请求页 | 否 | 有无请求时点击入口，核对页面 |  |
| G-037 | 活动／统计 | 策略（全部流量／策略名称，ForEach 模板） | `apps/macos/Sources/SluiceApp/TrafficStatsView.swift:87` | 切换最近十分钟曲线；统计不可用或回退时禁用；策略消失后恢复全部流量 | 否 | 用两个仅含 DIRECT/REJECT 的策略组产生本地流量，切换筛选；测试旧内核回退和策略删除 |  |
| G-038 | 活动／统计空状态 | 启动 Sluice | `apps/macos/Sources/SluiceApp/TrafficStatsView.swift:57` | 未活动时启动内核；启动中不显示该动作 | 否 | 本地配置测试停止→启动；涉及系统代理或 TUN 时需无Surge机器 |  |

### 设置

| ID | 页面 | 控件（界面显示的中文标签） | 源码 file:line | 预期行为 | 需外网 | 测试方法 | 结果 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| G-039 | 设置／网络接管 | 系统代理 | `apps/macos/Sources/SluiceApp/Views.swift:959`<br>`apps/macos/Sources/SluiceApp/Views.swift:1064` | 切换系统代理，卡片状态与工具栏同步；无入站监听时禁用 | 否 | 需无Surge机器；用本地监听开启/关闭，核对所有网络服务及退出恢复 |  |
| G-040 | 设置／增强模式 | 增强模式 | `apps/macos/Sources/SluiceApp/Views.swift:976`<br>`apps/macos/Sources/SluiceApp/Views.swift:1064` | 写入增强模式设置，按需重启／授权，忙碌时禁用 | 否 | 需无Surge机器；测试管理员批准、取消和失败；核对 TUN、路由、DNS恢复；启动自检可能访问外网 |  |
| G-041 | 设置／增强模式辅助程序 | 安装辅助程序／打开系统设置／刷新状态／重试（状态按钮） | `apps/macos/Sources/SluiceApp/MaintenanceSettingsView.swift:63`<br>`apps/macos/Sources/SluiceApp/Helper.swift:34` | 按未安装、待批准、就绪、失败状态注册、打开登录项或刷新状态 | 否 | 需无Surge机器；完整 app 覆盖四状态及未打包构建错误，确认后台服务状态 |  |
| G-042 | 设置／当前配置 | 显示文件 | `apps/macos/Sources/SluiceApp/Views.swift:1004` | Finder 显示当前配置文件 | 否 | 切换本地配置后点击，核对选中的确切路径 |  |
| G-043 | 设置／代理服务 | 复制 HTTP 地址 | `apps/macos/Sources/SluiceApp/Views.swift:1010` | 复制 http://host:port，IPv6 加方括号；未配置时隐藏 | 否 | 用 IPv4/IPv6 本地监听配置，粘贴核对；无需设置系统代理 |  |
| G-044 | 设置／代理服务 | 复制 SOCKS5 地址 | `apps/macos/Sources/SluiceApp/Views.swift:1015` | 复制 socks5://host:port，IPv6 加方括号；未配置时隐藏 | 否 | 用本地监听配置，复制比对 |  |
| G-045 | 设置／通用 | 打开应用时启动 | `apps/macos/Sources/SluiceApp/Views.swift:1023`<br>`apps/macos/Sources/SluiceApp/Views.swift:1064` | 保存自动启动偏好，后续打开主窗口时按偏好启动内核 | 否 | 仅本地配置测试关闭/开启和重开应用；涉及系统代理或 TUN 时需无Surge机器 |  |
| G-046 | 设置／通用 | 登录时打开 | `apps/macos/Sources/SluiceApp/Views.swift:1131`<br>`apps/macos/Sources/SluiceApp/Views.swift:1064` | 注册／注销 SMAppService 登录项并反映错误和待批准状态 | 否 | 完整 app 切换后核对登录项和实际登录启动；仅使用本地配置；若启动会接管网络，需无Surge机器 |  |
| G-047 | 设置／软件更新 | 检查更新… | `apps/macos/Sources/SluiceApp/MaintenanceSettingsView.swift:29` | 打开 Sparkle 更新流程；未打包、未配置或检查中按 canCheck 禁用 | 是 | 完整 app 验证更新渠道、无更新、有更新、失败、上次检查时间；开发构建只核对禁用态 |  |
| G-048 | 设置／外观 | 跟随系统／浅色／深色（ForEach 模板） | `apps/macos/Sources/SluiceApp/Views.swift:1085`<br>`apps/macos/Sources/SluiceApp/Views.swift:660` | 切换窗口色彩并持久化偏好 | 否 | 遍历三项，重开应用核对，跟随系统时切换 macOS 外观 |  |
| G-049 | 设置／菜单栏 | 菜单栏显示（显示图标和实时速度／仅显示图标／仅显示实时速度） | `apps/macos/Sources/SluiceApp/Views.swift:1106` | 改变状态栏展示模式并持久化 | 否 | 逐项选择并产生本地流量，检查图标／速度布局 |  |
| G-050 | 设置／菜单栏 | 显示当前的出站模式 | `apps/macos/Sources/SluiceApp/Views.swift:1115` | 显示／隐藏 R/D/G 模式标记 | 否 | 切换并用仅 DIRECT/REJECT 的策略改变模式，核对菜单栏同步 |  |
| G-051 | 设置／菜单栏 | 未启用系统代理和增强模式时，将图标显示为灰色 | `apps/macos/Sources/SluiceApp/Views.swift:1116` | 控制闲置图标灰显；仅速度模式时禁用 | 否 | 本地环境仅测未接管灰显及禁用；启用系统代理/TUN 的对照需无Surge机器 |  |
| G-052 | 设置／诊断信息 | 导出诊断信息…／正在导出… | `apps/macos/Sources/SluiceApp/MaintenanceSettingsView.swift:134` | 导出本地脱敏 ZIP，导出中禁用；显示成功路径或失败原因 | 否 | 隔离日志目录；停止/运行内核各测一次，解压核对脱敏与 API 404 回退；TUN/系统代理快照对照需无Surge机器 |  |
| G-053 | 设置／诊断信息 | 在 Finder 中显示 | `apps/macos/Sources/SluiceApp/MaintenanceSettingsView.swift:156` | 成功导出后显示 ZIP 文件 | 否 | 导出后点击，核对 Finder 选中该 ZIP |  |

### 策略

| ID | 页面 | 控件（界面显示的中文标签） | 源码 file:line | 预期行为 | 需外网 | 测试方法 | 结果 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| G-054 | 策略 | 直接连接／全局代理／规则判定（ForEach 模板） | `apps/macos/Sources/SluiceApp/Views.swift:1163`<br>`apps/macos/Sources/SluiceApp/Views.swift:660` | 调用控制 API 切换 mode，停止时禁用 | 否 | 仅 DIRECT/REJECT 配置下遍历三模式，对照 /v1/mode 与本地 route 结果 |  |
| G-055 | 策略 | 搜索策略组或节点 | `apps/macos/Sources/SluiceApp/Views.swift:1189`<br>`apps/macos/Sources/SluiceApp/Views.swift:628` | 按组名或选项名筛选组和节点 | 否 | 搜索组名、DIRECT、无匹配文本，检查组内筛选和清空 |  |
| G-056 | 策略／无策略组 | 启动 Sluice | `apps/macos/Sources/SluiceApp/Views.swift:1177`<br>`apps/macos/Sources/SluiceApp/Views.swift:1704` | 内核不活动时启动并加载策略组 | 否 | 本地配置测试启动与加载；若涉及系统代理或 TUN，需无Surge机器 |  |
| G-057 | 策略／搜索空状态 | 清除搜索 | `apps/macos/Sources/SluiceApp/Views.swift:1180`<br>`apps/macos/Sources/SluiceApp/Views.swift:1704` | 清空搜索，恢复策略列表 | 否 | 输入无匹配关键字后点击 |  |
| G-058 | 节点／策略 | 测试全部／测试中…（共享按钮） | `apps/macos/Sources/SluiceApp/Views.swift:513`<br>`apps/macos/Sources/SluiceApp/NodeBrowser.swift:62`<br>`apps/macos/Sources/SluiceApp/Views.swift:1171` | 并发测试所有策略组，显示进度；停止、无组或测试中禁用，切页共享进度 | 否 | 所有组 url 指向本地 HTTP 服务，DIRECT 成功、REJECT 失败；默认外网 URL 或真实节点测试需无Surge机器且需外网 |  |
| G-059 | 策略／策略组 | 测试／测试中…（ForEach 模板） | `apps/macos/Sources/SluiceApp/Views.swift:1239` | 测试当前组全部选项，更新延迟和自动组选择 | 否 | 组 url 指向 http://127.0.0.1:18080/；覆盖手动、自动、fallback、load-balance；真实节点或默认外网 URL 需无Surge机器 |  |
| G-060 | 策略／选项 | 节点／选项名称（ForEach 模板） | `apps/macos/Sources/SluiceApp/Views.swift:1269` | 手动组点击切换选择；当前选择不重复提交；自动组只读 | 否 | 组含 DIRECT/REJECT，切换后对照 API；停止禁用，自动组不可切换 |  |
| G-061 | 策略／选项右键 | 节点选项 contextMenu（ForEach 模板） | `apps/macos/Sources/SluiceApp/Views.swift:1261` | 打开当前选项的测试菜单 | 否 | 右键 DIRECT/REJECT 选项，确认测试项和禁用态 |  |
| G-062 | 策略／选项右键 | 测试节点／测试中…（ForEach 模板） | `apps/macos/Sources/SluiceApp/Views.swift:1262` | 用默认测试 URL 测单个节点，显示共享测试状态 | 是 | 需无Surge机器；GUI 不传 url，默认访问 gstatic；本地仅测 REJECT 失败或测试中禁用态，不能冒充公网成功 |  |

### 节点、订阅与详情

| ID | 页面 | 控件（界面显示的中文标签） | 源码 file:line | 预期行为 | 需外网 | 测试方法 | 结果 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| G-063 | 节点 | 刷新列表 | `apps/macos/Sources/SluiceApp/NodeBrowser.swift:61` | 从磁盘重新读取节点/订阅并刷新摘要 | 否 | 修改本地配置后点击，对照列表数和显示字段 |  |
| G-064 | 节点 | 添加节点 | `apps/macos/Sources/SluiceApp/NodeBrowser.swift:63` | 请求打开添加节点表单 | 否 | 点击并核对标题、字段和按钮 |  |
| G-065 | 节点 | 添加订阅 | `apps/macos/Sources/SluiceApp/NodeBrowser.swift:64` | 请求打开添加订阅表单 | 否 | 点击并核对标题和四个字段 |  |
| G-066 | 节点 | 全部／节点／订阅（ForEach 模板） | `apps/macos/Sources/SluiceApp/NodeBrowser.swift:67`<br>`apps/macos/Sources/SluiceApp/Views.swift:660` | 按类别筛选记录 | 否 | 无节点及 file:// 订阅配置遍历三项；真实节点列表分支需无Surge机器 |  |
| G-067 | 节点 | 名称、协议或服务器 | `apps/macos/Sources/SluiceApp/NodeBrowser.swift:71`<br>`apps/macos/Sources/SluiceApp/Views.swift:628` | 按名称、类型、端点、传输方式搜索 | 否 | 本地订阅记录搜索，检查大小写、空值和无匹配 |  |
| G-068 | 节点列表 | 节点／订阅名称行（ForEach 模板） | `apps/macos/Sources/SluiceApp/NodeBrowser.swift:77` | 点击记录打开其详情 | 否 | 以本地 file:// 订阅验证详情；真实节点详情检查需无Surge机器 |  |
| G-069 | 节点列表右键 | 节点 contextMenu（ForEach 模板） | `apps/macos/Sources/SluiceApp/NodeBrowser.swift:81` | 展示详情、测速、复制名称、复制服务器 | 否 | 右键本地订阅记录，检查四项与运行态禁用条件 |  |
| G-070 | 节点列表右键 | 查看详情（ForEach 模板） | `apps/macos/Sources/SluiceApp/NodeBrowser.swift:82` | 打开对应记录的详情 sheet | 否 | 点击后核对名称与原记录一致 |  |
| G-071 | 节点列表右键 | 测试节点／测试中…（ForEach 模板） | `apps/macos/Sources/SluiceApp/NodeBrowser.swift:83` | 运行时测速，测试中禁用；错误显示到全局反馈 | 是 | 需无Surge机器；真实节点与默认外网 URL 成功/失败；本地订阅组仅 REJECT 可测无外网失败 |  |
| G-072 | 节点列表右键 | 复制名称（ForEach 模板） | `apps/macos/Sources/SluiceApp/NodeBrowser.swift:85` | 复制选中记录名称 | 否 | 复制带中文/空格的本地订阅名称并比对 |  |
| G-073 | 节点列表右键 | 复制服务器（ForEach 模板） | `apps/macos/Sources/SluiceApp/NodeBrowser.swift:86` | 复制显示端点；订阅不泄露完整 URL 凭据 | 否 | 使用 file:// 订阅，粘贴核对本地订阅文件文案 |  |
| G-074 | 节点／空列表 | 添加订阅 | `apps/macos/Sources/SluiceApp/NodeBrowser.swift:97`<br>`apps/macos/Sources/SluiceApp/Views.swift:1704` | 打开订阅表单 | 否 | 空配置点击主操作，取消后列表不变 |  |
| G-075 | 节点／空列表 | 添加节点 | `apps/macos/Sources/SluiceApp/NodeBrowser.swift:97`<br>`apps/macos/Sources/SluiceApp/Views.swift:1705` | 打开节点表单 | 否 | 空配置点击次操作 |  |
| G-076 | 节点／无搜索结果 | 清除筛选 | `apps/macos/Sources/SluiceApp/NodeBrowser.swift:100`<br>`apps/macos/Sources/SluiceApp/Views.swift:1704` | 清空搜索并将类别恢复全部 | 否 | 订阅类别输入无匹配关键字，点击核对两个状态均重置 |  |
| G-077 | 节点／sheet | 添加节点 | `apps/macos/Sources/SluiceApp/NodeBrowser.swift:106` | showAddNode 触发 sheet；关闭后刷新列表 | 否 | 分别经顶部和活动页入口打开，取消后核对刷新 |  |
| G-078 | 节点／sheet | 添加订阅 | `apps/macos/Sources/SluiceApp/NodeBrowser.swift:107` | showAddSub 触发 sheet；关闭后刷新列表 | 否 | 经顶部/空状态打开，提交本地订阅或取消，核对刷新 |  |
| G-079 | 节点／sheet | 节点名称／订阅信息（详情） | `apps/macos/Sources/SluiceApp/NodeBrowser.swift:108` | selected 触发对应详情弹窗 | 否 | 打开本地订阅详情，核对显示类型、过滤、更新间隔且无凭据 |  |
| G-080 | 添加节点 | 分享链接或代理行 | `apps/macos/Sources/SluiceApp/Views.swift:1384`<br>`apps/macos/Sources/SluiceApp/Views.swift:1334` | 接受分享链接或代理行多行输入 | 否 | 本地只输入空值、缺少等号、未知类型等无效文本验证状态；真实节点配置测试需无Surge机器 |  |
| G-081 | 添加节点 | 添加／检查中… | `apps/macos/Sources/SluiceApp/Views.swift:1387`<br>`apps/macos/Sources/SluiceApp/Views.swift:1367` | 转换链接、校验配置后保存，成功关闭，失败保留表单和错误；自动处理重名 | 是 | 本地仅测空值禁用和无效输入不改盘；成功导入真实节点及运行应用需无Surge机器，公网节点连通性需外网 |  |
| G-082 | 添加节点 | 取消 | `apps/macos/Sources/SluiceApp/Views.swift:1387`<br>`apps/macos/Sources/SluiceApp/Views.swift:1366` | 关闭表单而不提交 | 否 | 输入无效草稿后取消，核对配置未变 |  |
| G-083 | 添加订阅 | 订阅地址 | `apps/macos/Sources/SluiceApp/Views.swift:1413`<br>`apps/macos/Sources/SluiceApp/Views.swift:1340` | 接受 http://、https://、file://；无效协议提交时报错 | 否 | 测试 file:// 本地文件、loopback HTTP 地址和无效协议；公网地址需无Surge机器 |  |
| G-084 | 添加订阅 | 名称 | `apps/macos/Sources/SluiceApp/Views.swift:1415`<br>`apps/macos/Sources/SluiceApp/Views.swift:1340` | 留空默认 Subscription；同名自动生成唯一名称 | 否 | 用本地订阅测试留空、中文名称、重复名称 |  |
| G-085 | 添加订阅 | 名称过滤（正则，可选） | `apps/macos/Sources/SluiceApp/Views.swift:1416`<br>`apps/macos/Sources/SluiceApp/Views.swift:1340` | 保存 policy-regex-filter；非法正则导致校验失败 | 否 | 本地 DIRECT/REJECT 订阅测试空值、合法与非法正则；成功筛选真实节点需无Surge机器 |  |
| G-086 | 添加订阅 | User-Agent（可选） | `apps/macos/Sources/SluiceApp/Views.swift:1418`<br>`apps/macos/Sources/SluiceApp/Views.swift:1340` | 留空用默认值；自定义值写入配置；拒绝换行或双引号 | 否 | loopback HTTP 服务记录请求头，提交普通值、引号、换行，核对报错 |  |
| G-087 | 添加订阅 | 添加／下载中… | `apps/macos/Sources/SluiceApp/Views.swift:1419`<br>`apps/macos/Sources/SluiceApp/Views.swift:1367` | 下载或读本地文件，校验成功后保存组并关闭；失败不改配置 | 否 | file:// 与本地 http.server 提供仅 DIRECT/REJECT 的订阅，验证零节点回退 REJECT；损坏/不存在文件测试失败；公网订阅需无Surge机器且需外网 |  |
| G-088 | 添加订阅 | 取消 | `apps/macos/Sources/SluiceApp/Views.swift:1419`<br>`apps/macos/Sources/SluiceApp/Views.swift:1366` | 关闭未提交表单 | 否 | 填满四字段后取消，核对磁盘和策略组未变 |  |
| G-089 | 节点详情 | 复制服务器 | `apps/macos/Sources/SluiceApp/NodeBrowser.swift:204` | 复制详情显示的端点 | 否 | 本地订阅详情复制核对；节点 IPv6 端点显示检查需无Surge机器 |  |
| G-090 | 节点详情 | 测试节点／测试中… | `apps/macos/Sources/SluiceApp/NodeBrowser.swift:205` | 运行时调用默认 URL 测试并显示连接耗时、响应延迟、实际出站、状态或错误 | 是 | 需无Surge机器；公网节点测试成功/失败；本地 REJECT 仅覆盖失败和停止时禁用 |  |
| G-091 | 节点详情 | 完成 | `apps/macos/Sources/SluiceApp/NodeBrowser.swift:208` | 关闭详情 sheet | 否 | 打开详情后点击完成 |  |
| G-092 | 节点详情 | Esc（完成） | `apps/macos/Sources/SluiceApp/NodeBrowser.swift:208` | 键盘关闭详情 sheet | 否 | 详情内按 Esc，核对返回原筛选列表 |  |

### 最近请求与活动连接

| ID | 页面 | 控件（界面显示的中文标签） | 源码 file:line | 预期行为 | 需外网 | 测试方法 | 结果 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| G-093 | 请求 | 最近／活动（ForEach 模板） | `apps/macos/Sources/SluiceApp/Views.swift:1465`<br>`apps/macos/Sources/SluiceApp/Views.swift:660` | 切换最近决策列表与活动 TCP 连接列表 | 否 | 建立 loopback 请求及长连接，切换后核对标题数量和对应列表 |  |
| G-094 | 请求／最近 | 全部／代理／直连／拒绝（ForEach 模板） | `apps/macos/Sources/SluiceApp/Views.swift:1472`<br>`apps/macos/Sources/SluiceApp/Views.swift:660` | 按最终出站筛选最近请求 | 否 | DIRECT/REJECT 本地请求覆盖全部/直连/拒绝；代理项本地为空，真实代理分支需无Surge机器 |  |
| G-095 | 请求／最近 | 目标、进程、策略或出站 | `apps/macos/Sources/SluiceApp/Views.swift:1475`<br>`apps/macos/Sources/SluiceApp/Views.swift:628` | 筛选对应字段并更新计数 | 否 | 本地请求记录测试目标、进程、规则/策略与出站关键字 |  |
| G-096 | 请求／最近 | 暂停更新／继续更新 | `apps/macos/Sources/SluiceApp/Views.swift:1476` | 暂停时冻结快照，网络继续；恢复显示最新列表 | 否 | 持续发本地请求，暂停时核对列表稳定、API计数增长，再继续 |  |
| G-097 | 请求／最近 | 清除 | `apps/macos/Sources/SluiceApp/Views.swift:1481` | 清空应用最近列表、冻结快照和选择；空列表禁用 | 否 | 暂停/未暂停各清除一次；保持本地连接，核对没有断流 |  |
| G-098 | 请求／最近 | 请求目标行（ForEach 模板） | `apps/macos/Sources/SluiceApp/Views.swift:1563`<br>`apps/macos/Sources/SluiceApp/Views.swift:1500` | 选中后更新右侧详情，消失后清除选择 | 否 | 点击两个本地请求，核对目标、规则、策略、时间与选择高亮 |  |
| G-099 | 请求／最近右键 | 请求 contextMenu（ForEach 模板） | `apps/macos/Sources/SluiceApp/Views.swift:1503` | 显示当前记录的复制菜单 | 否 | 右键不同目标，核对菜单作用于被右键记录 |  |
| G-100 | 请求／最近右键 | 复制目标（ForEach 模板） | `apps/macos/Sources/SluiceApp/Views.swift:1504` | 复制请求 target | 否 | 粘贴比对本地目标 host:port |  |
| G-101 | 请求／最近右键 | 复制匹配规则（ForEach 模板） | `apps/macos/Sources/SluiceApp/Views.swift:1505` | 复制命中的 rule 字符串 | 否 | DIRECT/REJECT 两种记录分别复制比对 |  |
| G-102 | 请求／最近空状态 | 启动 Sluice | `apps/macos/Sources/SluiceApp/Views.swift:1515`<br>`apps/macos/Sources/SluiceApp/Views.swift:1704` | 无内核无记录时启动 | 否 | 用本地配置点击，检查端口与列表；系统代理/TUN 场景需无Surge机器 |  |
| G-103 | 请求／最近无匹配 | 清除筛选 | `apps/macos/Sources/SluiceApp/Views.swift:1519`<br>`apps/macos/Sources/SluiceApp/Views.swift:1704` | 清空搜索和出站类别 | 否 | 设置两个筛选后点击，确认完整列表恢复 |  |
| G-104 | 请求／活动 | 全部／代理／直连（ForEach 模板） | `apps/macos/Sources/SluiceApp/ActiveRequestsView.swift:87`<br>`apps/macos/Sources/SluiceApp/Views.swift:660` | 按出站过滤当前打开的 TCP 连接 | 否 | 本地 DIRECT 长连接覆盖全部/直连；代理类别为空，真实代理连接需无Surge机器 |  |
| G-105 | 请求／活动 | 目标、进程或策略链 | `apps/macos/Sources/SluiceApp/ActiveRequestsView.swift:89`<br>`apps/macos/Sources/SluiceApp/Views.swift:628` | 按目标、进程、规则、来源或策略链等记录字段筛选 | 否 | 本地长连接搜索，核对无匹配和清空 |  |
| G-106 | 请求／活动 | 活动连接目标行（ForEach 模板） | `apps/macos/Sources/SluiceApp/ActiveRequestsView.swift:31` | 选择连接并展示详情；记录消失时清除选择 | 否 | 保持两条 loopback TCP 连接，选择切换并让一条自然关闭 |  |
| G-107 | 请求／活动右键 | 连接 contextMenu（ForEach 模板） | `apps/macos/Sources/SluiceApp/ActiveRequestsView.swift:38` | 显示复制和断开命令 | 否 | 右键活动连接与暂停快照中的已关闭记录，核对断开禁用 |  |
| G-108 | 请求／活动右键 | 复制目标（ForEach 模板） | `apps/macos/Sources/SluiceApp/ActiveRequestsView.swift:39` | 复制该连接目标 | 否 | 复制本地连接目标后粘贴核对 |  |
| G-109 | 请求／活动右键 | 复制策略链（ForEach 模板） | `apps/macos/Sources/SluiceApp/ActiveRequestsView.swift:40` | 复制整条 policyChain | 否 | 构造仅含 DIRECT/REJECT 的嵌套选择组，复制并比对链顺序 |  |
| G-110 | 请求／活动右键 | 断开连接（ForEach 模板） | `apps/macos/Sources/SluiceApp/ActiveRequestsView.swift:42` | 仅关闭对应活动连接，已消失或内核停止时禁用 | 否 | 保持两条本地连接，断开一条，另一条继续；对照 API |  |
| G-111 | 请求／活动空状态 | 启动 Sluice | `apps/macos/Sources/SluiceApp/ActiveRequestsView.swift:52`<br>`apps/macos/Sources/SluiceApp/Views.swift:1704` | 停止时启动内核以加载连接 | 否 | 本地配置测试启动；若启用系统代理或 TUN，需无Surge机器 |  |
| G-112 | 请求／活动无匹配 | 清除筛选 | `apps/macos/Sources/SluiceApp/ActiveRequestsView.swift:55`<br>`apps/macos/Sources/SluiceApp/Views.swift:1704` | 清空搜索并恢复全部类别 | 否 | 无匹配条件点击，核对长连接重新出现 |  |
| G-113 | 请求／活动 | 暂停更新／继续更新 | `apps/macos/Sources/SluiceApp/ActiveRequestsView.swift:95` | 冻结列表快照，网络继续运行；恢复时更新列表 | 否 | 暂停后建立/关闭本地连接，对照 API，再恢复 |  |
| G-114 | 请求／活动 | 全部断开（入口） | `apps/macos/Sources/SluiceApp/ActiveRequestsView.swift:100` | 弹出确认对话框；无活动连接或停止时禁用 | 否 | 有两条本地长连接时点击，确认弹窗出现但连接仍存活 |  |
| G-115 | 请求／活动对话框 | 断开全部活动连接？ | `apps/macos/Sources/SluiceApp/ActiveRequestsView.swift:72` | 说明全部 TCP 连接将断开 | 否 | 检查标题、说明、取消与确认两个按钮 |  |
| G-116 | 请求／活动对话框 | 全部断开 | `apps/macos/Sources/SluiceApp/ActiveRequestsView.swift:73` | 调用 API 关闭所有活动连接并刷新 | 否 | 两条本地长连接确认后均断开，API active 列表最终为空 |  |
| G-117 | 请求／活动对话框 | 取消 | `apps/macos/Sources/SluiceApp/ActiveRequestsView.swift:74` | 关闭确认框并保留连接 | 否 | 点击取消，核对两条本地连接均继续传输 |  |
| G-118 | 请求／活动详情 | 断开连接 | `apps/macos/Sources/SluiceApp/ActiveRequestsView.swift:139` | 断开选中连接，过期快照记录时禁用 | 否 | 选择一条本地长连接断开；暂停后自然关闭连接再检查按钮 |  |

### DNS、规则与日志

| ID | 页面 | 控件（界面显示的中文标签） | 源码 file:line | 预期行为 | 需外网 | 测试方法 | 结果 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| G-119 | DNS 缓存 | 域名、类型或解析结果 | `apps/macos/Sources/SluiceApp/DNSView.swift:29`<br>`apps/macos/Sources/SluiceApp/Views.swift:628` | 过滤缓存域名、记录类型和答案 | 否 | 以 loopback DNS fixture 填充 A/AAAA 记录，逐个字段搜索 |  |
| G-120 | DNS 缓存 | 刷新 | `apps/macos/Sources/SluiceApp/DNSView.swift:30` | 取消旧请求循环并重读缓存；停止或忙碌时禁用 | 否 | 本地 DNS 产生记录后点击；请求中切页核对无过期响应覆盖 |  |
| G-121 | DNS 缓存 | 清空缓存 | `apps/macos/Sources/SluiceApp/DNSView.swift:35` | POST flush 后显示清空条数；失败显示错误，停止/忙碌时禁用 | 否 | 本地 DNS 填充后清空，核对列表及反馈；停止 API 触发失败 |  |
| G-122 | DNS 缓存／域名右键 | 域名 contextMenu（行模板） | `apps/macos/Sources/SluiceApp/DNSView.swift:51` | 显示域名复制操作 | 否 | 右键本地 DNS 记录的域名单元格 |  |
| G-123 | DNS 缓存／域名右键 | 复制域名（行模板） | `apps/macos/Sources/SluiceApp/DNSView.swift:51` | 复制该条记录的域名 | 否 | 粘贴核对与缓存记录相同 |  |
| G-124 | DNS 缓存／解析结果右键 | 解析结果 contextMenu（行模板） | `apps/macos/Sources/SluiceApp/DNSView.swift:61` | 显示答案复制操作 | 否 | 右键答案单元格，核对菜单 |  |
| G-125 | DNS 缓存／解析结果右键 | 复制解析结果（行模板） | `apps/macos/Sources/SluiceApp/DNSView.swift:61` | 以逗号分隔复制全部答案 | 否 | 使用多答案本地 DNS 记录，粘贴核对内容与顺序 |  |
| G-126 | DNS 缓存／停止空状态 | 启动 Sluice | `apps/macos/Sources/SluiceApp/DNSView.swift:77`<br>`apps/macos/Sources/SluiceApp/Views.swift:1704` | 启动后自动加载 DNS 缓存，启动中无按钮 | 否 | 本地配置停止→启动，核对自动刷新；TUN/系统代理场景需无Surge机器 |  |
| G-127 | DNS 缓存／读取失败 | 重试 | `apps/macos/Sources/SluiceApp/DNSView.swift:84`<br>`apps/macos/Sources/SluiceApp/Views.swift:1704` | 生成新请求重试读取 | 否 | 断开并恢复 loopback API，点击重试 |  |
| G-128 | DNS 缓存／无匹配 | 清除筛选 | `apps/macos/Sources/SluiceApp/DNSView.swift:87`<br>`apps/macos/Sources/SluiceApp/Views.swift:1704` | 清空搜索恢复缓存列表 | 否 | 无匹配后点击，检查数量恢复 |  |
| G-129 | DNS 缓存／空缓存 | 刷新 | `apps/macos/Sources/SluiceApp/DNSView.swift:91`<br>`apps/macos/Sources/SluiceApp/Views.swift:1704` | 重启缓存读取请求循环 | 否 | 空缓存点击，随后用本地 DNS 生成记录，确认出现 |  |
| G-130 | 规则 | 搜索规则 | `apps/macos/Sources/SluiceApp/Views.swift:1820`<br>`apps/macos/Sources/SluiceApp/Views.swift:628` | 按类型、值或策略名称搜索 | 否 | 本地 DOMAIN、IP-CIDR、FINAL 等规则验证搜索 |  |
| G-131 | 规则 | 在配置中编辑 | `apps/macos/Sources/SluiceApp/Views.swift:1821` | 切到配置页 | 否 | 点击核对配置页和已有草稿保留 |  |
| G-132 | 规则／路由测试 | 测试主机 | `apps/macos/Sources/SluiceApp/Views.swift:1863` | 输入目标后清除旧测试结果 | 否 | 替换默认公网主机为 127.0.0.1:18080 或 .test 精确域名，核对旧结果消失 |  |
| G-133 | 规则／路由测试 | Enter（onSubmit） | `apps/macos/Sources/SluiceApp/Views.swift:1863` | 按回车执行同一 check 操作 | 否 | 本地目标回车；停止时离线预览、运行时 API 判定各一次 |  |
| G-134 | 规则／路由测试 | 测试／测试中… | `apps/macos/Sources/SluiceApp/Views.swift:1870` | 显示匹配规则、策略和出站；空白/进行中禁用；离线提示跳过需解析规则 | 否 | DIRECT/REJECT 规则覆盖命中、FINAL、无匹配、无效目标；避免触发公网 DNS 的规则 |  |
| G-135 | 日志 | 全部／问题（ForEach 模板） | `apps/macos/Sources/SluiceApp/Views.swift:2002`<br>`apps/macos/Sources/SluiceApp/Views.swift:660` | 问题模式仅保留 WARN/ERROR | 否 | 由本地配置错误产生告警，遍历两项核对条数 |  |
| G-136 | 日志 | 搜索 | `apps/macos/Sources/SluiceApp/Views.swift:2004`<br>`apps/macos/Sources/SluiceApp/Views.swift:628` | 按消息或级别筛选 | 否 | 搜索 WARN、已知本地消息与无匹配词 |  |
| G-137 | 日志 | 跟随最新 | `apps/macos/Sources/SluiceApp/Views.swift:2005` | 开启时自动滚到最新日志，关闭后可自由浏览 | 否 | 连续产生本地日志，开关并滚动核对 |  |
| G-138 | 日志 | 导出 | `apps/macos/Sources/SluiceApp/Views.swift:2007` | 打开保存面板导出当前筛选日志；空结果时禁用 | 否 | 筛选部分日志后导出，核对仅包含当前显示行 |  |
| G-139 | 日志 | 清除日志 | `apps/macos/Sources/SluiceApp/Views.swift:2009` | 清空应用日志显示 | 否 | 清除后产生新本地日志，核对列表可继续追加 |  |
| G-140 | 日志／无匹配 | 清除筛选 | `apps/macos/Sources/SluiceApp/Views.swift:2038`<br>`apps/macos/Sources/SluiceApp/Views.swift:1704` | 清空搜索且关闭问题筛选 | 否 | 组合两个过滤条件使结果为空后点击 |  |
| G-141 | 日志／保存面板 | 导出当前显示的 N 条日志（NSSavePanel） | `apps/macos/Sources/SluiceApp/Views.swift:2052` | 展示本地日志保存对话框，默认文件名 Sluice.log | 否 | 点击导出，检查默认名、提示和目录选择 |  |
| G-142 | 日志／保存面板 | 存储为／保存位置（系统标签随语言变化） | `apps/macos/Sources/SluiceApp/Views.swift:2053` | 允许更改文件名与保存目录 | 否 | 在临时目录输入中文文件名，选择位置后检查落盘路径 |  |
| G-143 | 日志／保存面板 | 存储／保存（系统确认按钮） | `apps/macos/Sources/SluiceApp/Views.swift:2055` | 按 UTF-8 写入时间、级别和消息；写入失败显示横幅 | 否 | 保存到临时目录核对内容；不可写位置验证失败提示 |  |
| G-144 | 日志／保存面板 | 取消（系统按钮） | `apps/macos/Sources/SluiceApp/Views.swift:2055` | 退出面板而不写文件 | 否 | 打开后取消，确认目标文件不存在 |  |

### 配置管理与文本编辑

| ID | 页面 | 控件（界面显示的中文标签） | 源码 file:line | 预期行为 | 需外网 | 测试方法 | 结果 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| G-145 | 配置 | 从当前新建… | `apps/macos/Sources/SluiceApp/Views.swift:2086` | 打开从当前草稿新建配置表单；busy 时禁用 | 否 | 修改未保存草稿后点击，核对新建表单说明 |  |
| G-146 | 配置 | 在 Finder 中显示 | `apps/macos/Sources/SluiceApp/Views.swift:2087` | 显示当前激活配置 | 否 | 切换两份本地配置后分别点击并核对路径 |  |
| G-147 | 配置／磁盘变更提示 | 复制草稿 | `apps/macos/Sources/SluiceApp/Views.swift:2091` | 复制当前草稿以保留尚未保存内容 | 否 | 外部修改磁盘配置后点击，粘贴核对仍为编辑器版本 |  |
| G-148 | 配置／磁盘变更提示 | 载入磁盘版本（入口） | `apps/macos/Sources/SluiceApp/Views.swift:2092` | 打开放弃修改确认框 | 否 | 外部更新配置后点击，确认未立即覆盖草稿 |  |
| G-149 | 配置 | 编辑方式（文本／规则／策略组） | `apps/macos/Sources/SluiceApp/Views.swift:2095` | 三个编辑模式共享同一份草稿 | 否 | 切换三模式，验证已编辑内容往返一致，未知行仍保留 |  |
| G-150 | 配置／文本 | 配置编辑区（NSTextView） | `apps/macos/Sources/SluiceApp/Views.swift:2305`<br>`apps/macos/Sources/SluiceApp/Views.swift:2107` | 编辑绑定草稿；纯文本、语法着色、行号、撤销；错误行标红并滚入视图 | 否 | 仅本地 DIRECT/REJECT 配置输入、复制粘贴、撤销/重做、长行/空行/中文，再检查故意错误行 |  |
| G-151 | 配置 | 还原 | `apps/macos/Sources/SluiceApp/Views.swift:2130` | 有变更时请求确认还原；无变更或 busy 时禁用 | 否 | 修改草稿并点击，核对弹窗；无变更时核对禁用 |  |
| G-152 | 配置 | 检查／检查中… | `apps/macos/Sources/SluiceApp/Views.swift:2131` | 校验提交版本而不保存；显示有效或错误；busy 禁用 | 否 | 有效/无效本地配置分别检查，核对磁盘未变、错误定位；远程订阅配置需无Surge机器 |  |
| G-153 | 配置 | 保存／保存并应用／处理中… | `apps/macos/Sources/SluiceApp/Views.swift:2132` | 校验成功后保存；运行时应用；草稿与磁盘冲突、无变更或不可切换状态禁用 | 否 | 本地配置测试停止/运行保存、坏配置不落盘、磁盘冲突保护、保存中继续编辑；TUN/系统代理或公网订阅需无Surge机器 |  |
| G-154 | 配置快捷键 | ⌘S | `apps/macos/Sources/SluiceApp/Views.swift:2132` | 触发相同的保存流程和禁用条件 | 否 | 有效和无变更草稿分别按 ⌘S；本地配置检查落盘；接管网络或公网订阅需无Surge机器 |  |
| G-155 | 配置／还原对话框 | 放弃当前未保存的修改？ | `apps/macos/Sources/SluiceApp/Views.swift:2146` | 要求确认放弃草稿 | 否 | 分别由还原与磁盘提示入口打开 |  |
| G-156 | 配置／还原对话框 | 载入磁盘版本 | `apps/macos/Sources/SluiceApp/Views.swift:2147` | 用当前磁盘文本替换草稿并清理变更状态 | 否 | 草稿和磁盘各有不同标记，确认后核对磁盘版本 |  |
| G-157 | 配置／还原对话框 | 取消（SwiftUI 自动提供） | `apps/macos/Sources/SluiceApp/Views.swift:2146` | 关闭确认框并保留草稿 | 否 | 点系统取消或 Esc，核对草稿不变 |  |
| G-158 | 配置／切换对话框 | 切换配置会放弃当前未保存的修改 | `apps/macos/Sources/SluiceApp/Views.swift:2149` | 未保存草稿切换前显示保护对话框 | 否 | 修改草稿后选另一份本地配置，确认尚未切换 |  |
| G-159 | 配置／切换对话框 | 放弃修改并切换到「配置名」（动态名称） | `apps/macos/Sources/SluiceApp/Views.swift:2152` | 丢弃草稿并切换目标配置 | 否 | 本地两个配置核对选中态、磁盘、运行路由；监听或增强模式改变会重启，接管网络时需无Surge机器 |  |
| G-160 | 配置／切换对话框 | 复制草稿并切换 | `apps/macos/Sources/SluiceApp/Views.swift:2153` | 先复制原草稿，再切换 | 否 | 粘贴核对旧草稿，界面载入新配置；涉及系统代理、TUN 或公网订阅需无Surge机器 |  |
| G-161 | 配置／切换对话框 | 取消（SwiftUI 自动提供） | `apps/macos/Sources/SluiceApp/Views.swift:2149` | 保留原配置和未保存草稿 | 否 | 取消后核对活动配置路径及草稿 |  |
| G-162 | 配置／删除对话框 | 删除「配置名」？（动态名称） | `apps/macos/Sources/SluiceApp/Views.swift:2156` | 显示永久删除说明与确认动作 | 否 | 对非活动测试配置请求删除，核对名称与说明 |  |
| G-163 | 配置／删除对话框 | 删除配置 | `apps/macos/Sources/SluiceApp/Views.swift:2159` | 永久删除非活动配置并刷新列表；错误显示反馈 | 否 | 仅在临时 profiles 中删除复制品；验证权限错误且当前配置仍保留 |  |
| G-164 | 配置／删除对话框 | 取消（SwiftUI 自动提供） | `apps/macos/Sources/SluiceApp/Views.swift:2156` | 取消后保留文件 | 否 | 点击取消或 Esc，检查文件及列表仍在 |  |
| G-165 | 配置／命名 sheet | 从当前新建配置／复制配置／重命名配置 | `apps/macos/Sources/SluiceApp/Views.swift:2168` | 根据 action 打开命名表单；三种标题和初始名称不同 | 否 | 分别从新建、复制、重命名入口打开，检查默认名 |  |
| G-166 | 配置／本地配置 | 刷新配置列表 | `apps/macos/Sources/SluiceApp/ConfigProfilesView.swift:43` | 重读配置目录；busy 时禁用 | 否 | 在临时 profiles 新增/删除 .conf 后刷新 |  |
| G-167 | 配置／本地配置 | 配置名称（ForEach 模板） | `apps/macos/Sources/SluiceApp/ConfigProfilesView.swift:60` | 切换配置；运行时热重载，监听/TUN设置改变按需重启；busy/不可切换时禁用 | 否 | 两份本地配置测试有效切换、坏配置保留原活动状态、草稿确认；接管网络或公网订阅需无Surge机器 |  |
| G-168 | 配置／本地配置 | 「配置名」的操作（…，ForEach 模板） | `apps/macos/Sources/SluiceApp/ConfigProfilesView.swift:77` | 打开该配置操作菜单；busy 时禁用 | 否 | 各行打开，核对操作针对该行 |  |
| G-169 | 配置／本地配置菜单 | 复制…（ForEach 模板） | `apps/macos/Sources/SluiceApp/ConfigProfilesView.swift:78` | 打开复制表单，默认名为原名加“ 副本” | 否 | 复制临时配置，核对使用源文件内容 |  |
| G-170 | 配置／本地配置菜单 | 重命名…（ForEach 模板） | `apps/macos/Sources/SluiceApp/ConfigProfilesView.swift:79` | 打开重命名表单；活动配置不可切换时禁用 | 否 | 对非活动/活动本地配置操作，活动重命名保留未保存草稿；接管网络时需无Surge机器 |  |
| G-171 | 配置／本地配置菜单 | 删除…（ForEach 模板） | `apps/macos/Sources/SluiceApp/ConfigProfilesView.swift:82` | 请求删除确认；当前使用配置禁用 | 否 | 核对活动行禁用，非活动行打开对应确认框 |  |
| G-172 | 配置命名 | 配置名称 | `apps/macos/Sources/SluiceApp/ConfigProfilesView.swift:124`<br>`apps/macos/Sources/SluiceApp/Views.swift:1340` | 编辑本地文件名，自动添加 .conf；busy 时禁用并初始聚焦 | 否 | 测试空名、中文、重名、路径分隔符、已有 .conf，核对错误或规范化结果 |  |
| G-173 | 配置命名 | Enter（onSubmit） | `apps/macos/Sources/SluiceApp/ConfigProfilesView.swift:126` | 调用 save，busy 时防止重复提交 | 否 | 输入有效/重复名称后回车，核对成功关闭或保留错误 |  |
| G-174 | 配置命名 | 保存 | `apps/macos/Sources/SluiceApp/ConfigProfilesView.swift:131`<br>`apps/macos/Sources/SluiceApp/Views.swift:1367` | 提交新建／复制／重命名；空名称或 busy 时禁用 | 否 | 三种 action 分别提交，本地新建包含草稿、复制来自原文件、重命名更新引用；活动增强模式配置需无Surge机器 |  |
| G-175 | 配置命名 | 取消 | `apps/macos/Sources/SluiceApp/ConfigProfilesView.swift:132`<br>`apps/macos/Sources/SluiceApp/Views.swift:1366` | 关闭命名表单，不创建或重命名文件 | 否 | 三种 action 修改名称后各取消一次 |  |

### 规则与策略组结构化编辑

| ID | 页面 | 控件（界面显示的中文标签） | 源码 file:line | 预期行为 | 需外网 | 测试方法 | 结果 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| G-176 | 配置／规则或策略组 | 添加 | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:21` | 打开相应类型的新建表单 | 否 | 在规则、策略组模式各点击一次，检查默认值 |  |
| G-177 | 配置／规则或策略组 | 编辑 | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:22` | 编辑选中行；未选中时禁用 | 否 | 选中本地规则/组再编辑，核对值回填 |  |
| G-178 | 配置／规则或策略组 | 删除 | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:23` | 仅从草稿删除选中行；未选中禁用 | 否 | 两种模式各删一行，核对文本草稿变化而磁盘未变 |  |
| G-179 | 配置／规则或策略组 | 上移 | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:26` | 将选中行向上移动一位；首行或未选中禁用 | 否 | 三行本地配置测中间行和首行，检查注释/未知行保留 |  |
| G-180 | 配置／规则或策略组 | 下移 | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:28` | 将选中行向下移动一位；末行或未选中禁用 | 否 | 测中间行和末行，文本模式核对顺序 |  |
| G-181 | 配置／规则 sheet | 编辑规则 | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:41` | 打开规则表单，提交时校验草稿快照 | 否 | 打开后从其他路径改变草稿，再提交应提示草稿已更新 |  |
| G-182 | 配置／策略组 sheet | 编辑策略组 | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:48` | 打开组表单，检测快照冲突及名称重复 | 否 | 测试重复组名、与内置策略冲突、过期草稿 |  |
| G-183 | 配置／表格行 | 双击行（ForEach 模板） | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:111` | 选择该行并立即打开编辑表单 | 否 | 规则与策略组各双击一行，核对回填对应行 |  |
| G-184 | 配置／表格行 | 单击行（ForEach 模板） | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:112` | 只更新选择态 | 否 | 单击后核对高亮与工具栏启用，未打开 sheet |  |
| G-185 | 配置／表格行右键 | 行 contextMenu（ForEach 模板） | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:113` | 展示该行的编辑操作 | 否 | 右键非当前选中行，核对编辑目标 |  |
| G-186 | 配置／表格行右键 | 编辑（ForEach 模板） | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:113` | 打开被右键行的编辑 sheet | 否 | 规则/组各右键编辑一行 |  |
| G-187 | 配置／结构化空状态 | 添加 | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:126` | 空规则或空组表格打开新建表单 | 否 | 移除对应节所有行后点击 |  |
| G-188 | 编辑规则 | 类型（ForEach 选项模板） | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:173` | 选择支持的规则类型，保留当前未知类型；FINAL 隐藏值输入 | 否 | 遍历 StructuredConfig.Rule.types 的20种类型，核对 FINAL 与 AND/OR/NOT 提示 |  |
| G-189 | 编辑规则 | 值 | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:176` | 编辑非 FINAL 规则值 | 否 | 输入 .test 域名、loopback CIDR、空值及换行，提交检查校验 |  |
| G-190 | 编辑规则 | 策略（ForEach 选项模板） | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:177` | 从现有策略及当前值中选择出站 | 否 | 仅 DIRECT/REJECT/本地组，核对生成文本；未知当前值保留显示 |  |
| G-191 | 编辑规则 | 选项 | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:180` | 编辑如 no-resolve 的附加选项 | 否 | 输入 no-resolve、空值和格式错误后提交 |  |
| G-192 | 编辑规则 | 取消 | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:189` | 关闭表单，不修改草稿 | 否 | 编辑字段后点击取消，对比草稿 |  |
| G-193 | 编辑规则 | Esc（取消） | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:189` | 快捷键执行取消 | 否 | 字段有焦点时按 Esc，核对草稿未变 |  |
| G-194 | 编辑规则 | 更新草稿 | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:190` | 规范化并验证规则，成功只更新草稿；非法值或快照冲突保留错误 | 否 | 测试有效 DOMAIN、FINAL、嵌套条件、空策略、换行/多余逗号，核对落盘前状态 |  |
| G-195 | 编辑规则 | Return（默认操作） | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:197` | 执行更新草稿 | 否 | 有效和无效规则分别用回车提交 |  |
| G-196 | 编辑策略组 | 名称 | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:215` | 编辑组名，提交时去首尾空白并拒绝非法或重复名称 | 否 | 中文、空名、逗号/等号/注释前缀、DIRECT 重名测试 |  |
| G-197 | 编辑策略组 | 类型（ForEach 选项模板） | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:216` | 选择 select、url-test、fallback、load-balance；自动类型显示 URL 和间隔 | 否 | 逐项切换，核对字段出现和原参数保留 |  |
| G-198 | 编辑策略组 | 测试 URL | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:220` | 自动类型可编辑健康检查 URL | 否 | 填写 http://127.0.0.1:18080/；仅更新草稿无需联网，应用外网 URL 需无Surge机器 |  |
| G-199 | 编辑策略组 | 间隔（秒） | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:221` | 自动类型可设置非负整数秒 | 否 | 测试空值、0、600、负数、小数、溢出和文本，提交核对错误 |  |
| G-200 | 编辑策略组 | 添加成员 | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:227` | 打开候选成员菜单；无候选时禁用 | 否 | DIRECT/REJECT 本地候选，添加全部后核对禁用 |  |
| G-201 | 编辑策略组／成员菜单 | 成员名称（ForEach 模板） | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:228` | 追加候选到有序列表；排除自身及已有成员 | 否 | 依次加 DIRECT、REJECT 和本地组，核对候选去重 |  |
| G-202 | 编辑策略组／成员行 | 上移成员（ForEach 模板） | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:241` | 向上交换相邻成员，首项禁用 | 否 | 三个本地成员测试顺序、首项禁用 |  |
| G-203 | 编辑策略组／成员行 | 下移成员（ForEach 模板） | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:243` | 向下交换相邻成员，末项禁用 | 否 | 中间项与末项核对 |  |
| G-204 | 编辑策略组／成员行 | 移除成员（ForEach 模板） | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:245` | 移除该成员并恢复到候选菜单 | 否 | 删除 DIRECT/REJECT 后重新添加，核对不重复 |  |
| G-205 | 编辑策略组 | 取消 | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:253` | 关闭 sheet，放弃表单修改 | 否 | 修改名、类型和成员后取消，对照草稿 |  |
| G-206 | 编辑策略组 | Esc（取消） | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:253` | 快捷键取消 | 否 | 表单内按 Esc，核对草稿不变 |  |
| G-207 | 编辑策略组 | 更新草稿 | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:254` | 验证名称、成员、参数、间隔后更新草稿；无成员且无 policy-path 时拒绝 | 否 | DIRECT/REJECT 组成功；自引用、无成员、重复名、非法间隔失败；file:// 订阅参数保留 |  |
| G-208 | 编辑策略组 | Return（默认操作） | `apps/macos/Sources/SluiceApp/StructuredConfigEditors.swift:254` | 调用同一 submit 操作 | 否 | 合法与非法组各按回车，核对成功关闭或错误保留 |  |

### 菜单栏与应用命令

| ID | 页面 | 控件（界面显示的中文标签） | 源码 file:line | 预期行为 | 需外网 | 测试方法 | 结果 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| G-209 | 菜单栏入口 | Sluice 图标／实时速度（MenuBarExtra） | `apps/macos/Sources/SluiceApp/SluiceApp.swift:49` | 打开常驻菜单；关闭主窗口后仍可访问 | 否 | 关闭主窗口，点击状态项，核对图标/速度三种展示偏好 |  |
| G-210 | 菜单栏 | 停止 Sluice／启动 Sluice | `apps/macos/Sources/SluiceApp/MenuBar.swift:66` | 切换内核运行，starting 时禁用 | 否 | 本地配置启动、停止；系统代理或 TUN 开启时需无Surge机器 |  |
| G-211 | 菜单栏 | 出站模式：当前模式（Menu） | `apps/macos/Sources/SluiceApp/MenuBar.swift:72` | 展开三种模式；停止时禁用 | 否 | 本地内核运行/停止分别打开检查 |  |
| G-212 | 菜单栏／出站模式 | 直接连接／全局代理／规则判定（ForEach 模板） | `apps/macos/Sources/SluiceApp/MenuBar.swift:74` | 选中一种模式并更新勾选，取消勾选不触发切换 | 否 | 仅 DIRECT/REJECT 配置遍历，核对 /v1/mode 与策略页同步 |  |
| G-213 | 菜单栏 | 组名：当前选择（ForEach Menu 模板） | `apps/macos/Sources/SluiceApp/MenuBar.swift:87` | 仅手动组显示子菜单；停止时禁用 | 否 | DIRECT/REJECT 的 select 与自动组配置，核对仅 select 出现 |  |
| G-214 | 菜单栏／策略组 | 选项名称及延迟（ForEach Toggle 模板） | `apps/macos/Sources/SluiceApp/MenuBar.swift:89` | 切换手动组当前选项，更新勾选 | 否 | DIRECT/REJECT 之间切换，对照策略页和 API |  |
| G-215 | 菜单栏／策略组 | 测试延迟／测试中…（ForEach 模板） | `apps/macos/Sources/SluiceApp/MenuBar.swift:101` | 触发该组测试，测试中禁用 | 否 | 组 url 配本地 HTTP 服务，核对延迟与 REJECT 失败；公网节点或默认 URL 需无Surge机器 |  |
| G-216 | 菜单栏 | 设置为系统代理 | `apps/macos/Sources/SluiceApp/MenuBar.swift:111` | 设置或取消系统代理；无入站监听禁用 | 否 | 需无Surge机器；本地服务核对开关与系统配置恢复 |  |
| G-217 | 菜单栏 | 增强模式 | `apps/macos/Sources/SluiceApp/MenuBar.swift:116` | 切换增强配置并报告错误 | 否 | 需无Surge机器；覆盖授权/取消/开关/路由恢复；内核自检可能访问外网 |  |
| G-218 | 菜单栏 | 重新载入配置 | `apps/macos/Sources/SluiceApp/MenuBar.swift:126` | 运行时重载；停止或重载中禁用 | 否 | 仅本地配置修改规则后重载；增强模式配置需无Surge机器 |  |
| G-219 | 菜单栏快捷键 | ⌘R | `apps/macos/Sources/SluiceApp/MenuBar.swift:128` | 触发重新载入配置 | 否 | 本地内核运行/停止各按键一次；TUN 配置需无Surge机器 |  |
| G-220 | 菜单栏 | 重启内核 | `apps/macos/Sources/SluiceApp/MenuBar.swift:129` | 活动时重启，停止时禁用 | 否 | 本地配置核对重启；系统代理或增强模式场景需无Surge机器 |  |
| G-221 | 菜单栏 | 菜单栏显示（Menu） | `apps/macos/Sources/SluiceApp/MenuBar.swift:133` | 展开显示模式及出站标记选项 | 否 | 打开并核对三个模式及末尾开关 |  |
| G-222 | 菜单栏／菜单栏显示 | 显示图标和实时速度／仅显示图标／仅显示实时速度（ForEach 模板） | `apps/macos/Sources/SluiceApp/MenuBar.swift:135` | 选择并持久化唯一显示模式 | 否 | 依次选择，核对设置页 Picker 同步 |  |
| G-223 | 菜单栏／菜单栏显示 | 显示当前的出站模式 | `apps/macos/Sources/SluiceApp/MenuBar.swift:141` | 切换模式标记并与设置同步 | 否 | 切换后检查设置页与 R/D/G 标记 |  |
| G-224 | 菜单栏 | 显示主窗口 | `apps/macos/Sources/SluiceApp/MenuBar.swift:145` | 打开 main 窗口并激活应用 | 否 | 关闭窗口后点击，核对已有窗口复用 |  |
| G-225 | 菜单栏快捷键 | ⌘0 | `apps/macos/Sources/SluiceApp/MenuBar.swift:146` | 显示并激活主窗口 | 否 | 窗口关闭/非前台时分别触发 |  |
| G-226 | 菜单栏 | 查看请求 | `apps/macos/Sources/SluiceApp/MenuBar.swift:147` | 打开主窗口并跳转请求页 | 否 | 关闭窗口后点击，核对侧栏选中请求 |  |
| G-227 | 菜单栏 | 编辑当前配置 | `apps/macos/Sources/SluiceApp/MenuBar.swift:148` | 打开主窗口并跳转配置页 | 否 | 点击后核对当前配置名和未保存草稿保留 |  |
| G-228 | 菜单栏 | 导出诊断信息… | `apps/macos/Sources/SluiceApp/MenuBar.swift:149` | 导出脱敏 ZIP 后在 Finder 显示；失败跳设置页并显示错误；导出中禁用 | 否 | 本地隔离日志目录，内核停止/运行分别导出；真实接管网络快照需无Surge机器 |  |
| G-229 | 菜单栏 | 检查更新… | `apps/macos/Sources/SluiceApp/MenuBar.swift:163`<br>`apps/macos/Sources/SluiceApp/Updater.swift:60` | 调用 Sparkle 检查更新；canCheck 为 false 时禁用 | 是 | 完整 app 检查成功/失败、进行中禁用；开发构建核对禁用 |  |
| G-230 | 菜单栏 | 退出 Sluice | `apps/macos/Sources/SluiceApp/MenuBar.swift:164` | 结束应用并清理拥有的内核，按配置恢复网络 | 否 | 本地配置退出后核对进程与端口；系统代理或 TUN 恢复测试需无Surge机器 |  |
| G-231 | 菜单栏快捷键 | ⌘Q | `apps/macos/Sources/SluiceApp/MenuBar.swift:165` | 执行退出动作 | 否 | 本地配置按键核对进程退出；涉及系统代理或 TUN 时需无Surge机器 |  |
| G-232 | 应用菜单命令 | 应用信息之后的命令组（CommandGroup） | `apps/macos/Sources/SluiceApp/SluiceApp.swift:46` | 在应用菜单“关于”之后插入检查更新命令 | 否 | 打开应用菜单，核对位置、只有一个命令项及状态 |  |
| G-233 | 应用菜单命令 | 检查更新… | `apps/macos/Sources/SluiceApp/SluiceApp.swift:46`<br>`apps/macos/Sources/SluiceApp/Updater.swift:60` | 执行检查更新，与菜单栏共享 canCheck | 是 | 完整 app 测试更新流程及两入口禁用同步；开发构建核对禁用 |  |

## A2. 菜单栏（MenuBarExtra）功能与显示

本节补充 A 节菜单栏入口的逐项检查及显示回归，保留原 G 编号供历史记录引用；M 编号独立计数。动态策略组按模板遍历每个 `select` 组及其每个选项，自动组不应出现。当前 `MenuBarDisplayMode` 只有 `iconAndSpeed`、`iconOnly`、`speedOnly` 三值；两行速度是前者和后者的渲染方式，没有独立的“两行”模式。以下结果全部待执行。

### 菜单及子菜单

| ID | 页面 | 控件（界面显示的中文标签） | 源码 file:line | 预期行为 | 需外网 | 测试方法 | 结果 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| M-001 | 菜单栏入口 | Sluice 图标／实时速度（MenuBarExtra） | `apps/macos/Sources/SluiceApp/SluiceApp.swift:49`<br>`apps/macos/Sources/SluiceApp/SluiceApp.swift:22` | 点击打开原生菜单；主窗口关闭后状态项仍存在 | 否 | 依次使用三种显示模式，关闭主窗口后打开菜单，再点击空白处关闭 |  |
| M-002 | 菜单栏／状态头 | Sluice · 已停止／启动中…／运行中／出错 | `apps/macos/Sources/SluiceApp/MenuBar.swift:57`<br>`apps/macos/Sources/SluiceApp/Core.swift:108` | 只读标题与内核状态一致 | 否 | 本地配置覆盖停止、启动中、运行、无效配置失败；每次重新打开核对标题；涉及系统代理/TUN 时需无Surge机器 |  |
| M-003 | 菜单栏／状态头 | 配置：当前配置名 | `apps/macos/Sources/SluiceApp/MenuBar.swift:58`<br>`apps/macos/Sources/SluiceApp/MenuBarModel.swift:26` | 显示当前配置文件去掉扩展名后的名称 | 否 | 切换两份临时配置，含中文及空格文件名；重新打开菜单核对名称 |  |
| M-004 | 菜单栏／状态头 | ↓ 下载速度／↑ 上传速度／连接数 | `apps/macos/Sources/SluiceApp/MenuBar.swift:59`<br>`apps/macos/Sources/SluiceApp/MenuBarModel.swift:27` | 仅运行中显示，顺序为下载、上传、活动连接数；菜单关闭后重开刷新快照 | 否 | 限速下载本地大文件，对照 API 流量和活动连接；停止后重开确认消失；菜单保持打开时按 M-051 检查冻结 |  |
| M-005 | 菜单栏／状态头 | 系统代理已开启，内核未运行 | `apps/macos/Sources/SluiceApp/MenuBar.swift:61` | 非运行状态且系统代理开启时显示警告，运行中改显示流量行 | 否 | 需无Surge机器；构造系统代理开、内核停状态，启动后重开菜单核对替换，关闭代理后核对警告消失 |  |
| M-006 | 菜单栏／状态头 | 系统代理：其他代理说明 | `apps/macos/Sources/SluiceApp/MenuBar.swift:64`<br>`apps/macos/Sources/SluiceApp/MenuBarModel.swift:28` | `otherSystemProxy` 非空时显示只读说明，空时隐藏 | 否 | 需无Surge机器；用受控本地其他代理配置产生说明，对照系统代理状态；恢复后重开菜单核对隐藏 |  |
| M-007 | 菜单栏 | 启动 Sluice | `apps/macos/Sources/SluiceApp/MenuBar.swift:67` | 停止／失败时显示启动并启动内核；启动中按钮禁用 | 否 | 仅本地配置点击，核对状态和监听端口；启动失败后可重试；涉及系统代理/TUN 时需无Surge机器 |  |
| M-008 | 菜单栏 | 停止 Sluice | `apps/macos/Sources/SluiceApp/MenuBar.swift:67` | 活动时显示停止，starting 时禁用；运行时可停止 | 否 | 本地启动后停止，核对端口释放和菜单标题；涉及系统代理/TUN 时需无Surge机器并检查网络恢复 |  |
| M-009 | 菜单栏 | 出站模式：当前模式（子菜单入口） | `apps/macos/Sources/SluiceApp/MenuBar.swift:73`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:81` | 显示当前模式中文名及对应图标；仅运行中可展开 | 否 | 本地配置运行时展开，核对三项和唯一 ✓；停止、启动中、失败时核对禁用 |  |
| M-010 | 菜单栏／出站模式 | 直接连接 | `apps/macos/Sources/SluiceApp/MenuBar.swift:74`<br>`apps/macos/Sources/SluiceApp/Views.swift:66` | 设置 `direct`，重新打开显示 ✓，策略页与 D 标记同步 | 否 | 本地 DIRECT/REJECT 配置点击，对照 `/v1/mode` 和本地路由；重复点击不取消选中 |  |
| M-011 | 菜单栏／出站模式 | 全局代理 | `apps/macos/Sources/SluiceApp/MenuBar.swift:74`<br>`apps/macos/Sources/SluiceApp/Views.swift:66` | 设置 `global`，重新打开显示 ✓，策略页与 G 标记同步 | 否 | FINAL 仅用 DIRECT/REJECT，点击后对照 `/v1/mode` 和 FINAL 路由；重复点击核对唯一选中 |  |
| M-012 | 菜单栏／出站模式 | 规则判定 | `apps/macos/Sources/SluiceApp/MenuBar.swift:74`<br>`apps/macos/Sources/SluiceApp/Views.swift:66` | 设置 `rule`，重新打开显示 ✓，策略页与 R 标记同步 | 否 | 本地规则配置点击，对照 `/v1/mode` 和两条不同匹配规则；重复点击核对唯一选中 |  |
| M-013 | 菜单栏／策略组 | 组名：当前选择（每个策略组子菜单模板） | `apps/macos/Sources/SluiceApp/MenuBar.swift:87`<br>`apps/macos/Sources/SluiceApp/MenuBarModel.swift:31` | 每个 select 组显示独立入口及当前选项，非运行时禁用；自动组隐藏，无手动组时整段隐藏 | 否 | 配置两个不同名 select 组及 url-test/fallback/load-balance 组，全部成员只用 DIRECT/REJECT；遍历入口并覆盖空组列表 |  |
| M-014 | 菜单栏／每个策略组 | 选项名称及延迟（每组选项 Button 模板） | `apps/macos/Sources/SluiceApp/MenuBar.swift:90`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:182` | 每个选项为按钮；名称、延迟和当前选项 ✓ 正确，点击只修改所属组 | 否 | 遍历每个手动组的每个选项，切换 DIRECT/REJECT 后对照 API 和策略页；覆盖中文长组名，核对选中其他组不串组 |  |
| M-015 | 菜单栏／每个策略组选项 | 延迟彩色圆点及未测试／毫秒数／超时 | `apps/macos/Sources/SluiceApp/MenuBar.swift:98`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:187`<br>`apps/macos/Sources/SluiceApp/Latency.swift:6`<br>`apps/macos/Sources/SluiceApp/Views.swift:487` | nil 为灰色未测试，0…199 ms 为绿色，200…499 ms 为警示色，≥500 ms 和负值超时为失败色；原色圆点不被菜单模板染色 | 否 | 用本地延迟 HTTP 服务或受控 API 夹具覆盖 nil、-1、0、199、200、499、500；遍历各组选项，在浅/深色及选中高亮下核对文字和圆点 |  |
| M-016 | 菜单栏／每个策略组 | 测试延迟／测试中… | `apps/macos/Sources/SluiceApp/MenuBar.swift:103`<br>`apps/macos/Sources/SluiceApp/Core.swift:813` | 仅测试目标组，进行中禁用该按钮，完成后更新延迟并恢复；错误可见 | 否 | 每个组 url 显式指向本地 HTTP 服务，DIRECT 成功、REJECT 失败；延迟响应期间重开观察测试中，检查其他组独立；真实节点或默认公网 URL 需无Surge机器且需外网 |  |
| M-017 | 菜单栏 | 设置为系统代理 | `apps/macos/Sources/SluiceApp/MenuBar.swift:115`<br>`apps/macos/Sources/SluiceApp/MenuBarModel.swift:34` | 切换系统代理并反映勾选；无 HTTP/SOCKS 监听配置时禁用 | 否 | 需无Surge机器；用本地监听开关，核对 networksetup 和主窗口同步；分别覆盖仅 HTTP、仅 SOCKS、均无配置，最后恢复系统设置 |  |
| M-018 | 菜单栏 | 增强模式 | `apps/macos/Sources/SluiceApp/MenuBar.swift:120` | 切换增强模式配置，按需授权和重启；失败写入“增强模式：”错误 | 否 | 需无Surge机器；覆盖开关、批准、取消和失败，对照 TUN/路由/DNS 恢复；内核 apple.com 自检允许失败，验证自检成功另需外网 |  |
| M-019 | 菜单栏 | 重新载入配置 | `apps/macos/Sources/SluiceApp/MenuBar.swift:130` | 运行时重载；停止、启动中或重载中禁用 | 否 | 修改临时配置规则后点击，对照路由；无效配置显示错误；重开核对禁用态；系统代理/TUN 配置需无Surge机器 |  |
| M-020 | 菜单栏快捷键 | ⌘R | `apps/macos/Sources/SluiceApp/MenuBar.swift:132` | 触发与重新载入配置按钮相同的动作并遵守禁用条件 | 否 | 本地配置运行、停止、重载中分别按键，对照路由及错误；系统代理/TUN 配置需无Surge机器 |  |
| M-021 | 菜单栏 | 重启内核 | `apps/macos/Sources/SluiceApp/MenuBar.swift:133` | 活动时重启，非活动时禁用 | 否 | 本地配置点击，对照内核进程和监听端口恢复；停止时核对禁用；系统代理/TUN 场景需无Surge机器 |  |
| M-022 | 菜单栏 | 菜单栏显示（子菜单入口） | `apps/macos/Sources/SluiceApp/MenuBar.swift:137` | 展开三个显示模式和“显示当前的出站模式”，含分隔线；停止时仍可使用 | 否 | 运行/停止均展开，核对项目、顺序及唯一模式 ✓，逐项点击按 M-023…M-026 检查 |  |
| M-023 | 菜单栏／菜单栏显示 | 显示图标和实时速度 | `apps/macos/Sources/SluiceApp/MenuBar.swift:138`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:10` | 保存 `menuBarDisplayMode=iconAndSpeed`，该项唯一勾选，图标和两行速度显示 | 否 | 从另外两模式分别切入，对照设置页 Picker；重开应用核对持久化；渲染见 M-035 |  |
| M-024 | 菜单栏／菜单栏显示 | 仅显示图标 | `apps/macos/Sources/SluiceApp/MenuBar.swift:138`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:11` | 保存 `menuBarDisplayMode=iconOnly`，该项唯一勾选，速度隐藏 | 否 | 从另外两模式分别切入，对照设置页并重开应用；渲染见 M-036 |  |
| M-025 | 菜单栏／菜单栏显示 | 仅显示实时速度 | `apps/macos/Sources/SluiceApp/MenuBar.swift:138`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:12` | 保存 `menuBarDisplayMode=speedOnly`，该项唯一勾选，只显示两行速度 | 否 | 从另外两模式分别切入，对照设置页并重开应用；渲染见 M-037 |  |
| M-026 | 菜单栏／菜单栏显示 | 显示当前的出站模式 | `apps/macos/Sources/SluiceApp/MenuBar.swift:147`<br>`apps/macos/Sources/SluiceApp/MenuBarModel.swift:39` | 切换 `menuBarShowOutboundMode` 和 ✓，与设置页同步并持久化；图标模式显示或隐藏徽标 | 否 | 三种显示模式分别开关并重开应用；默认开启，speedOnly 下保留偏好但不绘制徽标；R/D/G 逐项见 M-039…M-044 |  |
| M-027 | 菜单栏 | 显示主窗口 | `apps/macos/Sources/SluiceApp/MenuBar.swift:155`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:196` | 打开或复用 main 窗口并激活应用 | 否 | 窗口关闭、最小化、后台时分别点击，核对窗口激活及没有重复窗口 |  |
| M-028 | 菜单栏快捷键 | ⌘0 | `apps/macos/Sources/SluiceApp/MenuBar.swift:156` | 执行显示主窗口动作 | 否 | 窗口关闭及应用不在前台时打开菜单按键，核对 main 窗口激活 |  |
| M-029 | 菜单栏 | 查看请求 | `apps/macos/Sources/SluiceApp/MenuBar.swift:157`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:196` | 激活主窗口并请求切换到请求页 | 否 | 关闭窗口后点击，再从其他页面点击，核对请求页及侧栏选择 |  |
| M-030 | 菜单栏 | 编辑当前配置 | `apps/macos/Sources/SluiceApp/MenuBar.swift:158` | 激活主窗口并切换配置页，显示当前配置 | 否 | 切换两份本地配置后分别点击，核对文件名；有未保存草稿时再次进入核对草稿保留 |  |
| M-031 | 菜单栏 | 导出诊断信息… | `apps/macos/Sources/SluiceApp/MenuBar.swift:159`<br>`apps/macos/Sources/SluiceApp/MenuBarModel.swift:40` | 导出脱敏 ZIP 并在 Finder 显示；导出中禁用；失败显示“导出诊断信息失败：”并打开活动页（overview） | 否 | 隔离目录，运行/停止各导出一次，核对脱敏、Finder、并发禁用及不可写目标错误；系统代理/TUN 快照对照需无Surge机器 |  |
| M-032 | 菜单栏 | 检查更新… | `apps/macos/Sources/SluiceApp/MenuBar.swift:172`<br>`apps/macos/Sources/SluiceApp/Updater.swift:60` | 调用 Sparkle，`canCheck=false` 时禁用，与应用菜单入口同步 | 是 | 完整 app 覆盖无更新、有更新、失败和检查中禁用；开发构建只核对禁用态 |  |
| M-033 | 菜单栏 | 退出 Sluice | `apps/macos/Sources/SluiceApp/MenuBar.swift:173`<br>`apps/macos/Sources/SluiceApp/SluiceApp.swift:18` | 退出应用并调用 `stopForQuit` 清理拥有的内核与网络状态 | 否 | 本地配置停止/运行时分别退出，检查进程、端口和状态项消失；系统代理/TUN 恢复需无Surge机器 |  |
| M-034 | 菜单栏快捷键 | ⌘Q | `apps/macos/Sources/SluiceApp/MenuBar.swift:174`<br>`apps/macos/Sources/SluiceApp/SluiceApp.swift:18` | 执行退出动作和相同清理流程 | 否 | 打开菜单按键，核对应用及内核退出；系统代理/TUN 清理分支需无Surge机器 |  |

### 显示设置与渲染

| ID | 页面 | 控件（界面显示的中文标签） | 源码 file:line | 预期行为 | 需外网 | 测试方法 | 结果 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| M-035 | 菜单栏显示 | 图标和实时速度（iconAndSpeed） | `apps/macos/Sources/SluiceApp/MenuBar.swift:229`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:248` | 默认模式显示左侧图标、可选徽标和右侧两行速度；两区不重叠 | 否 | 使用独立偏好域核对默认值，再明确选择此模式；本地限速流量下截图，徽标开关各测一次；宽度稳定性见 M-053/M-054 |  |
| M-036 | 菜单栏显示 | 仅图标（iconOnly） | `apps/macos/Sources/SluiceApp/MenuBar.swift:15`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:257` | 仅绘制图标和可选徽标，无速度文本 | 否 | 空闲与本地限速流量下核对速度均隐藏；徽标开关核对布局及点击区域，恢复该模式后偏好一致 |  |
| M-037 | 菜单栏显示 | 仅实时速度（speedOnly） | `apps/macos/Sources/SluiceApp/MenuBar.swift:15`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:256` | 两行速度从左侧开始，无图标、徽标或其预留空白；灰色图标设置禁用 | 否 | 开关出站标记均截图，核对两行及无多余左间距；进入设置页核对灰色选项禁用；宽度稳定性见 M-057/M-058 |  |
| M-038 | 菜单栏显示 | 两行速度：上行在上／下行在下 | `apps/macos/Sources/SluiceApp/MenuBar.swift:268`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:307` | iconAndSpeed 与 speedOnly 均在 22 pt 高图像内完整显示两行，上传在上、下载在下，文字不截断 | 否 | 两种模式分别空闲、下载本地大文件，对照 API 上下行数据及截图；覆盖普通/Retina 缩放，iconOnly 不显示两行；当前没有独立两行枚举值 |  |
| M-039 | 菜单栏／出站标记 | 显示当前的出站模式：开，规则判定 R | `apps/macos/Sources/SluiceApp/MenuBar.swift:285`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:320` | rule 下 iconAndSpeed、iconOnly 显示 R 徽标；speedOnly 不绘制 | 否 | 本地切为 rule，三种显示模式逐一开启标记，对照 `/v1/mode` 和截图 |  |
| M-040 | 菜单栏／出站标记 | 显示当前的出站模式：关，规则判定 R | `apps/macos/Sources/SluiceApp/MenuBar.swift:230`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:285` | rule 下三种模式均隐藏 R；含图标模式释放徽标间距 | 否 | 本地 rule 下三种模式逐一关闭标记，对照设置和截图，重开应用核对保持关闭 |  |
| M-041 | 菜单栏／出站标记 | 显示当前的出站模式：开，直接连接 D | `apps/macos/Sources/SluiceApp/MenuBar.swift:285`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:318` | direct 下 iconAndSpeed、iconOnly 显示 D 徽标；speedOnly 不绘制 | 否 | 本地切为 direct，三种模式逐一开启标记，对照 `/v1/mode`；由 R 切换后无残留 R |  |
| M-042 | 菜单栏／出站标记 | 显示当前的出站模式：关，直接连接 D | `apps/macos/Sources/SluiceApp/MenuBar.swift:230`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:285` | direct 下三种模式均隐藏 D | 否 | 本地 direct 下三种模式逐一关闭标记；切换模式和重开菜单后均无徽标 |  |
| M-043 | 菜单栏／出站标记 | 显示当前的出站模式：开，全局代理 G | `apps/macos/Sources/SluiceApp/MenuBar.swift:285`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:319` | global 下 iconAndSpeed、iconOnly 显示 G 徽标；speedOnly 不绘制 | 否 | FINAL 为 DIRECT/REJECT，切为 global，三种模式逐一开启标记，对照 API；由 D 切换后无残留 D |  |
| M-044 | 菜单栏／出站标记 | 显示当前的出站模式：关，全局代理 G | `apps/macos/Sources/SluiceApp/MenuBar.swift:230`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:285` | global 下三种模式均隐藏 G | 否 | 本地 global 下三种模式逐一关闭标记，对照设置及截图；重开应用核对偏好 |  |
| M-045 | 设置／菜单栏与状态项 | 未启用系统代理和增强模式时，将图标显示为灰色：开 | `apps/macos/Sources/SluiceApp/Views.swift:1116`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:259` | 默认开启；代理与增强模式均关闭时墨色 alpha=0.55，任一开启则恢复；speedOnly 下设置禁用 | 否 | 三种显示模式覆盖两开关均关、仅系统代理开、仅 TUN 开、均开；观察图标及速度墨色，徽标仍清晰；启用系统代理/TUN 的对照需无Surge机器，最后恢复 |  |
| M-046 | 设置／菜单栏与状态项 | 未启用系统代理和增强模式时，将图标显示为灰色：关 | `apps/macos/Sources/SluiceApp/Views.swift:1095`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:261` | 关闭偏好后，未接管网络也不降低墨色透明度；偏好持久化 | 否 | 系统代理/TUN 均关闭，本地三模式对照 M-045，重开应用核对；speedOnly 中无法改此设置，切回含图标模式核对保存值 |  |
| M-047 | 菜单栏显示 | 浅色菜单栏 | `apps/macos/Sources/SluiceApp/MenuBar.swift:258`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:287` | 正常墨色为黑，徽标深底白字；失败用系统红色，灰显仍可辨认 | 否 | 将实际 macOS 菜单栏切为浅色，遍历三模式、R/D/G、标记开关、灰显和失败态；截图核对对比度、两行及裁切；系统代理/TUN 对照需无Surge机器 |  |
| M-048 | 菜单栏显示 | 深色菜单栏 | `apps/macos/Sources/SluiceApp/MenuBar.swift:258`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:293` | 正常墨色为白，徽标白底黑字；失败用系统红色，灰显仍可辨认 | 否 | 将实际 macOS 菜单栏切为深色，重复 M-047 全部组合，来回切换核对及时重绘；系统代理/TUN 对照需无Surge机器 |  |
| M-049 | 菜单栏速度格式 | 0 KB/s／KB/s／MB/s／GB/s／TB/s | `apps/macos/Sources/SluiceApp/MenuBar.swift:21` | 十进制单位；KB/s 整数，MB/s 以上数字最多四字符；负数、NaN、无穷值归零 | 否 | 本地流量核对零值及 KB/MB；离线调用格式函数覆盖负值、非有限值、单位边界及 GB/TB；1,000,000 B/s 当前格式为 1.00 MB/s |  |
| M-050 | 菜单栏可访问性 | Sluice，状态，出站模式，上传／下载每秒速度 | `apps/macos/Sources/SluiceApp/MenuBar.swift:243` | 可访问标签包含状态；含图标且标记开启时含模式名，含速度的模式含上下行速度 | 否 | 用辅助功能检查器遍历三模式、标记开关及 R/D/G，对照视觉内容和实时数值；iconOnly 不读速度，speedOnly 不读徽标模式名 |  |

### 显示稳定性与菜单跟踪

宽度采样共同方法（M-053…M-064）：沿用本地基线，关闭系统代理及增强模式，仅通过显式 HTTP 代理产生 loopback 流量。在临时目录准备足够大的文件（如 128 MiB），以 `python3 -m http.server 18080 --bind 127.0.0.1 --directory <临时目录>` 服务；用 `curl --noproxy '' --proxy http://127.0.0.1:18081 --limit-rate <每秒字节数> --max-time 5 --output /dev/null http://127.0.0.1:18080/large.bin` 连续分段下载，循环不同限速和短暂空闲共至少 30 秒。空的 `--noproxy` 用来避免 loopback 绕过代理；确认 API 流量增加。限时结束是夹具预期，不记为内核失败。边界采样改为在 999000 与 1000000 B/s 两侧持续往返，并对照 API 实际速率和显示文字；必要时延长稳态段，若实际速率一直低于阈值则略调高上侧限速，直到确实跨越边界。

每个用例固定显示模式、出站标记开关、屏幕缩放和其他状态项，先记录状态项 frame；以约 1 秒间隔连续截图 30 秒（至少 30 帧），同时保存时间、上下行速率、frame x/width。可从 `CGWindowListCopyWindowInfo` 中定位 Sluice 状态项窗口边界；若系统未单列状态项，则用辅助功能 frame 配合 `screencapture` 的固定菜单栏区域裁图定位。不得把整个菜单栏窗口宽度或每帧重新裁出的文字宽度当成状态项宽度。以相同坐标单位比较各帧宽度及相邻状态项位置，保存原图和测量表。每行均分别固定出站标记开、关各跑一轮，设置切换本身允许改变布局；一轮内速率变化不得改变宽度或挤动相邻项。浅/深色指实际菜单栏背景，不能只改变应用窗口主题。当前源码按实时字符串测量 `speedWidth`，已知会导致宽度变化、菜单栏跳动；下面是待执行的回归验收，不能据源码把结果填为通过。

| ID | 页面 | 控件（界面显示的中文标签） | 源码 file:line | 预期行为 | 需外网 | 测试方法 | 结果 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| M-051 | 菜单栏／菜单跟踪 | 菜单及子菜单打开期间的状态快照 | `apps/macos/Sources/SluiceApp/MenuBarModel.swift:69`<br>`apps/macos/Sources/SluiceApp/MenuBarModel.swift:86`<br>`apps/macos/Sources/SluiceApp/SluiceApp.swift:50` | 原生菜单跟踪期间内容冻结、不闪退或自动关闭；独立状态项速度继续更新，全部菜单关闭后快照刷新 | 否 | 持续变化的本地限速流量下保持菜单打开至少 30 秒，往返出站/组/显示子菜单并停留；核对状态头冻结而标签更新，关闭重开显示最新状态 |  |
| M-052 | 菜单栏／菜单跟踪 | 子菜单选择动作与结束跟踪 | `apps/macos/Sources/SluiceApp/MenuBarModel.swift:75`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:76`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:92` | 跟踪结束后动作仍只执行一次，捕获的模式/组/选项正确，无选择无效或菜单意外关闭 | 否 | 本地流量持续更新时逐项选择三出站模式、每组选项、测试延迟和每个显示设置；每次重开对照 API/偏好，覆盖 Esc 取消及快速往返子菜单 |  |
| M-053 | 菜单栏／宽度稳定性 | 图标和实时速度 × 浅色菜单栏 | `apps/macos/Sources/SluiceApp/MenuBar.swift:253`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:257` | iconAndSpeed 在速度变化时 frame 宽度恒定、相邻项不跳动，图标和两行不裁切 | 否 | 按共同方法，浅色、iconAndSpeed，循环空闲及 64000/512000/1200000 B/s，约 1 秒一帧采样 30 秒比较宽度；已知动态测宽问题待回归 |  |
| M-054 | 菜单栏／宽度稳定性 | 图标和实时速度 × 深色菜单栏 | `apps/macos/Sources/SluiceApp/MenuBar.swift:253`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:257` | 深色下 iconAndSpeed 宽度恒定、无跳动、无裁切 | 否 | 按共同方法，深色、iconAndSpeed，循环空闲及 64000/512000/1200000 B/s，约 1 秒一帧采样 30 秒比较 frame |  |
| M-055 | 菜单栏／宽度稳定性 | 仅图标 × 浅色菜单栏 | `apps/macos/Sources/SluiceApp/MenuBar.swift:257` | iconOnly 宽度不受上下行速度变化影响，无隐藏速度占位变化 | 否 | 按共同方法，浅色、iconOnly，变化限速 30 秒、约 1 秒一帧；对照 API 确有流量变化，比较 frame 及相邻项 |  |
| M-056 | 菜单栏／宽度稳定性 | 仅图标 × 深色菜单栏 | `apps/macos/Sources/SluiceApp/MenuBar.swift:257` | 深色下 iconOnly 宽度恒定、相邻项不跳动 | 否 | 按共同方法，深色、iconOnly，变化限速 30 秒、约 1 秒一帧；对照 API 和 frame 记录 |  |
| M-057 | 菜单栏／宽度稳定性 | 仅实时速度 × 浅色菜单栏 | `apps/macos/Sources/SluiceApp/MenuBar.swift:253`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:256` | speedOnly 在速度变化时宽度恒定，两行不裁切，无相邻项跳动 | 否 | 按共同方法，浅色、speedOnly，循环空闲及 64000/512000/1200000 B/s，约 1 秒一帧采样 30 秒比较 frame；已知动态测宽问题待回归 |  |
| M-058 | 菜单栏／宽度稳定性 | 仅实时速度 × 深色菜单栏 | `apps/macos/Sources/SluiceApp/MenuBar.swift:253`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:256` | 深色下 speedOnly 宽度恒定、两行完整、相邻项不跳动 | 否 | 按共同方法，深色、speedOnly，循环空闲及 64000/512000/1200000 B/s，约 1 秒一帧采样 30 秒比较 frame |  |
| M-059 | 菜单栏／单位边界稳定性 | 图标和实时速度 × 浅色：999 KB/s → 1.0 MB/s | `apps/macos/Sources/SluiceApp/MenuBar.swift:25`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:253` | 跨 KB/MB 边界宽度恒定、无跳动或裁切；当前 1.0 MB/s 对应显示 1.00 MB/s | 否 | 按共同方法，浅色、iconAndSpeed，999000/1000000 B/s 两侧往返；约 1 秒截图一次至少 30 秒，确认实际显示跨单位并比较 frame |  |
| M-060 | 菜单栏／单位边界稳定性 | 图标和实时速度 × 深色：999 KB/s → 1.0 MB/s | `apps/macos/Sources/SluiceApp/MenuBar.swift:25`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:253` | 深色下跨 KB/MB 边界宽度恒定，1.00 MB/s 完整可见 | 否 | 按共同方法，深色、iconAndSpeed，在边界两侧往返，约 1 秒一帧至少 30 秒，对照实际速率、单位及 frame |  |
| M-061 | 菜单栏／单位边界稳定性 | 仅图标 × 浅色：999 KB/s → 1.0 MB/s | `apps/macos/Sources/SluiceApp/MenuBar.swift:257` | iconOnly 不显示速率，后台跨单位也不改变宽度 | 否 | 按共同方法，浅色、iconOnly，在边界两侧往返，API 证明跨界；约 1 秒截图一次至少 30 秒比较 frame |  |
| M-062 | 菜单栏／单位边界稳定性 | 仅图标 × 深色：999 KB/s → 1.0 MB/s | `apps/macos/Sources/SluiceApp/MenuBar.swift:257` | 深色下 iconOnly 在后台跨单位时宽度恒定、无跳动 | 否 | 按共同方法，深色、iconOnly，在边界两侧往返，API 证明跨界；约 1 秒一帧至少 30 秒比较 frame |  |
| M-063 | 菜单栏／单位边界稳定性 | 仅实时速度 × 浅色：999 KB/s → 1.0 MB/s | `apps/macos/Sources/SluiceApp/MenuBar.swift:25`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:253` | speedOnly 跨 KB/MB 边界宽度恒定，两行完整，1.00 MB/s 不裁切 | 否 | 按共同方法，浅色、speedOnly，在边界两侧往返；约 1 秒一帧至少 30 秒，确认实际显示跨单位并比较 frame |  |
| M-064 | 菜单栏／单位边界稳定性 | 仅实时速度 × 深色：999 KB/s → 1.0 MB/s | `apps/macos/Sources/SluiceApp/MenuBar.swift:25`<br>`apps/macos/Sources/SluiceApp/MenuBar.swift:253` | 深色下 speedOnly 跨单位宽度恒定、相邻项不跳动、文字不裁切 | 否 | 按共同方法，深色、speedOnly，在边界两侧往返；约 1 秒一帧至少 30 秒，对照实际单位及 frame |  |

## B. CLI

已实际构建并执行 `cargo run -q -- --help`；随后用同次构建的 `target/debug/sluice` 执行根帮助和 `run`、`check`、`route`、`convert`、`mitm`、`mitm gen-ca`、`diag`、`diag export` 各自的 `--help`。程序用 `std::env::args` 手写分派，没有 clap，也没有 `--version` 或 `-h` 专用分支。下表记录实际行为，不把 `--help` 误列为子命令支持的功能标志。`-h`、`--version` 均落入总帮助分支（退出 2），不作为受支持标志计数。六个叶命令：run、check、route、convert、mitm gen-ca、diag export；六个功能标志：route 的五项和 gen-ca 的 --force。

### 命令、位置参数、标志与帮助

| ID | 页面 | 控件（界面显示的中文标签） | 源码 file:line | 预期行为 | 需外网 | 测试方法 | 结果 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| C-001 | CLI／根帮助 | `sluice --help` | `src/main.rs:44`<br>`src/main.rs:223` | 打印完整 USAGE 并退出 2；当前不是成功退出的专用帮助命令 | 否 | 执行 cargo run -q -- --help，核对六个叶命令及退出码 |  |
| C-002 | CLI／run | `run <config.conf>` | `src/main.rs:186` | 加载配置并启动入站与 API；收到 SIGINT/SIGTERM 优雅退出，TUN需 root | 否 | 本地基线配置运行，用 loopback HTTP/SOCKS 请求，再发 SIGTERM 核对端口释放；系统代理/TUN 场景需无Surge机器 |  |
| C-003 | CLI／run 参数 | `<config.conf>` | `src/main.rs:187` | 读取指定文件，缺文件/语法错误失败；监听端口冲突和无监听配置失败 | 否 | 临时本地有效/坏/不存在配置与已占用 loopback 端口；enhanced-mode 运行需无Surge机器 |  |
| C-004 | CLI／run 帮助 | `run --help` | `src/main.rs:186` | 将 --help 当配置路径，文件不存在时退出 1 | 否 | 无同名文件的临时目录执行，核对 read --help 错误 |  |
| C-005 | CLI／check | `check <config.conf>` | `src/main.rs:146` | 严格扩展订阅并校验路由，打印代理/组/规则数；不启动监听或 TUN | 否 | 本地 DIRECT/REJECT 和 file:// 订阅检查有效、损坏、缺文件；公网订阅校验需无Surge机器且需外网 |  |
| C-006 | CLI／check 参数 | `<config.conf>` | `src/main.rs:147` | 从该路径读取配置，相对规则集/订阅按配置目录解析 | 否 | 临时复制本地规则及数据文件，切换工作目录调用检查，核对相对路径 |  |
| C-007 | CLI／check 帮助 | `check --help` | `src/main.rs:146` | 将 --help 当配置路径，文件不存在时退出 1 | 否 | 临时目录执行，检查 read --help 错误 |  |
| C-008 | CLI／route | `route <config.conf> <host[:port]>` | `src/main.rs:155` | 显示 target、rule、policy、outbound，支持附加连接上下文；不建立目标业务连接 | 否 | 使用 tests/fixtures/local-check/rules.conf 中的本地规则；验证 FINAL、精确域名、loopback 和 IPv6 |  |
| C-009 | CLI／route 参数 | `<config.conf>` | `src/main.rs:171` | 严格构建指定配置及订阅；坏配置退出 1 | 否 | 本地有效/无效配置；公网订阅或远程规则集需无Surge机器 |  |
| C-010 | CLI／route 参数 | `<host[:port]>` | `src/main.rs:172` | 默认端口 443，显式端口覆盖；无效 authority 报错 | 否 | 测试 127.0.0.1、127.0.0.1:8443、[::1]:8443 和非法端口；域名用精确规则避免公网 DNS |  |
| C-011 | CLI／route 标志 | `--process <name>` | `src/main.rs:160` | 给 PROCESS-NAME 提供进程名上下文 | 否 | 规则 PROCESS-NAME,local-check,DIRECT，目标使用 loopback，比较带/不带标志 |  |
| C-012 | CLI／route 标志 | `--src <ip:port>` | `src/main.rs:161` | 给 SRC-IP 提供来源；非法地址失败 | 否 | 使用 127.2.0.1:12345 命中本地 fixture，测试非法地址与缺值 |  |
| C-013 | CLI／route 标志 | `--proto TCP\|UDP\|HTTP\|HTTPS\|QUIC` | `src/main.rs:162` | 设置协议上下文；非法协议失败 | 否 | 遍历五种协议与无效值，对照 PROTOCOL 规则 |  |
| C-014 | CLI／route 标志 | `--in-port <port>` | `src/main.rs:163` | 给 IN-PORT 提供监听端口；非法/超范围值失败 | 否 | 用 8765 命中 fixture，测试 0、65535、65536 和非数字 |  |
| C-015 | CLI／route 标志 | `--url <url>` | `src/main.rs:164` | 提供 URL-REGEX 匹配文本，不请求该 URL | 否 | 用 http://url.test/ 命中 fixture，比较无标志和不匹配文本 |  |
| C-016 | CLI／route 帮助与非法选项 | `route --help` | `src/main.rs:155`<br>`src/main.rs:223` | 缺 target 时打印总帮助并退出 2；有完整位置参数后未知选项/缺值退出 1 | 否 | 执行子命令帮助；本地配置测试未知参数、奇数参数个数及多个有效标志组合 |  |
| C-017 | CLI／convert | `convert <share-link>` | `src/main.rs:176` | 解析分享链接为一条 [Proxy] 配置，不连接节点 | 否 | 离线使用 loopback 地址与假凭据的 links.txt，逐行转换各受支持协议；不运行转换结果 |  |
| C-018 | CLI／convert 参数 | `<share-link>` | `src/main.rs:177` | 支持 ss、vmess、vless、trojan、hysteria2/hy2、anytls；无效或不支持的链接失败 | 否 | 使用 tests/fixtures/local-check/links.txt 的纯解析用例及畸形链接；无真实节点/公网访问 |  |
| C-019 | CLI／convert 帮助 | `convert --help` | `src/main.rs:176` | 把 --help 当链接，退出 1 并提示 not a link | 否 | 执行帮助调用，核对 stderr/退出码 |  |
| C-020 | CLI／mitm 命令组 | `mitm` | `src/main.rs:180`<br>`src/main.rs:54` | 仅支持 gen-ca 叶命令；单独调用打印总帮助退出 2 | 否 | 分别执行 mitm 与 mitm --help，核对没有隐含子命令 |  |
| C-021 | CLI／mitm 帮助 | `mitm --help` | `src/main.rs:223` | 打印总帮助并退出 2 | 否 | 执行并比对根 USAGE |  |
| C-022 | CLI／mitm gen-ca | `mitm gen-ca` | `src/main.rs:180` | 生成 ca.crt/ca.key，已有 CA 默认拒绝覆盖；只输出信任安装说明 | 否 | 用独立临时 HOME 生成两次，核对首次成功、二次拒绝、私钥权限；不运行输出的信任安装命令 |  |
| C-023 | CLI／mitm gen-ca 标志 | `--force` | `src/main.rs:181` | 覆盖现有 CA 证书和私钥 | 否 | 只在临时 HOME 内生成后加 --force，核对证书指纹变化及 key 权限 |  |
| C-024 | CLI／mitm gen-ca 帮助 | `mitm gen-ca --help` | `src/main.rs:180`<br>`src/main.rs:223` | 未匹配生成分支，打印总帮助退出 2，不生成 CA | 否 | 临时 HOME 执行并核对无新增 CA |  |
| C-025 | CLI／diag 命令组 | `diag` | `src/main.rs:182`<br>`src/main.rs:55` | 仅支持 export 叶命令；缺子命令打印总帮助退出 2 | 否 | 执行 diag，核对用法与退出码 |  |
| C-026 | CLI／diag 帮助 | `diag --help` | `src/main.rs:223` | 打印总帮助并退出 2 | 否 | 执行并比对根 USAGE |  |
| C-027 | CLI／diag export | `diag export <out.zip> [config.conf]` | `src/main.rs:182` | 导出本地脱敏诊断 ZIP 并打印路径，失败退出 1 | 否 | 临时 HOME/SLUICE_LOG_DIR 中放假凭据日志，导出解压并核对脱敏；真实系统代理/TUN快照需无Surge机器 |  |
| C-028 | CLI／diag export 参数 | `<out.zip>` | `src/main.rs:183` | 输出路径必须以 .zip 结尾；创建父目录，覆盖同名输出 | 否 | 仅在临时目录测试新路径、同名覆盖、非 .zip 和不可写路径 |  |
| C-029 | CLI／diag export 参数 | `[config.conf]` | `src/main.rs:183` | 可选收集指定配置的脱敏副本与校验结果；不传时仍可导出 | 否 | 分别省略参数、传本地有效/错误配置，核对包内容；公网订阅配置需无Surge机器 |  |
| C-030 | CLI／diag export 帮助 | `diag export --help` | `src/main.rs:182` | 把 --help 当输出路径，因不是 .zip 退出 1 | 否 | 执行并核对 output must end in .zip，未生成归档 |  |
| C-031 | CLI／非法调用 | `空参数／未知命令／多余参数` | `src/main.rs:223` | 不匹配分支时打印总帮助并退出 2；不会误启动代理 | 否 | 执行空参数、unknown、-h、--version、run 的额外参数、mitm gen-ca 的未知标志；route 选项错误按专门分支退出 1 |  |

## C. Control API

覆盖顶部注释中的 21 个方法/路径组合，另拆出 10 个行为查询参数；补充实现支持的 3 个 PUT 别名及 1 个未匹配请求用例。参数必须 URL 编码（尤其路径、空格、中文、URL 内的 &、+、?）。`/v1/route` 当前只读 target/process/src/proto，CLI 的 --in-port、--url 不是该 API 的已支持查询参数。响应断言同时检查 HTTP 状态码和 JSON；SSE 另按 event/data 帧检查。

### 端点与行为查询参数

| ID | 页面 | 控件（界面显示的中文标签） | 源码 file:line | 预期行为 | 需外网 | 测试方法 | 结果 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A-001 | API／订阅 | `GET /v1/subscriptions` | `src/api.rs:3`<br>`src/api.rs:168` | 返回订阅使用量、过期/更新元数据、节点数和抓取错误 | 否 | 基线无订阅返回 []；file:// DIRECT/REJECT 订阅验证零节点；loopback HTTP fixture 提供元数据头与失败，核对字段；公网订阅需无Surge机器 |  |
| A-002 | API／策略 | `GET /v1/policies` | `src/api.rs:4`<br>`src/api.rs:171` | 返回组类型、当前选择、选项；latency_ms 为 null/负值/毫秒表示未测/失败/成功 | 否 | 仅 DIRECT/REJECT 组配本地测试 URL，前后 GET 比对；包含中文/空格组名 |  |
| A-003 | API／策略选择 | `POST /v1/policies/<group>` | `src/api.rs:5`<br>`src/api.rs:250` | 切换手动组，缺 select 返回 400；自动组/未知组/非法选项返回 400 | 否 | curl --noproxy '*' -X POST 请求本地 API，缺参/不存在组/自动组逐一核对 |  |
| A-004 | API／策略参数 | `?select=<opt>` | `src/api.rs:252` | 决定选中的组选项，支持百分号解码；失败保留旧选择 | 否 | DIRECT/REJECT 来回切换，GET 验证；带空格/中文组名 URL 编码；未知选项 400 |  |
| A-005 | API／组测试 | `POST /v1/policies/<group>/test` | `src/api.rs:6`<br>`src/api.rs:198` | 并行测试成员，返回 tested/selected/results，失败 latency_ms 为 null；未知组 404 | 否 | 所有组 url 指向本地 http.server，DIRECT 成功/REJECT失败，自动组更新选择；默认外网 URL/真实节点需无Surge机器 |  |
| A-006 | API／路由 | `GET /v1/route` | `src/api.rs:7`<br>`src/api.rs:367` | 解释路由决策；无 target 或 target 无效返回 400，决策失败 500 | 否 | 本地配置 GET 缺参/无效目标/有效 loopback 目标，对照 CLI route |  |
| A-007 | API／路由参数 | `?target=<host[:port]>` | `src/api.rs:367` | 指定目标，缺端口默认 443，返回标准化 target、rule、policy、outbound、process | 否 | 127.0.0.1:18080、[::1]:18080、精确 .test 域名和非法端口；仅本地解析规则 |  |
| A-008 | API／路由参数 | `process=<name>` | `src/api.rs:51`<br>`src/api.rs:106` | 向 PROCESS-NAME 规则提供进程名；缺省无进程 | 否 | 本地规则 PROCESS-NAME,local-check,DIRECT，对比带/不带参数，并检查返回 process |  |
| A-009 | API／路由参数 | `src=<ip:port>` | `src/api.rs:51`<br>`src/api.rs:104` | 向 SRC-IP 提供来源；解析失败时忽略来源 | 否 | 127.2.0.1:12345 命中 fixture，测试不匹配与非法地址，核对回退而非 400 |  |
| A-010 | API／路由参数 | `proto=<protocol>` | `src/api.rs:51`<br>`src/api.rs:103` | 设置协议；缺省/非法值回退默认协议 | 否 | 逐个 TCP/UDP/HTTP/HTTPS/QUIC 与非法值对照 PROTOCOL 规则 |  |
| A-011 | API／重载 | `POST /v1/reload` | `src/api.rs:8`<br>`src/api.rs:290` | 从当前路径重建配置及订阅；成功返回 reloaded/summary，失败 400 且旧路由保留 | 否 | 本地规则有效/无效两次修改后 POST；file:// 订阅更新；TUN或公网订阅需无Surge机器 |  |
| A-012 | API／模式 | `GET /v1/mode` | `src/api.rs:9`<br>`src/api.rs:260` | 返回当前 mode：rule、direct、global | 否 | 本地 API 逐次切换后读取比对 |  |
| A-013 | API／模式设置 | `POST /v1/mode` | `src/api.rs:10`<br>`src/api.rs:261` | 设置出站模式；缺失或非法 set 返回 400 | 否 | 本地 API 缺参/无效值，核对旧模式未变 |  |
| A-014 | API／模式参数 | `?set=<mode>` | `src/api.rs:261` | rule 按规则、direct 强制直连、global 使用 FINAL 策略 | 否 | DIRECT/REJECT 规则下遍历三值，再用 /v1/route 检查语义，非法值不变 |  |
| A-015 | API／流量 | `GET /v1/traffic` | `src/api.rs:11`<br>`src/api.rs:269` | 返回启动后累计 up/down 和当前 active 数 | 否 | 本地 HTTP/SOCKS 收发已知数据，核对累计增长与连接关闭后 active 回落 |  |
| A-016 | API／DNS | `GET /v1/dns` | `src/api.rs:12`<br>`src/api.rs:273` | 返回缓存 entries 的 name/type/ttl/answers，TTL 随时间递减 | 否 | 用 loopback DNS fixture 产生 A/AAAA 记录，对照多次 GET；无缓存时空数组 |  |
| A-017 | API／DNS清空 | `POST /v1/dns/flush` | `src/api.rs:13`<br>`src/api.rs:289` | 清空缓存并返回 flushed 条数 | 否 | 本地 DNS 填充后 POST，GET 验证空；重复 POST 返回 0 |  |
| A-018 | API／最近连接 | `GET /v1/connections` | `src/api.rs:14`<br>`src/api.rs:294` | 返回最近路由记录，新记录在后；含目标、规则、进程、URL/MITM字段 | 否 | 用本地 DIRECT/REJECT 请求核对记录内容和先后顺序；界面清除不应伪装成 API 删除历史 |  |
| A-019 | API／活动连接 | `GET /v1/connections/active` | `src/api.rs:15`<br>`src/api.rs:316` | 列出当前 TCP 连接，最早在前，含策略链/字节/速率；不列 UDP | 否 | 本地 http.server 下载大文件或保持 TCP 流，核对字段与自然关闭；使用本地 DNS/UDP 对照不入列表 |  |
| A-020 | API／断开单连接 | `DELETE /v1/connections/<id>` | `src/api.rs:16`<br>`src/api.rs:321` | 关闭指定活动连接；成功 closed=1/id，不存在 404，非法 id 400 | 否 | 两条本地长连接，删除一条核对另一条继续，重复删/非数字 id 检查状态码 |  |
| A-021 | API／断开全部 | `DELETE /v1/connections` | `src/api.rs:17`<br>`src/api.rs:320` | 关闭所有活动 TCP 连接，返回 closed 数量 | 否 | 两条本地连接调用后均断开，GET 最终为空；重复 DELETE 为 0 |  |
| A-022 | API／统计 | `GET /v1/stats` | `src/api.rs:18`<br>`src/api.rs:326` | 返回总量、策略/节点累计和最多600个每秒速率样本；只记录该秒有流量的策略 | 否 | 仅本地 DIRECT/REJECT 组产生流量，对照 /traffic；验证历史按时间升序与600条上限 |  |
| A-023 | API／节点测试 | `POST /v1/nodes/<name>/test` | `src/api.rs:19`<br>`src/api.rs:220` | 测试节点或组当前出站，返回耗时/状态；未知名称404，连接失败200且 ok=false | 是 | 需无Surge机器；省略 url 会访问默认 gstatic；本地成功用下一行显式 url，REJECT 可测不访问外网的失败 |  |
| A-024 | API／节点测试参数 | `url=<http://URL>` | `src/api.rs:35`<br>`src/api.rs:222` | 覆盖测试地址；实现缺省为 DEFAULT_TEST_URL，并不读取组 url；仅支持 http:// | 否 | 显式传 http://127.0.0.1:18080/，DIRECT 成功/REJECT失败；https://及非法 URL 检查 ok=false；真实节点或公网 URL 需无Surge机器 |  |
| A-025 | API／节点测试参数 | `timeout=<毫秒>` | `src/api.rs:36`<br>`src/api.rs:223` | 默认5000，解析失败用默认，合法数值钳制到100…60000 | 否 | 始终带 loopback url；用延迟本地 HTTP 服务测试 0、99、100、5000、60001、非法值，核对超时 ok=false |  |
| A-026 | API／事件 | `GET /v1/events` | `src/api.rs:20`<br>`src/api.rs:132` | SSE 推送 traffic、conn_open、conn_close、log；每15秒注释保活，断开客户端释放连接 | 否 | curl --noproxy '*' -N 连接本地 API，触发本地请求/断开/模式日志，核对 event/data JSON、保活与重连 |  |
| A-027 | API／事件参数 | `?types=<逗号分隔事件类型>` | `src/api.rs:43`<br>`src/api.rs:133` | 只发送指定事件类型，省略发送全部；空值/未知类型无匹配事件但仍保活 | 否 | 本地测试 traffic,log、conn_open、空值与未知类型，确认无其他事件泄漏且保活仍在 |  |
| A-028 | API／当前配置 | `GET /v1/profile` | `src/api.rs:21`<br>`src/api.rs:339` | 返回当前 path 及相邻 .conf 配置列表 | 否 | 临时目录放两份 .conf 与一份非 .conf，GET 核对路径和列表 |  |
| A-029 | API／切换配置 | `POST /v1/profile` | `src/api.rs:22`<br>`src/api.rs:344` | 先校验构建，再原子切换；成功 reloaded/path/summary；失败400且仍为旧路径；监听和增强模式需另行重启 | 否 | 同监听的本地有效/无效配置切换；缺 path 为400；涉及 TUN设置或公网订阅需无Surge机器 |  |
| A-030 | API／切换配置参数 | `?path=<file>` | `src/api.rs:344` | 选择本地配置路径，百分号解码；不存在/坏配置失败 | 否 | 临时目录测试带中文/空格绝对路径、坏文件与不存在文件；GET /profile 验证回滚 |  |
| A-031 | API／诊断 | `POST /v1/diag` | `src/api.rs:49`<br>`src/api.rs:359` | 在固定日志目录生成脱敏 ZIP，返回 path；失败500；请求不能指定任意输出路径 | 否 | 隔离 HOME/SLUICE_LOG_DIR 与假凭据，POST 后解压核对脱敏；附加 out/path 参数不得改写任意位置；真实代理/TUN快照需无Surge机器 |  |
| A-032 | API／兼容方法 | `PUT /v1/policies/<group>?select=<opt>` | `src/api.rs:250` | 与 POST 选择策略行为一致（实现额外支持） | 否 | DIRECT/REJECT 手动组用 PUT 切换并 GET 核对，缺参仍400 |  |
| A-033 | API／兼容方法 | `PUT /v1/mode?set=<mode>` | `src/api.rs:261` | 与 POST 设置模式行为一致（实现额外支持） | 否 | 本地配置 PUT 三模式，核对响应与 GET |  |
| A-034 | API／兼容方法 | `PUT /v1/profile?path=<file>` | `src/api.rs:344` | 与 POST 切换配置行为一致（实现额外支持） | 否 | 本地有效/无效两文件测试成功与失败保留原路径 |  |
| A-035 | API／未匹配请求 | `未知路径／错误 HTTP 方法` | `src/api.rs:384` | 返回404 JSON error | 否 | 本地 API 请求 /v1/unknown、POST /v1/traffic、GET /v1/diag，核对404且无副作用 |  |

## 数量汇总

| 部分 | ID 范围 | 测试项数 |
| --- | --- | --- |
| A. GUI | G-001…G-233 | 233 |
| A2. 菜单栏（MenuBarExtra）功能与显示 | M-001…M-064 | 64 |
| B. CLI | C-001…C-031 | 31 |
| C. Control API | A-001…A-035 | 35 |
| 合计 |  | 363 |

GUI 分组明细：

| 分组 | 测试项数 |
| --- | --- |
| 全局、侧栏与共享交互 | 26 |
| 活动与统计 | 12 |
| 设置 | 15 |
| 策略 | 9 |
| 节点、订阅与详情 | 30 |
| 最近请求与活动连接 | 26 |
| DNS、规则与日志 | 26 |
| 配置管理与文本编辑 | 31 |
| 规则与策略组结构化编辑 | 33 |
| 菜单栏与应用命令 | 25 |

A2 分组明细：菜单及子菜单 34 项（M-001…M-034），显示设置与渲染 16 项（M-035…M-050），显示稳定性与菜单跟踪 14 项（M-051…M-064），共 64 项；均为待执行用例，不沿用原 G 行的历史执行结论。

全部结果待执行后填写；本文没有把扫描、编译或帮助命令检查记为功能通过。

## 执行结果（2026-10-30，本机 loopback，DIRECT/REJECT 与 file:// 订阅）

- CLI（C-001…C-031）：全部本地执行通过；`diag export` 包内 `._*` AppleDouble 文件（F1）已修复。
- API（A-001…A-035）：全部本地执行通过；A-023 默认测速 URL 需外网。观察：`DELETE /v1/connections/<id>` 返回 closed 后该连接仍在 `/active` 中约 3 秒。
- GUI：各页面主要按钮、表单、对话框、右键菜单、Picker、快捷键 ⌘1…⌘9/⌘S 均已点击验证。

| 编号 | 问题 | 涉及行 | 状态 |
| --- | --- | --- | --- |
| F1 | 诊断 zip 含 `._*` 文件 | C-027, A-031, G-052 | 已修复并复测 |
| F3 | 订阅行"复制服务器"复制占位文字 | G-073, G-089 | 已修复并复测 |
| F4 | 规则页"在配置中编辑"未打开规则编辑器 | G-131 | 已修复并复测 |
| F5 | 添加时弹窗标题为"编辑…"；错误提示不消失 | G-181, G-182 | 已修复并复测 |
| F6 | 确认对话框取消按钮为英文 Cancel | G-157, G-161, G-164 | 已修复并复测 |
| F7 | 活动连接右键菜单动作失效 | G-107…G-110 | 已修复并复测 |
| F8 | 菜单栏子菜单（出站模式/组选项/测试延迟）选择无效、菜单自动关闭 | G-211…G-215, G-221…G-223 | 已提交修复，待无 Surge 机器复测 |

需无 Surge 机器（见 `~/Desktop/Sluice实测说明-全按钮清单.md`）：G-005…G-008, G-039…G-041, G-046, G-047, G-062, G-071, G-090, G-216, G-217, G-229, G-233, A-023，以及各行中标注的系统代理/TUN/公网节点分支；另有 G-011, G-021, G-219, G-224…G-228 等少数按钮因时间转交清单第八节。
