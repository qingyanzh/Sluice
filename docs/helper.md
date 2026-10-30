# 特权 Helper（增强模式）

增强模式（TUN）需要 root。以前每次启动都通过 `osascript … with administrator privileges` 弹出管理员密码框；现在由一个 launchd 守护进程代为以 root 运行核心。

## 组成

| 文件 | 位置 |
| --- | --- |
| `SluiceHelper`（`apps/macos/Sources/SluiceHelper`） | `Sluice.app/Contents/MacOS/SluiceHelper` |
| `dev.sluice.Sluice.helper.plist`（`apps/macos/Helper`） | `Sluice.app/Contents/Library/LaunchDaemons/` |
| XPC 协议（`apps/macos/Sources/SluiceHelperShared`） | App 与 Helper 共用 |

`scripts/build-app.sh` 负责拷贝和签名（Helper 的签名标识为 `dev.sluice.Sluice.helper`）。

## 流程

1. 首次打开增强模式时，App 调用 `SMAppService.daemon(plistName:).register()`，系统提示用户到「系统设置 › 通用 › 登录项与扩展」允许 Sluice。在用户批准之前，App 打开该设置页，并且本次仍用管理员密码框启动。
2. 批准后，App 通过 Mach 服务 `dev.sluice.Sluice.helper`（`NSXPCConnection`，`.privileged`）发送 `start(config:appPID:)`。Helper 运行 `Contents/Resources/sluice run <config>`。核心路径由 Helper 自己决定，调用方不能指定要执行的程序。核心输出写到 `/Library/Logs/Sluice/core.log`（root 拥有，0644），App 跟读这个文件。
3. 停止时调用 `stop`：Helper 发送 SIGINT，核心恢复路由和 DNS；如果 10 秒内没退出就 SIGKILL（utun 随进程关闭，DNS 备份在下次启动时恢复）。
4. **App 崩溃保护**：Helper 用 `DispatchSource.makeProcessSource(.exit)` 监视 App 的 PID，App 一退出（包括崩溃、被强杀）就停掉核心，TUN/DNS 不会残留。
5. 只要 Helper 不可用（`swift run` 开发运行、注册失败、XPC 出错），就自动回退到 osascript。

命令行调试：`Sluice.app/Contents/MacOS/Sluice --helper status|register|unregister|hello`，以及 `SluiceHelper client hello|status|start <config> [watch-pid]|stop`。

## 调用方校验与安全性

- **Developer ID 签名**（Helper 读到自己的 Team ID 时）：对每个连接执行 `setCodeSigningRequirement("anchor apple generic and identifier \"dev.sluice.Sluice\" and certificate leaf[subject.OU] = \"<TEAM>\"")`。这项检查由内核基于 audit token 完成，不受 PID 复用影响。
- **ad-hoc 签名（当前状态）**：没有身份可以校验，只能检查调用进程的可执行文件路径（`proc_pidpath`），要求它等于同一 bundle 里的 `Contents/MacOS/Sluice`。这比签名校验**弱得多**：
  - PID 复用竞争：校验和后续消息之间，PID 有可能被换掉；
  - 能写入 `Sluice.app` 的任何人（同一用户，例如 App 放在 `~/Applications` 里）都能替换 `Sluice` 本体，从而以 root 运行核心；
  - root 会读取调用方给出的任意配置文件路径，配置可以让核心监听端口、改路由和 DNS。
  Helper 不接受调用方传入的可执行文件，所以无法借它运行任意程序；但在 ad-hoc 构建中，它仍是同一用户到 root 的一条「受限」提权路径。正式发布应使用 Developer ID。

## ad-hoc 签名下 SMAppService 是否可用

本机实测（macOS 27，ad-hoc 构建）：`register()` 成功，状态变为 `requiresApproval`，`unregister()` 也正常。也就是说，**注册本身不需要 Developer ID**。本机没有点击批准（这台机器运行 Surge，不在本机启用 TUN），所以「批准后 launchd 能否拉起 ad-hoc 签名的 daemon」没有在本机验证。已知 macOS 会对后台项做签名和 Gatekeeper 评估：未公证或被隔离（quarantine）的下载版可能被拒绝，或者每次构建后需要重新批准，因为 cdhash 会变。这种情况下 XPC 调用失败，App 自动回退到管理员密码框，功能不受影响。

结论：开发构建可以用 ad-hoc；面向用户分发时，App 和 Helper 都应使用同一个 Developer ID 签名，并启用 hardened runtime 和公证。签名后 Helper 自动切换到代码签名校验，无需改代码。

## CI

`.github/workflows/ci.yml` 的 `helper` job（`scripts/ci/helper.sh`）：CI 无法点击「批准」，所以用 `launchctl bootstrap system` 加载一个等价的 plist（`Program` 指向构建出的 Helper，用环境变量指定核心路径和允许的客户端），然后用 `SluiceHelper client` 依次验证：XPC 握手以 root 运行、拒绝其他可执行文件、无 TUN 启停、通过 Helper 启动增强模式并通过 `tun-check.sh` 检查，再杀掉充当 App 的进程，确认 Helper 停止核心且路由/DNS 已恢复（`tun-check.sh after`）。
