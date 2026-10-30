# 特权 Helper（增强模式）

增强模式（TUN）需要 root。以前每次启动都通过 `osascript … with administrator privileges` 弹出管理员密码框；现在由一个 launchd 守护进程代为以 root 运行核心。

## 组成

| 文件 | 位置 |
| --- | --- |
| `SluiceHelper`（`apps/macos/Sources/SluiceHelper`） | `Sluice.app/Contents/MacOS/SluiceHelper` |
| `dev.sluice.Sluice.helper.plist`（`apps/macos/Helper`） | `Sluice.app/Contents/Library/LaunchDaemons/` |
| XPC 协议（`apps/macos/Sources/SluiceHelperShared`） | App 与 Helper 共用 |
| 核心哈希槽（`apps/macos/Sources/SluiceCoreHash`） | 编译进 Helper 的每个架构切片 |

`scripts/build-app.sh` 负责拷贝和签名（Helper 的签名标识为 `dev.sluice.Sluice.helper`，核心为 `dev.sluice.core`）。先签名核心，再用 `scripts/record-core-cdhash.sh <helper> <core>` 将核心各架构的 cdhash 写入 Helper，最后签名 Helper 和 App。写入会改变 Helper 的字节，因此必须在 Helper 签名前完成。

## 流程

1. 首次打开增强模式时，App 调用 `SMAppService.daemon(plistName:).register()`，系统提示用户到「系统设置 › 通用 › 登录项与扩展」允许 Sluice。在用户批准之前，App 打开该设置页，并且本次仍用管理员密码框启动。
2. 批准后，App 通过 Mach 服务 `dev.sluice.Sluice.helper`（`NSXPCConnection`，`.privileged`）发送 `start(config:appPID:)`。Helper 将 `Contents/Resources/sluice` 复制到受保护的暂存目录，校验副本签名后，以 root 运行副本的 `run <config>`。核心路径由 Helper 自己决定，调用方不能指定要执行的程序。核心输出写到 `/Library/Logs/Sluice/core.log`（root 拥有，0644），App 跟读这个文件。
3. 停止时调用 `stop`：Helper 发送 SIGINT，核心恢复路由和 DNS；如果 10 秒内没退出就 SIGKILL（utun 随进程关闭，DNS 备份在下次启动时恢复）。
4. **App 崩溃保护**：Helper 用 `DispatchSource.makeProcessSource(.exit)` 监视 App 的 PID，App 一退出（包括崩溃、被强杀）就停掉核心，TUN/DNS 不会残留。
5. 只要 Helper 不可用（`swift run` 开发运行、注册失败、XPC 出错、核心校验被拒绝），就自动回退到 osascript 管理员密码框。

命令行调试：`Sluice.app/Contents/MacOS/Sluice --helper status|register|unregister|hello`，以及 `SluiceHelper client hello|status|start <config> [watch-pid]|stop`。

## 调用方校验与安全性

- **Developer ID 签名**（Helper 读到自己的 Team ID 时）：对每个连接执行 `setCodeSigningRequirement("anchor apple generic and identifier \"dev.sluice.Sluice\" and certificate leaf[subject.OU] = \"<TEAM>\"")`。这项检查由内核基于 audit token 完成，不受 PID 复用影响。
- **ad-hoc 签名（当前状态）**：没有身份可以校验，只能检查调用进程的可执行文件路径（`proc_pidpath`），要求它等于同一 bundle 里的 `Contents/MacOS/Sluice`。这比签名校验**弱得多**：
  - PID 复用竞争：校验和后续消息之间，PID 有可能被换掉；
  - 能写入 `Sluice.app` 的任何人（同一用户，例如 App 放在 `~/Applications` 里）都能替换 `Sluice` 本体，从而请求以 root 运行已经通过校验的核心；
  - root 会读取调用方给出的任意配置文件路径，配置可以让核心监听端口、改路由和 DNS。
  Helper 不接受调用方传入的可执行文件，而且会独立校验核心；但在 ad-hoc 构建中，调用方身份校验仍然较弱。正式发布应使用 Developer ID。上述模型以 launchd 运行的 Helper 本身可信为前提，不能防止攻击者替换 Helper 本身。

## 核心校验与暂存

- 默认暂存目录是 `/Library/Application Support/Sluice/Helper`，只允许通过守护进程 plist 的 `EnvironmentVariables` 中的 `SLUICE_HELPER_STAGE_DIR` 覆盖，XPC 请求不能指定。缺失目录以 0700 创建；用 `lstat` 检查最终目录必须是目录、归 `geteuid()` 所有（系统 daemon 即 root），且不能被组或其他用户写入。祖先目录也拒绝符号链接及组/其他用户可写目录，所有者必须是 root 或 Helper 的有效用户，防止暂存路径被重命名替换。覆盖路径必须是绝对路径，不能使用 `/tmp` 等符号链接或公共可写目录。
- 每次启动都建立独立的 0700 子目录，将核心的字节复制到新的 0500 文件；不继承来源的 ACL、所有权或硬链接。来源必须是普通文件，拒绝符号链接。**只验证并执行暂存副本**，所以校验期间或之后替换 bundle 中的核心不会改变本次执行的文件。启动失败、校验拒绝或核心退出后清理本次副本。
- **Developer ID 签名**：Helper 读到自己的 Team ID 时，使用 `SecStaticCodeCheckValidity`，标志为 `kSecCSCheckAllArchitectures | kSecCSStrictValidate`，要求 `anchor apple generic and identifier "dev.sluice.core" and certificate leaf[subject.OU] = "<TEAM>"`。只接受同一团队、指定标识的有效签名核心。
- **ad-hoc 签名**：先用相同标志校验完整签名（不附加 requirement），再读取 `kSecCodeInfoUnique`，将十六进制 cdhash 与 Helper 内嵌的构建时列表比较。有效签名本身不足以获得信任：替换成其他有效签名程序也会被拒绝。
- `SluiceCoreHash` 的 C 槽是带 `volatile`、`used` 的 200 字节数组，以 `SLUICE-CORE-CDHASH:` 开头，其余初始为零。记录脚本通过 `lipo -archs` 和每个架构的 `codesign -d -a <arch> -vvv` 获取 cdhash，用 Perl 写入逗号分隔列表，并修补通用 Helper 中的全部槽。槽为空时明确报错并拒绝启动；只运行 `swift build` 得到的 Helper 需要先记录哈希，再重新 ad-hoc 签名，才能启动核心。
- 校验或目录检查失败均通过 `start` 的错误回复返回给 App，由 App 回退到管理员密码框。

## ad-hoc 签名下 SMAppService 是否可用

本机实测（macOS 27，ad-hoc 构建）：`register()` 成功，状态变为 `requiresApproval`，`unregister()` 也正常。也就是说，**注册本身不需要 Developer ID**。本机没有点击批准（这台机器运行 Surge，不在本机启用 TUN），所以「批准后 launchd 能否拉起 ad-hoc 签名的 daemon」没有在本机验证。已知 macOS 会对后台项做签名和 Gatekeeper 评估：未公证或被隔离（quarantine）的下载版可能被拒绝，或者每次构建后需要重新批准，因为 cdhash 会变。这种情况下 XPC 调用失败，App 自动回退到管理员密码框，功能不受影响。

结论：开发构建可以用 ad-hoc；面向用户分发时，App 和 Helper 都应使用同一个 Developer ID 签名，并启用 hardened runtime 和公证。签名后 Helper 自动切换到代码签名校验，无需改代码。

## CI

`.github/workflows/ci.yml` 的 `helper` job（`scripts/ci/helper.sh`）：CI 无法点击「批准」，所以先记录核心 cdhash 并用 `codesign -f -s -` 重新签名 Helper，再用 `launchctl bootstrap system` 加载一个等价的 plist（`Program` 指向构建出的 Helper，用环境变量指定核心路径和允许的客户端），然后用 `SluiceHelper client` 依次验证：XPC 握手以 root 运行、拒绝其他可执行文件、无 TUN 启停、将核心临时替换为 `/usr/bin/true` 后 `client start` 必须报错拒绝（随后恢复原核心）、通过 Helper 启动增强模式并通过 `tun-check.sh` 检查，再杀掉充当 App 的进程，确认 Helper 停止核心且路由/DNS 已恢复（`tun-check.sh after`）。
