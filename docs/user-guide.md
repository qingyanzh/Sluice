# Sluice 中文用户指南

Sluice 是采用 Surge 风格配置的规则代理，包含命令行内核和 macOS 应用。普通模式提供 HTTP、SOCKS5 代理；增强模式通过 TUN 接管不遵循系统代理设置的应用。

本文依据当前仓库的[示例配置](../examples/sluice.conf)、[增强模式示例](../examples/tun-test.conf)、[配置解析器](../src/config.rs)及相关实现编写。Surge 风格不代表兼容 Surge 的全部配置；功能和参数以当前源码为准。当前支持通过 `[MITM]` 解密指定主机的 HTTPS，并进行 URL、Header 和 Body 重写；启用前需生成并信任 CA，详见[MITM 与证书信任](#7-mitm-与证书信任)。普通转发和仅开启增强模式不需要安装 CA。

首次使用可依次阅读[安装](#1-安装)、[首次运行](#2-首次运行)、[节点](#3-添加节点)或[订阅](#4-添加和更新订阅)。需要调整分流时阅读[规则](#5-规则与出站模式)；需要接管不遵循系统代理的应用时阅读[增强模式](#6-增强模式tun)。遇到问题可直接查看[故障排查](#9-故障排查)。

## 1. 安装

### 从源码构建 macOS 应用

应用要求 macOS 14 或更新版本；构建需要 Rust/Cargo 和 Swift 工具链，Swift 包声明的工具版本为 5.10。以下命令均在仓库根目录执行：

```sh
scripts/build-app.sh
open dist/Sluice.app
```

脚本会构建 Rust 内核和 SwiftUI 界面，将内核嵌入 `dist/Sluice.app`。可把该应用复制到“应用程序”目录后使用。

如果需要拖放安装的磁盘映像：

```sh
scripts/build-dmg.sh
```

产物为 `dist/Sluice-<Cargo.toml 中的版本号>.dmg`，打开后将 Sluice 拖入 Applications。

这里介绍仓库提供的源码构建方式。构建脚本使用本地临时签名（ad hoc），没有公证步骤；仓库没有给出 Homebrew 安装命令或正式安装包的下载说明。

### 只使用命令行内核

```sh
cargo build --release
./target/release/sluice check examples/sluice.conf
./target/release/sluice route examples/sluice.conf www.google.com
./target/release/sluice run examples/sluice.conf
```

`examples/sluice.conf` 包含占位节点和远程规则集。检查可能需要联网，示例节点不能直接用于实际代理；请先替换服务器及凭据。前台运行时用 `Ctrl+C` 停止。

## 2. 首次运行

1. 打开应用。首次启动会创建 `~/Library/Application Support/Sluice/sluice.conf`。
2. 在“配置”查看文件；在“设置”可查看当前配置路径，也可在“配置”中“选取…”其他文件。
3. 点击“启动”，确认状态为“运行中”。默认配置没有可用代理节点，`Proxy` 组只有 `DIRECT`，所以此时流量仍为直连。
4. 按下一节添加节点或订阅，然后到“策略”中选择实际节点或订阅组。
5. 在“设置”打开“系统代理”，按 macOS 提示输入管理员凭据；此操作设置网络服务的 HTTP、HTTPS 和 SOCKS 代理。
6. 访问目标网站，在“请求”查看匹配规则和实际出站，在“日志”查看错误。

系统代理与内核启动是两个操作。仅启动内核不会让应用自动使用代理；不遵循系统代理的软件需要单独设置代理，或使用增强模式。

默认监听地址如下；如果你修改了配置，请使用自己的端口：

| 用途 | 地址 |
| --- | --- |
| HTTP 代理，也用于 HTTPS 的 CONNECT 隧道 | `127.0.0.1:6252` |
| SOCKS5 代理 | `127.0.0.1:6253` |
| 应用控制 API | `127.0.0.1:6170` |

例如，可以先用显式代理测试，排除系统代理设置的影响：

```sh
curl --proxy http://127.0.0.1:6252 https://example.com/
curl --proxy socks5h://127.0.0.1:6253 https://example.com/
```

默认情况下，关闭主窗口后应用仍在菜单栏运行。停止或退出内核前，先关闭“系统代理”；当前停止/退出逻辑不负责自动关闭系统代理，否则应用可能继续向已停止的本地端口发请求。

### 可从零开始的最小配置

下面与应用首次生成配置的主要内容一致，不包含远程资源，可保存为 `sluice.conf` 后检查和运行。它只用于验证本地代理服务，出站为直连：

```ini
[General]
http-listen = 127.0.0.1:6252
socks5-listen = 127.0.0.1:6253
api-listen = 127.0.0.1:6170
loglevel = info

[Proxy]

[Proxy Group]
Proxy = select, DIRECT

[Rule]
DOMAIN-SUFFIX,local,DIRECT
FINAL,Proxy
```

macOS 应用通过 `127.0.0.1` 上的 API 管理内核，应保留示例中的 `api-listen`。单独使用命令行时可以省略它。上述监听端口来自应用初始配置和示例文件；内核不会自动补上被省略的 HTTP 或 SOCKS5 监听项。

### 编辑配置时的约定

配置使用 UTF-8 文本，节名按 `[General]`、`[Proxy]`、`[Proxy Group]`、`[Host]`、`[Rule]`、`[MITM]`、`[URL Rewrite]`、`[Header Rewrite]`、`[Body Rewrite]` 的大小写书写。以 `#`、`;` 或 `//` 开头的整行可以作为注释；示例中的说明应另起一行，不要放在参数末尾。节点和组的名称、规则引用应保持一致，避免重名或循环引用。

后续代码块除明确标为完整配置外，均为片段。编辑已有配置时，将内容合并到同名节；规则插在 `FINAL` 之前，不要直接把整段追加到文件末尾。节点、策略组和规则参数用逗号分隔，给值加引号不能转义其中的逗号；重写行使用空白分隔，语法见第 7 节。不要直接粘贴其他客户端的完整配置后就认为全部功能已生效：未知节和部分未知参数会被忽略。

## 3. 添加节点

### 在应用中导入

打开“节点”→“添加节点”，粘贴**一个**分享链接或**一行**代理定义，再点击“添加”。当前可识别 `ss://`、`vmess://`、`vless://`、`trojan://`、`anytls://`、`hysteria2://`（也接受 `hy2://`）。具体参数仍需在内核支持范围内，例如 Shadowsocks 插件不受支持。

应用会转换并检查输入，保存到 `[Proxy]`，并尝试加入 `FINAL` 指向的 `select` 组。默认配置中的这个组就是 `Proxy`。如果你把 `FINAL` 改成了节点、`DIRECT` 或其他类型的组，需要自行在配置中安排引用。新增节点不会自动取代当前选择；到“策略”中选择它。

命令行也可以转换分享链接；将 `实际分享链接` 替换为提供方给出的内容：

```sh
./target/release/sluice convert '实际分享链接'
```

输出是一行可放进 `[Proxy]` 的定义，不会自动修改配置文件。

### AnyTLS

支持 AnyTLS v2（anytls-go、sing-box、mihomo），使用 TLS、流复用与填充；空闲会话最多保留 4 个，30 秒后关闭。UDP 使用 sing-box UoT v2，每个目标地址独立建立流。

```ini
[Proxy]
AnyTLS = anytls, proxy.example.com, 443, password=change-me, sni=proxy.example.com, udp=true
```

可选 `skip-cert-verify=true`、`alpn=h2|http/1.1`；默认校验证书、不发送 ALPN，并启用 UDP。`udp=false` 禁用 UDP。`tfo` 会保留配置值，但当前仍使用普通 TCP 连接。Clash YAML 的 `type: anytls` 也可导入，`client-fingerprint` 接受但忽略（使用 rustls）。分享链接示例：`anytls://password@proxy.example.com:443?sni=proxy.example.com&insecure=1#Name`，其中 `insecure=1` 表示跳过证书验证，密码和名称可使用百分号编码。

### 手动编辑配置

以下节点定义来自 `examples/sluice.conf`。将片段合并到配置中的同名节，替换服务器、端口、密码或 UUID；不要保留重复的节点或组定义。

```ini
[Proxy]
HK-SS = ss, hk.example.com, 8388, encrypt-method=aes-256-gcm, password=change-me
JP-Trojan = trojan, jp.example.com, 443, password=change-me, sni=jp.example.com
SG-VMess = vmess, sg.example.com, 443, username=b831381d-6324-4d53-ad4f-8cda48b30811, encrypt-method=auto, tls=true, sni=sg.example.com
KR-Hy2 = hysteria2, kr.example.com, 443, password=change-me, sni=kr.example.com
CDN-VMess = vmess, cdn.example.com, 443, username=b831381d-6324-4d53-ad4f-8cda48b30811, tls=true, ws=true, ws-path=/ray, ws-headers=Host:cdn.example.com
US-VLESS = vless, us.example.com, 443, uuid=b831381d-6324-4d53-ad4f-8cda48b30811, tls=true, sni=us.example.com

[Proxy Group]
Proxy = select, Auto, HK-SS, JP-Trojan, US-VLESS, DIRECT
Auto = url-test, HK-SS, JP-Trojan, US-VLESS, url=http://www.gstatic.com/generate_204, interval=300, tolerance=50
Backup = fallback, HK-SS, JP-Trojan, interval=120
Spread = load-balance, HK-SS, JP-Trojan
```

节点存在于 `[Proxy]` 并不意味着会被使用：它必须被规则直接引用，或加入规则所用的策略组。上例中的 `SG-VMess`、`KR-Hy2`、`CDN-VMess` 仅展示语法；要使用它们，请将名称加入 `Proxy` 等组。

| 组类型 | 行为 |
| --- | --- |
| `select` | 在“策略”或菜单栏手动选择选项；新启动时默认第一项 |
| `url-test` | 按健康检查延迟选择；`tolerance` 为切换所需的延迟改善值，单位毫秒 |
| `fallback` | 按配置顺序选择第一个健康选项 |
| `load-balance` | 每个新连接在健康选项中随机选择 |

组可以嵌套。自动组按 `interval` 秒探测，默认 600 秒，最小 10 秒；默认测试地址为 `http://www.gstatic.com/generate_204`。当前探测地址解析只接受 `http://`。可在“策略”点“测试”或“测试全部”；这里测的是经节点访问测试地址的耗时，不是带宽。

自动组不会保证所有连接成功。`url-test`、`fallback` 全部探测失败时保留原选择；`load-balance` 把未测试的选项视为可用，全部失败时仍会从原有选项中尝试。可在“策略”和日志中确认当前选项及探测结果。

其他参数如 REALITY、gRPC、XHTTP、Vision 和 Hysteria2 端口跳跃，在当前解析器和对应协议实现中已有支持。高级组合应按服务端参数核对 [config.rs](../src/config.rs) 和[互通脚本](../scripts/ci/interop.sh)；**本文未验证你的服务端组合是否兼容**，不要仅凭协议名称套用其他客户端的参数。

## 4. 添加和更新订阅

在“节点”→“添加订阅”填写 HTTP/HTTPS 订阅地址，可选填写名称及名称过滤正则，例如 `香港|HK`。保存前应用会获取订阅内容（可能命中缓存）并检查配置。订阅会成为独立的 `select` 组，并尝试加入 `FINAL` 指向的 `select` 组。使用时先在 `Proxy` 组选订阅组，再在该订阅组中选节点。

订阅导入支持：

- 分享链接列表，明文或整体 Base64 编码。
- Surge 风格的代理行，或完整的 Surge 托管配置（仅导入 `[Proxy]` 段，跳过内置策略和不支持的类型）。
- 含 `proxies:` 的 Clash / Mihomo YAML 节点列表；这不代表支持其整个配置文件中的规则及所有扩展。

手写配置还可以使用本地订阅文件。以下是订阅组的配置片段，将 `policy-path` 替换为实际地址，并把组加入 `Proxy`：

```ini
[Proxy Group]
Proxy = select, Airport, DIRECT
Airport = url-test, policy-path=https://example.com/your-subscription, policy-regex-filter=香港|HK, update-interval=86400
```

这是示例 URL，不能直接获取真实节点。`policy-regex-filter` 可省略，表示保留全部节点；`policy-path` 也可写本地文件路径，相对路径以配置文件所在目录为基准。应用的“添加订阅”表单只接受 HTTP/HTTPS 地址，本地路径请在“配置”中编辑。

默认请求 User-Agent 为 `clash.meta mihomo/1.18.10 Sluice/<版本>`。如服务商要求，可在“添加订阅”的可选 User-Agent 栏填写，或在订阅组添加 `user-agent="自定义值"`。下载支持最多 5 次重定向、chunked、gzip/deflate；HTTP 错误会显示状态码及响应正文摘要。

控制 API `GET /v1/subscriptions` 返回各订阅的组名、地址、流量用量（字节）、总量、到期时间、服务端建议更新间隔（小时）、最后成功下载时间、下载错误及过滤后节点数。时间使用 Unix 秒，未提供的信息为 `null`；用量元数据随磁盘缓存保存。服务端建议间隔仅展示，实际更新仍使用配置中的 `update-interval`。

`update-interval` 单位为秒，默认 86400，最小 60。内核运行期间会按订阅更新间隔触发重新载入。相同来源及 User-Agent 的组共享导入节点，也可以使用不同过滤条件。不支持或格式有误的订阅条目会被跳过并记录原因；过滤后若组没有任何可用选项，内核会放入 `REJECT`，不会自动直连。保存成功只表示配置可加载；仍需到“策略”确认实际导入了哪些节点。

“节点”页显示配置中的独立节点和订阅入口；订阅展开后的节点在“策略”页查看和选择。要修改订阅地址、过滤条件，或删除节点和订阅，在“配置”中编辑相应定义，并同步删除组和规则中对它们的引用，再检查和保存。

远程订阅与规则集共用磁盘缓存，位置按内核进程的 `$HOME` 为 `Library/Caches/Sluice`，普通用户运行通常是 `~/Library/Caches/Sluice`。增强模式以 root 运行时，不应假定仍使用同一缓存目录。

“重新载入配置”会重新构建配置，但缓存未过期时不保证重新下载订阅；“节点”页的“刷新列表”只更新显示。下载失败且有旧缓存时会回退到旧缓存，因此看到旧节点不一定是重新载入失败。请结合日志判断。

## 5. 规则与出站模式

### 自上而下匹配

`[Rule]` 按顺序匹配，第一条命中即停止。策略可以写节点名、组名，或内置的 `DIRECT`（直连）、`REJECT`（拒绝）。最后一条必须是 `FINAL,策略名`，名称必须与定义一致。

下面基于 `examples/sluice.conf`，省略需要外部资源的规则，适用于已定义 `Proxy` 组的配置：

```ini
[Rule]
DOMAIN-KEYWORD,adservice,REJECT
DOMAIN-SUFFIX,google.com,Proxy
DOMAIN-SUFFIX,github.com,Proxy
DOMAIN,localhost,DIRECT
IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
FINAL,Proxy
```

`DOMAIN` 精确匹配域名，`DOMAIN-SUFFIX` 匹配本域及其子域名，`DOMAIN-KEYWORD` 匹配域名中的字符串。`no-resolve` 表示不为这条 IP 规则主动解析目标域名；它仍可匹配原本就是 IP 的目标。

内核还支持以下规则，详见 [rule.rs](../src/rule.rs)：

| 类型 | 条件及限制 |
| --- | --- |
| `IP-CIDR6` | IPv6 地址段 |
| `GEOIP` / `IP-ASN` | 国家或 ASN；分别需要 `[General]` 的 `geoip-db` / `asn-db` 指向有效 MaxMind 数据库，否则相应规则不会命中 |
| `PROCESS-NAME` | 客户端进程名；TUN 模式识别其他用户的进程需要 root |
| `DST-PORT` / `IN-PORT` | 目标端口 / 本地代理入口端口；入口端口条件不适用于 TUN |
| `SRC-IP` | 客户端源 IP 或网段 |
| `PROTOCOL` | `TCP`、`UDP`、`HTTP`、`HTTPS`、`QUIC`；具体分类取决于入口提供的连接信息 |
| `URL-REGEX` | 明文 HTTP 请求及 MITM 解密后的 HTTPS 请求可匹配完整 URL（含路径和查询）；未解密的 HTTP CONNECT 仅提供 `https://host/`，不能匹配隧道内 HTTPS 的路径 |
| `AND` / `OR` / `NOT` | 组合条件；子规则不用填写策略 |

组合语法示例，插入 `FINAL` 之前：

```ini
AND,((DOMAIN,a.com),(DST-PORT,443)),Proxy
```

### 外部规则集

以下片段同样放在 `[Rule]` 中、`FINAL` 之前；本地文件需自行提供：

```ini
RULE-SET,rules/custom.list,Proxy
DOMAIN-SET,https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/gfw.txt,Proxy
```

`RULE-SET` 读取 Surge 风格的规则列表，策略由引用行统一指定；`DOMAIN-SET` 读取域名列表，其中 `.example.com` 表示包含本域及子域。也接受 Clash 的 `payload:` 列表。本地相对路径以配置文件目录为基准。规则集中的不支持条目会被跳过；远程文件下载成功并不表示其中每一条都受支持，可在运行日志中查看加载数量和跳过数量。

远程规则集默认每 86400 秒更新，可用 `[General]` 中的 `rule-set-update-interval` 调整（单位秒，最小 60）。缓存与下载失败回退机制见订阅一节。首次下载失败且没有缓存时，运行内核可警告后以空规则集继续；检查命令会报错，不能把“内核在运行”等同于远程规则已生效。

### 出站模式和规则测试

“策略”及菜单栏提供三种出站模式：

- **规则判定**：按 `[Rule]` 匹配。
- **直接连接**：所有进入 Sluice 的流量直接出站。
- **全局代理**：所有进入 Sluice 的流量使用 `FINAL` 指向的策略。如果该策略或组当前选的是 `DIRECT`，结果仍是直连。

出站模式只决定进入 Sluice 后的处理方式。接管范围仍由系统代理、应用自身代理设置或增强模式决定。

在“规则”页输入主机进行测试。内核运行时使用实时判定；停止时只有离线预览，会跳过部分需要 DNS、数据库或规则集的条件。命令行也可执行：

```sh
./target/release/sluice route "$HOME/Library/Application Support/Sluice/sluice.conf" www.google.com:443
```

命令会加载文件并显示规则、策略、最终出站，不会实际访问该目标；它新建路由器，不反映正在运行的内核中的手动选择或探测状态。要判断当前行为，以运行中的应用测试和“请求”为准。路由测试通过也不保证节点能连通。

## 6. 增强模式（TUN）

增强模式适合需要代理不遵循系统代理设置的应用或 UDP 流量的情况。当前 macOS 实现直接创建 `utun` 并调整路由和 DNS，需要 root；不是 Network Extension 安装流程。应用通过 `osascript` 的 `do shell script … with administrator privileges` 启动 root 内核，没有安装常驻的 privileged helper（特权辅助程序）；源码中的 `Privileged` 只是调用管理员授权的封装，见 [System.swift](../apps/macos/Sources/SluiceApp/System.swift) 和 [Core.swift](../apps/macos/Sources/SluiceApp/Core.swift)。

### 开启与关闭

在“设置”或菜单栏打开“增强模式”。应用会检查并保存配置；若内核已在运行，会重启以应用设置，否则下次启动时生效。启动时按 macOS 管理员提示授权。关闭增强模式同样需要重启内核；停止、重启或退出时，应用通过管理员授权发送 `SIGINT` 给 root 内核，也可能再次出现提示。取消停止授权可能让内核继续运行，应确认它已停止再启动另一份。

手动配置时，将以下设置合并到现有 `[General]`；保留原来的节点、策略组和规则：

```ini
[General]
enhanced-mode = true
fake-ip-range = 198.18.0.0/15
```

命令行启动示例：

```sh
sudo ./target/release/sluice run "$HOME/Library/Application Support/Sluice/sluice.conf"
```

切勿同时让应用和命令行启动同一套监听端口或两套增强模式内核。

### 网络与 DNS 行为

- IPv4 的 `0.0.0.0/1`、`128.0.0.0/1` 路由进入 TUN；默认 TUN 地址为 `198.18.0.1`，系统各网络服务的 DNS 指向 `198.18.0.2`。
- 普通 A 查询返回 fake IP，内核再将它映射回域名，使域名规则可用于 TUN 流量。普通 AAAA 查询返回空结果，使域名连接使用 IPv4；`[Host]` 指定的静态或分域 DNS 答案优先，不遵循这套普通 fake-IP 回答流程。
- 系统存在 IPv6 默认路由时，也接管 `::/1` 和 `8000::/1`，处理直接连接 IPv6 地址的应用。不要将此理解为 fake-IP DNS 会生成 IPv6 地址。
- 默认接管进入 TUN 的 UDP 53 端口 DNS 查询。应用自带的 DoH/DoT 等加密 DNS 不会因此被解密；若目标以真实 IP 进入 TUN，域名规则可能无法匹配。
- 内核自身连接绑定物理接口，避免流量回到 TUN。其他 VPN、代理的 TUN 或网络扩展可能造成冲突，应先停止冲突的接管服务。

上游 DNS 默认复用启动时检测到的系统服务器，也可像示例配置那样设置 `dns-server`。加密 DNS 与静态域名的写法见 `examples/tun-test.conf`，例如：

```ini
[General]
encrypted-dns-server = https://1.1.1.1/dns-query, tls://8.8.8.8

[Host]
sluice-static.test = 10.9.8.7
example.net = server:https://1.1.1.1/dns-query
iana.org = server:tls://8.8.8.8
wikipedia.org = server:quic://dns.adguard-dns.com
```

`encrypted-dns-server` 支持 DoH（`https://`）、DoT（`tls://`）、DoQ（`quic://`），用于解析器的真实查询；普通 A 查询仍可走 fake-IP 流程。应按实际网络选择可达的上游；配置了加密 DNS 也不代表所有 DNS 请求都不会回退到普通上游。

若使用 `dns-server`，按 `examples/sluice.conf` 的注释填写裸 IP 地址，以逗号分隔；增强模式启动时不接受在这里写 DoH URL 或 `IP:端口`。加密上游应填写在 `encrypted-dns-server` 或 `[Host]` 的 `server:` 项中。

正常停止时，内核恢复路由和原 DNS。崩溃可能留下 DNS 指向 fake-IP 服务器；下次以增强模式启动时，会尝试从 `/var/tmp/sluice-dns-backup` 恢复，再进行接管。不要在恢复前删除该备份。

## 7. MITM 与证书信任

MITM 对 `[MITM]` 的 `hostname` 列表命中的 TLS 连接动态签发网站证书，解密后按每个 HTTP 请求单独分流。HTTP 代理的 CONNECT、SOCKS5 和增强模式的 TCP 流量均支持；客户端可使用 HTTP/1.1 或 HTTP/2。未命中的 HTTPS 仍按原方式转发。明文 HTTP 也支持重写，无需 CA；SOCKS5 和 TUN 的明文 HTTP 重写入口限目标端口 80。

### 生成 CA 并在钥匙串中信任

在仓库根目录，以日常用户身份运行：

```sh
./target/release/sluice mitm gen-ca
```

命令在 `~/Library/Application Support/Sluice/` 写入 `ca.crt` 和 `ca.key`，证书名称为 `Sluice MITM CA <随机标识>`，新建私钥文件权限为 `0600`。**Sluice 不会自动安装或信任 CA**，命令会打印对应的 macOS 信任命令：

```sh
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain \
  "$HOME/Library/Application Support/Sluice/ca.crt"
```

也可打开“钥匙串访问”，将 `ca.crt` 导入“系统”钥匙串，打开该证书，在“信任”中将 SSL 设为“始终信任”，保存并按提示授权。使用独立证书库的客户端还需在其自身信任设置中导入 CA。仅导入公开证书 `ca.crt`；妥善保管 `ca.key`，不要分享私钥。

已有 `ca.crt` 时生成命令会拒绝覆盖。确需更换时用 `./target/release/sluice mitm gen-ca --force`，随后重新信任新证书、移除旧 CA 的信任并重新载入配置；已有连接需重新建立。

### 主机列表与 CA 配置

将以下片段合并到配置，替换成你需要解密的主机：

```ini
[MITM]
hostname = example.com, *.example.com, alt.example.net:8443, -skip.example.com
skip-server-cert-verify = false
h2 = true
```

`hostname` 用逗号分隔，匹配不区分主机名大小写。`example.com` 只匹配该主机；`*.example.com` 匹配子域名，不包含根域名。包含项未写端口时只匹配 443，其他 TLS 端口须显式写成 `host:port`。以 `-` 开头的排除项优先于包含项，当前排除主机的所有端口。未填写主机列表时 MITM 关闭。`h2` 默认 `true`，控制是否向解密客户端提供 HTTP/2。

未指定 CA 时，内核从**自身进程的 `$HOME`** 下读取上述默认文件。增强模式以 root 运行，不能假定与普通用户使用同一 `$HOME`。为使应用检查和 root 内核读取同一份 CA，建议在 `[MITM]` 显式设置 PEM 文件的绝对路径（将 `你的用户名` 换成实际用户名；路径不用加引号）：

```ini
[MITM]
ca-cert = /Users/你的用户名/Library/Application Support/Sluice/ca.crt
ca-key = /Users/你的用户名/Library/Application Support/Sluice/ca.key
```

这两项与前面的主机列表合并。路径中的 `~/` 按内核进程的 `$HOME` 展开；相对 CA 路径以进程工作目录为基准，不是配置文件目录。不要在配置里写 `$HOME` 期待变量替换。

也可以用含 CA 证书及私钥的 PKCS#12：设置 `ca-p12 = /绝对路径/ca.p12` 或 `ca-p12 = <Base64 内容>`，并用 `ca-passphrase = 密码` 指定口令（省略为空）。`ca-p12` 优先于 PEM 设置；客户端仍须信任该 CA 的公开证书。这些选项及匹配行为见 [mitm.rs](../src/mitm.rs)。

### URL、Header 与 Body 重写

下面的片段适用于上面已启用 MITM 的 `example.com`；`https?` 表示也匹配明文 HTTP。重写行按空白分隔，含空格的值用双引号包住；不要添加行尾注释。

```ini
[URL Rewrite]
^https?://example\.com/old(.*)$ https://example.com/new$1 302
^https://example\.com/temp$ https://example.com/new 307
^https?://example\.com/ads/ _ reject
^https://example\.com/api/(.*)$ https://example.com/v2/$1 header

[Header Rewrite]
http-request ^https?://example\.com/ header-add X-Sluice yes
http-request ^https?://example\.com/ header-replace User-Agent "Sluice Test"
http-response ^https?://example\.com/ header-del Server
http-response ^https?://example\.com/ header-add X-Sluice-Rewrite ok

[Body Rewrite]
http-response ^https?://example\.com/ "Example Domain" "Sluice Domain"
```

- `[URL Rewrite]` 格式为 `URL正则 替换内容 302|307|reject|header`，第一条命中即决定结果。`302`、`307` 返回对应重定向；`reject` 返回 404，仍须填写占位替换值（上例为 `_`）；`header` 在内部修改请求 URL 后继续转发，不是修改某个 Header。替换支持 `$1` 等正则捕获组。
- `[Header Rewrite]` 格式为 `http-request|http-response URL正则 操作 头名称 [值]`。`header-add` 追加，`header-del` 删除，`header-replace` 仅替换已存在的头。所有同方向且命中的行依次执行；未写方向时默认为请求。
- `[Body Rewrite]` 格式为 `http-request|http-response URL正则 内容正则 替换内容 [内容正则 替换内容…]`，同方向命中的行按顺序执行，每对内容正则替换全部匹配，也支持捕获组；未写方向时默认为请求。适合文本内容，当前按 UTF-8 文本处理，不适合二进制。匹配响应 Body 重写时会移除请求的 `Accept-Encoding`；若响应仍带非 `identity` 的内容编码，则跳过响应 Body 重写。需重写的 Body 最多缓冲 8 MiB，超限会导致请求失败（502）。

URL 重写先于分流；内部 `header` 重写后的 URL 用于后续 Header、Body 匹配和路由。MITM 解密后，`URL-REGEX` 能按 HTTPS 的路径和查询匹配，例如将 `URL-REGEX,^https://example\.com/blocked,REJECT` 插入 `[Rule]` 的 `FINAL` 之前。已进入路由的解密请求会在 `/v1/connections` 中包含完整 `url` 和 `"mitm": true`；直接由 URL 重写返回的重定向或拒绝不会进入该路由记录。

保存并应用配置后，可用以下命令检查示例的响应头和文本替换；`--cacert` 显式为这次 curl 请求指定 CA，不依赖 curl 是否使用钥匙串：

```sh
curl --proxy http://127.0.0.1:6252 \
  --cacert "$HOME/Library/Application Support/Sluice/ca.crt" \
  -D - https://example.com/
```

预期响应头包含 `X-Sluice-Rewrite: ok`，正文中的 `Example Domain` 变成 `Sluice Domain`。也可参考仓库的 [MITM 检查脚本](../scripts/ci/mitm.sh)和 [TUN 检查脚本](../scripts/ci/tun.sh)。

### 信任范围与限制

客户端对 Sluice CA 的信任与内核对真实网站、代理节点的证书校验是两回事。`[MITM]` 的 `skip-server-cert-verify` 默认 `false`，控制解密后连接真实网站时的证书校验；`[Proxy]` 的 `tls=true`、`sni=...`、`skip-cert-verify` 属于代理节点连接参数。不要用跳过服务端验证来解决客户端不信任 Sluice CA 的问题。

内核的普通 TLS/QUIC 校验使用依赖内置的公共根证书集合，见 [trojan.rs](../src/trojan.rs)，不读取 macOS 钥匙串。`ca-cert` / `ca-key` 用于签发解密证书，不是添加上游可信根；在钥匙串中信任一个私有 CA，不会自动让内核接受它签发的网站或节点证书。

当前 MITM 解密 TCP 上的 HTTPS，不解密 HTTP/3 / QUIC（UDP）。采用证书固定（certificate pinning）的应用也可能拒绝动态证书；可用 `-hostname` 排除该主机。TUN 按目标主机匹配，通常依赖 fake-IP 映射恢复域名；直接以真实 IP 进入时不会自动按 TLS SNI 匹配域名列表。

## 8. 保存、检查与重新载入

在“配置”编辑后，可先点“检查”，再点“保存并应用”（停止状态下显示“保存”）。应用先用 `sluice check` 校验，失败时保留草稿并提示原因；若磁盘文件被外部修改，会要求载入磁盘版本，可先复制草稿保留修改。

命令行检查实际文件：

```sh
./target/release/sluice check "$HOME/Library/Application Support/Sluice/sluice.conf"
```

检查不仅解析语法，还会加载订阅和规则集、检查策略引用及数据库等；配置了 MITM 主机列表时，还会读取 CA 证书和私钥。远程资源不可达也可能导致检查失败。`check` 不会验证客户端是否信任 CA，也不会绑定监听端口、创建 TUN 或测试节点连接；部分增强模式参数也在启动时才校验。因此仍需启动内核并确认日志，不能把检查成功当作连通性验证，也不能据此判断未知参数有效。

运行内核每约 2 秒检查配置文件变化，也支持菜单栏“重新载入配置”和控制 API 触发重新载入（`SIGINT`、`SIGTERM`、`SIGHUP` 均会退出内核并恢复网络）。新连接使用新配置，已有连接继续使用旧配置；仍存在的组和选项会继承手动选择及健康检查状态。构建新配置失败时保留运行中的配置。

`[MITM]` 和三个重写节支持重新载入；已有的 TLS / HTTP 长连接继续使用旧配置，验证修改时应新建连接。仅替换 CA 文件而未改配置时，应主动重新载入，并确认客户端信任的新证书与内核使用的 CA 一致。

HTTP/SOCKS5/API 监听地址，以及增强模式开关、`tun-mtu`、`fake-ip-range`、TUN 启动所用的 `dns-server` 更改后需要**重启内核**。手动选择在热重载时可继承，但不要假定完整停止再启动后仍会保留。

## 9. 故障排查

先查看“日志”的第一条具体错误，再核对“请求”中的规则和实际出站。普通模式的内核输出显示在应用日志页或运行它的终端；应用启动的增强模式内核还写入 `~/Library/Logs/Sluice/core.log`。

| 现象 | 排查与处理 |
| --- | --- |
| 应用提示找不到内核 | 从源码重新运行 `scripts/build-app.sh`；仅运行 Swift 界面时需先构建 Rust 内核 |
| 应用提示缺少 API，或一直启动中 | 在 `[General]` 配置 `api-listen = 127.0.0.1:6170`；检查日志中 API 是否监听成功，修改端口后重启 |
| `Address already in use` | 停止其他 Sluice 内核或占用该端口的代理；也可修改相应监听端口并同步应用自身代理设置，然后重启 |
| 检查报 `line N`、未知策略、重复名称或 `the last rule must be FINAL` | 按行号核对语法；确保节点及组名唯一、引用存在，最后一条是 `FINAL` |
| “运行中”但仍直连 | 默认配置仅有 `DIRECT`；检查是否已开启系统代理、选中实际节点，以及出站模式是否为“直接连接” |
| 浏览器能代理，其他应用不能 | 确认该应用是否遵循系统代理；单独设置 HTTP/SOCKS5 代理或使用增强模式 |
| 添加订阅后没有节点或全部被拒绝 | 检查地址返回的是节点列表、过滤正则是否过严、日志中是否有跳过原因；空订阅组会使用 `REJECT` |
| 重新载入后订阅仍旧 | 检查更新间隔和磁盘缓存；重新载入不保证绕过缓存，下载失败时可能使用旧缓存 |
| `GEOIP` / `IP-ASN` 不生效 | 配置正确的 `geoip-db` / `asn-db` 文件；示例注释中的路径不是可用数据库，未设置时不会匹配 |
| 自动组测试全部失败 | 核对凭据和传输参数，检查测试 URL 是否可达且为 `http://`；探测失败不一定表示所有目标都不可达 |
| TLS 或认证错误 | 核对密码、UUID、SNI、TLS/REALITY 与服务端要求；分享链接可解析不等于端到端可用 |
| MITM 后出现不受信任证书或握手失败 | 确认客户端信任的是内核实际使用的 CA；独立证书库需单独导入。核对 `hostname`、端口和排除项；证书固定的应用可排除该主机；QUIC 不在解密范围内 |
| MITM 提示无法读取 CA，尤其是开启增强模式后 | 先以普通用户运行 `sluice mitm gen-ca`；在 `[MITM]` 用 `ca-cert` / `ca-key` 指定同一份 CA 的绝对路径，核对文件存在且当前检查进程和 root 内核均可读取 |
| HTTPS 重写或路径规则不生效 | 确认主机命中 `[MITM]`、客户端已信任 CA，且使用 TCP HTTPS；查看 `/v1/connections` 的 `url` / `mitm`，重新建立连接，并核对重写行的空白分隔语法 |
| 增强模式提示需要 root、授权取消 | 使用应用管理员提示或 `sudo ... run`；当前没有需另行安装的特权 helper，普通用户运行无法创建所需 TUN 接管。取消停止授权后应确认旧内核已退出 |
| 增强模式提示 `198.18.0.1` 已被其他接口占用 | 先退出其他代理的 TUN；确需更换 `fake-ip-range` 时选择无冲突网段并重启，当前允许的 IPv4 前缀为 `/8` 至 `/24` |
| 增强模式开启后断网，出现 egress self-test 失败 | 查看日志中的物理接口和上游 DNS，停止其他 VPN/网络扩展后重试；不要反复叠加接管服务 |
| 增强模式重启后，个别应用仍访问旧 fake IP，日志出现 `unknown fake IP` | 旧 DNS 缓存中的地址可能已没有映射；让应用重新解析域名，必要时退出并重开该应用 |
| 停止 Sluice 后仍无法联网 | 先关闭残留的系统代理；若 DNS 仍指向 `198.18.0.2`，按下述恢复步骤处理 |

### 增强模式诊断与网络恢复

仓库提供以下诊断脚本，在仓库根目录运行：

```sh
scripts/tun-diag.sh
scripts/tun-check.sh
```

`tun-diag.sh` 用于查看绑定物理接口的路由情况。`tun-check.sh` 是针对默认地址和 `examples/tun-test.conf` 的联网检查，包含规则、静态域名及加密 DNS 测试，会下载约 10 MB 测试数据，并通过 API 清空内核 DNS 缓存；用于其他配置时，部分失败可能只是测试预期不同。运行检查还需 `curl`、`dig` 和 Python 3。要复现该示例，请先停止现有内核，再运行：

```sh
sudo ./target/release/sluice run examples/tun-test.conf
```

在另一个终端执行检查。这个配置的默认出站为 `DIRECT`，用于验证 TUN，并不提供真实代理节点。停止后再检查清理情况：

```sh
scripts/tun-check.sh after
```

如果崩溃后 DNS 残留，可先重新启动增强模式，再正常停止，让内核尝试恢复备份。如仍无法恢复，在 macOS 当前网络服务的 DNS 设置中，恢复你原来的服务器；原来使用自动 DNS 的，应移除残留的 fake-IP DNS。避免在不知道原配置时覆盖手动 DNS。

需要反馈问题时，提供相关错误、出站模式、是否使用增强模式、复现步骤及脱敏后的配置。请遮去订阅 URL 中的令牌、节点密码、UUID 等凭据。
