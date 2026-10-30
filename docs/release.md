# 发布流程

推送 `v*` tag 会触发 [`.github/workflows/release.yml`](../.github/workflows/release.yml)：

1. 用 `scripts/build-dmg.sh`（`UNIVERSAL=1`）构建 arm64 + x86_64 通用版 Rust 内核与 Sluice.app，版本号取自 tag（`v1.2.3` → `CFBundleShortVersionString=1.2.3`），`CFBundleVersion` 取 workflow 的 run number（Sparkle 用它比较新旧）；
2. 有证书 secrets 时用 Developer ID 签名（hardened runtime，见 `apps/macos/Entitlements/`），否则 ad-hoc 签名；
3. 有 Apple ID secrets 时 `notarytool submit --wait` 公证并 `stapler staple`；
4. 生成 `appcast.xml`，有 `SPARKLE_ED_PRIVATE_KEY` 时用 EdDSA 签名；
5. 创建 GitHub Release，附上 DMG 与 appcast，release notes 自动生成，并注明签名/公证状态。

tag 中带 `-`（如 `v1.0.0-beta1`）会被标为 pre-release。App 的 `SUFeedURL` 指向
`https://github.com/qingyanzh/Sluice/releases/latest/download/appcast.xml`，`latest` 不包含 pre-release，所以测试版不会推送给用户。
App 每天自动检查一次更新，也可以通过应用菜单或菜单栏的「检查更新…」手动检查。

所有 secrets 都是可选的：缺哪一组就跳过对应步骤，构建本身总能完成。

## 1. 创建 Developer ID 证书

需要付费的 Apple Developer Program 账号（Account Holder 才能创建 Developer ID 证书）。

1. 打开「钥匙串访问」→ 菜单「证书助理」→「从证书颁发机构请求证书…」，填邮箱，选「存储到磁盘」，得到 `.certSigningRequest`。
2. 登录 <https://developer.apple.com/account/resources/certificates/add>，选 **Developer ID Application**，上传 CSR，下载 `.cer` 并双击导入钥匙串。
3. 在钥匙串「我的证书」里找到 `Developer ID Application: 你的名字 (TEAMID)`，右键 → 导出为 `.p12`，设一个密码。
4. 转成 base64：

   ```bash
   base64 -i DeveloperID.p12 | pbcopy
   ```

## 2. App 专用密码与 Team ID

- 在 <https://account.apple.com> →「登录与安全」→「App 专用密码」生成一个，用于 `notarytool`。
- Team ID 在 <https://developer.apple.com/account> 的 Membership 页面，10 位字母数字。

## 3. 生成 Sparkle 密钥

```bash
cd apps/macos && swift package resolve
.build/artifacts/sparkle/Sparkle/bin/generate_keys            # 生成并存入登录钥匙串，打印公钥
.build/artifacts/sparkle/Sparkle/bin/generate_keys -x sparkle_private.key   # 导出私钥
```

公钥会写进 Info.plist 的 `SUPublicEDKey`；私钥只放进 GitHub secret，导出后删掉本地文件（钥匙串里仍有一份，妥善备份）。
**私钥丢失后已安装的版本将无法再验证更新**，只能让用户手动下载新版。

## 4. 在 GitHub 中配置

仓库 Settings → Secrets and variables → Actions：

| 类型 | 名称 | 内容 |
| --- | --- | --- |
| Secret | `MACOS_CERT_P12` | 第 1 步的 base64 字符串 |
| Secret | `MACOS_CERT_PASSWORD` | 导出 `.p12` 时设的密码 |
| Secret | `APPLE_ID` | Apple 账号邮箱 |
| Secret | `APPLE_TEAM_ID` | Team ID |
| Secret | `APPLE_APP_PASSWORD` | App 专用密码 |
| Secret | `SPARKLE_ED_PRIVATE_KEY` | `sparkle_private.key` 的内容 |
| Variable | `SPARKLE_ED_PUBLIC_KEY` | `generate_keys` 打印的公钥 |

只设证书两项：签名但不公证；再加 Apple 三项：签名 + 公证；什么都不设：ad-hoc 签名，release notes 会提示用户右键打开。
没有 `SPARKLE_ED_PUBLIC_KEY` 的构建里 Sparkle 无法验证更新，等于没有自动更新。

## 5. 发布新版本

```bash
git checkout main && git pull
git tag v0.2.0
git push origin v0.2.0
```

在 Actions 页面等 Release workflow 完成，Release 页面即出现 `Sluice-0.2.0.dmg` 和 `appcast.xml`。
建议先推一个 `v0.2.0-rc1` 之类的 pre-release 验证，确认无误后删掉：

```bash
gh release delete v0.2.0-rc1 --cleanup-tag --yes
```

## 本地构建

```bash
VERSION=0.2.0 UNIVERSAL=1 scripts/build-dmg.sh
```

可选环境变量见 `scripts/build-app.sh` 开头的注释；设置 `SIGN_IDENTITY="Developer ID Application: …"` 即可在本地用正式证书签名。
