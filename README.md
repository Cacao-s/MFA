# MFA

跨平台的兩步驟驗證（2FA）驗證碼 app，用法類似 Authy／Google Authenticator。支援 Android、iOS、macOS、Windows。

> 開發中，尚未發佈。

## 功能

- 掃描網站提供的 QR code，或手動輸入金鑰，新增帳號
- 顯示每 30 秒更新一次的 6 位數驗證碼，點一下就複製
- 搜尋、排序帳號
- 用 Face ID／Touch ID／指紋／Windows Hello 或 PIN 鎖住 app
- 金鑰加密存在裝置上；可匯出加密備份檔，換機時匯入
- 可從 Google Authenticator 的「匯出帳戶」QR code 一次匯入

## 安裝

尚未發佈。發佈後會提供：

- iOS／macOS：App Store
- Android：Google Play 或 GitHub Releases 的 APK
- Windows：GitHub Releases 的安裝檔

## 開發

```sh
make help      # 列出所有 target
make setup     # 安裝 toolchain 元件並抓相依套件
make test      # 跑測試（目前 75 個）
make check     # 格式、clippy、測試，等同 CI 會跑的
```

`make run` 目前會直接失敗：還沒有可以跑的 app。平台 UI 等 plan 步驟 0 的 spike 做完、技術棧定案後才開始，spike 的驗證項目見 [spike/README.md](spike/README.md)。

平台無關的核心已經完成並通過測試（TOTP、`otpauth://` 解析、Google Authenticator 匯入、vault 格式與加解密、備份、同步合併邏輯），細節見 [crates/mfa-core/README.md](crates/mfa-core/README.md)。

各平台 UI 透過 [crates/mfa-ffi](crates/mfa-ffi/README.md) 呼叫核心：Swift／Kotlin 用 UniFFI 產生的 binding，Windows 走 C ABI 上的 JSON 通道。

```sh
make bindings                      # 產生 Swift／Kotlin binding
./scripts/build-apple.sh --release # XCFramework（需要 macOS ＋ Xcode）
./scripts/build-android.sh         # jniLibs（需要 NDK ＋ cargo-ndk）
```

同步可以同時開多個目標（雲端硬碟資料夾、GitHub、GitLab、自架伺服器），自架伺服器見 [crates/mfa-sync-server/README.md](crates/mfa-sync-server/README.md)：只存密文、沒有帳號系統，一組 bearer token。

```sh
export MFA_SYNC_TOKEN="$(openssl rand -hex 32)"
make server
```

規格與實作計劃不進版控，放在 `temp/`（見 `temp/README.md`）。
