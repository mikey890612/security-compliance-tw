# SAST：第三方元件

本檔不含法規或 OWASP 編號。對照關係一律查 `../mapping.md`。

本則看的是 manifest、lockfile 與內附的第三方檔，不是程式碼，所以範例是設定檔而不是
Go／Python／JavaScript 程式。

## SAST-DEP-001 · 使用已知漏洞的第三方元件

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| npm audit | 依 advisory 逐項列出（`GHSA-…`） | 依 advisory（critical／high／moderate／low） | verified | testdata/scan-artifacts/open-source/20260924T115741Z/npm-audit.json#advisory=GHSA-35jh-r3h4-6jhm（暫存 lockfile，見 `references/scanner-verification-log.md`） |
| pip-audit | 依 advisory 逐項列出（`PYSEC-…`／`GHSA-…`），附修補版本 | —（不給等級） | verified | testdata/scan-artifacts/open-source/20260924T115741Z/pip-audit.json#id=PYSEC-2020-96（暫存 requirements，見 `references/scanner-verification-log.md`） |
| govulncheck | 依 Go 漏洞資料庫逐項列出（`GO-…`），區分「有呼叫到」與「只有匯入」 | — | unverified | — |
| OWASP Dependency-Check | 依 CVE 逐項列出 | 依 CVSS | unverified | — |
| AWVS | Vulnerable JavaScript libraries | 依 CVE | unverified | — |
| ZAP | Vulnerable JS Library | Medium | unverified | — |
| Nessus | 依產品與版本比對的個別 plugin（網頁伺服器、框架、執行環境） | 依 CVSS | unverified | — |

商用 SAST（Fortify、Checkmarx）的原始碼掃描通常不比對元件版本；元件漏洞多半來自另購的 SCA 產品或弱點掃描。
**本 skill 不執行上述工具**——模式 1 只盤點並請使用者執行，見下方判定準則。

### 壞味道

**本則不憑記憶判定某版本有沒有漏洞。** 版本與漏洞的對應只認工具輸出或掃描報告；
沒有輸出時，列出元件清單並請使用者執行比對，**不要自己寫出 CVE 編號**——那是編造。

查的是「**能不能評估**」：版本有沒有鎖定、查不查得出來源與版本、有沒有定期比對的機制。

manifest 只寫套件名，沒有 lockfile——每次安裝結果都可能不同，無從比對：

```text
# requirements.txt
flask
pyyaml
lxml
```

`package.json` 用範圍版本，repo 裡卻沒有 `package-lock.json`（或 `.gitignore` 掉了）：

```json
{
  "dependencies": {
    "express": "^4.17.0",
    "libxmljs": "*"
  }
}
```

內附的第三方檔查不出名稱與版本，也不在任何 manifest 裡：

```text
static/vendor/legacy-widget.js     從舊專案複製，檔頭沒有版本
static/js/editor.min.js            壓縮檔，改過內容，不知道原本是哪一版
```

Go 模組天生鎖版（`go.mod` 加 `go.sum`），壞味道多半是 `replace` 指到本機目錄的分叉版本——
上游的修補不會自動進來：

```text
// go.mod
replace github.com/some/lib => ./third_party/lib-fork
```

### 過關寫法

版本鎖定、lockfile 進版控、建置時固定比對一次：

```text
# requirements.txt——由 pip-compile 或 uv 產生，版本全部鎖定
flask==3.1.3
pyyaml==6.0.2
```

```yaml
# CI：每次建置都比對；有 high 以上就失敗
- run: npm ci
- run: npm audit --omit=dev --audit-level=high
- run: pip-audit -r requirements.txt
- run: govulncheck ./...
```

內附的第三方檔，在同目錄放一份清單，寫明名稱、版本、來源與授權；能改用套件管理就改：

```text
static/vendor/README.md
| 檔案 | 元件 | 版本 | 來源 |
| richedit.js | RichEdit | 2.4.1 | https://… 官方發布包 |
```

要交 SBOM 的案子，可用 CycloneDX 的工具由 lockfile 產生，不要手寫。

### 常見誤判與處置

- **只影響開發相依**——`devDependencies`、測試工具，不進正式環境。
  處置：以 `npm audit --omit=dev`（或只比對正式 requirements）確認正式相依乾淨後判誤判，
  佐證附兩次輸出。建置工具仍應排入例行更新——被入侵的建置工具會污染產出。

- **受影響的函式沒有被呼叫**——npm audit、pip-audit 以版本比對，不看呼叫。
  處置：Go 專案附 govulncheck 的輸出（它區分有沒有呼叫到）可判誤判；
  其他語言無法證明時，照灰色地帶處理。

- **弱掃依橫幅版本比對，但系統套件已 backport 修補**——例如作業系統發行版的套件，
  版本號不變但漏洞已修。處置：判誤判，佐證附發行版的安全公告編號與套件版本。

- **升級會破壞相容，短期無法升**——這不是誤判。判真漏洞，列入 `false-positives.md` 的
  「已知風險接受」，附受影響的功能、補償控制與預計升級時程。

### 判定準則

真漏洞：工具輸出或掃描報告指出正式環境使用的元件版本有已知漏洞，且尚未升級到修補版本。

真漏洞：無從評估——相依沒有鎖定版本（沒有 lockfile、manifest 只寫套件名），
或內附的第三方檔查不出名稱與版本。定期評估更新的前提是知道自己用了什麼版本。

誤判：受影響的只有開發相依且正式建置不含；Go 專案經 govulncheck 確認沒有呼叫到受影響函式；
或系統套件已 backport 修補。三者都要附工具輸出或公告編號。

灰色地帶——**一律當真漏洞修**：版本在受影響範圍內，但無法確認是否呼叫到受影響函式。

模式 1 沒有工具輸出時：列出元件清單（manifest、lockfile 有無、內附檔與其版本），
附上各生態系的比對指令請使用者執行；使用者提供輸出後再逐項判定。
清單本身沒有問題的專案，列在 `findings.md` 開頭的「待使用者執行」，**不要判通過**。
