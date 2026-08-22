# 掃描工具行為特性

本檔說明各類掃描器的判定方式與誤判習性，供判讀掃描報告時參考。
**本 plugin 不執行任何掃描工具**——掃描由人執行。

## 商用 SAST

### Fortify SCA
- 判定方式：污點分析（taint analysis），追蹤資料從 source 流向 sink 的路徑
- 等級：Critical / High / Medium / Low
- 習性：偏保守，寧可多報。自訂的消毒函式（custom sanitizer）追不出來，
  除非在 Fortify 的 rulepack 中註冊為 cleanse rule
- 誤判處置：在 Audit Workbench 中標記為 Not an Issue 並填寫理由，
  該判定會寫入 `.fpr`，複掃時保留

### Checkmarx
- 判定方式：以 CxQL 查詢語言對程式碼圖譜（AST + DFG）比對
- 等級：High / Medium / Low / Information
- 習性：對框架的內建防護辨識度較 Fortify 好，但對動態語言誤判偏多
- 誤判處置：於結果介面標記 Not Exploitable，可設定為跨掃描持續

## 開源 SAST

| 工具 | 語言 | 判定方式 | 等級 |
|---|---|---|---|
| Semgrep | 多語 | 語法樣式比對（部分規則支援 taint mode） | ERROR / WARNING / INFO |
| SonarQube | 多語 | 規則引擎 + 部分資料流分析 | Blocker / Critical / Major / Minor |
| CodeQL | 多語 | 對程式碼資料庫下 QL 查詢，資料流分析完整 | error / warning / note |
| gosec | Go | AST 規則比對，無跨函式資料流 | HIGH / MEDIUM / LOW |
| bandit | Python | AST 規則比對，無跨函式資料流 | HIGH / MEDIUM / LOW |

gosec 與 bandit 只看單一函式內的樣式，把不安全操作包進 helper 函式就會漏報——
**這代表「gosec 沒報」不等於「Fortify 不會報」**。判讀時以資料流分析工具為準。

## DAST / 弱點掃描

| 工具 | 觀察對象 |
|---|---|
| Acunetix WVS | HTTP 回應標頭、錯誤頁內容、表單注入回應、Cookie 屬性 |
| Nessus | 服務版本指紋、TLS 組態、已知 CVE |
| OWASP ZAP | 同 AWVS，另含被動掃描規則 |
| HP WebInspect | 同 AWVS |

DAST 完全看不到源碼，只看執行期表現。因此 DAST 家族的 check
偵測的是**決定執行期行為的程式碼與設定**：middleware 註冊順序、
標頭設定、Cookie flags、錯誤處理器、TLS 組態。

## 誤判處置的共同原則

標記誤判前必須確認三件事，缺一不可：

1. 資料實際上不可控（來源為常數、列舉，或已通過白名單驗證）
2. 該路徑上確實存在有效的消毒或參數化，只是工具追不到
3. 有具體佐證可寫入 `false-positives.md`：檔案位置、資料來源、消毒點

若三者無法同時滿足，視為真漏洞處理。

## 各工具的誤判標記方式

| 工具 | 標記方式 | 是否跨掃描保留 |
|---|---|---|
| Fortify | Audit Workbench 標記 Not an Issue | 是，存於 `.fpr` |
| Checkmarx | 結果介面標記 Not Exploitable | 是，可設定 |
| Semgrep | 程式碼加 `# nosemgrep` 註解，或 `.semgrepignore` | 是 |
| SonarQube | 介面標記 Won't Fix / False Positive | 是 |
| gosec | 程式碼加 `#nosec G201` 註解 | 是 |
| bandit | 程式碼加 `# nosec` 註解，或 `.bandit` 設定 | 是 |
| AWVS / ZAP | 掃描設定中排除該規則或路徑 | 視設定 |

**在程式碼中加抑制註解時，一律附上理由**，例如：

```go
// #nosec G201 -- col 來自 allowedSort 白名單的 value，非使用者輸入
rows, err := db.Query("SELECT * FROM users ORDER BY " + col)
```

```python
# nosec B608 - 欄位名來自 ALLOWED_SORT 常數字典，已驗證
cur.execute(f"SELECT * FROM users ORDER BY {col}")
```

沒有理由的抑制註解，在人工審查時會被要求說明，等於沒省到事。
