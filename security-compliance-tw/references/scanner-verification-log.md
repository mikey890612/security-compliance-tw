# 掃描器驗證紀錄

| 日期 | 工具 | 版本 | 對應 checks | 結果摘要 | 操作者 |
|------|------|------|-------------|----------|--------|
| 2026-09-05 | gosec | dev (securego/gosec/v2@latest) | sast-injection (INJ-001 G202, INJ-002 G204); sast-errors (ERR-002 G104) | sample-go: 10 findings; verified 3 rows; artifact `testdata/scan-artifacts/open-source/20260905T084457Z/gosec.json` | 埕碩 許 |
| 2026-09-05 | bandit | 1.9.4 | sast-injection (INJ-001 B608, INJ-002 B602); sast-authz (AUTHZ-004 B103) | sample-multi (+insecure.py): 4 findings; verified 3 rows; artifact `testdata/scan-artifacts/open-source/20260905T084457Z/bandit.json` | 埕碩 許 |
| 2026-09-05 | semgrep | 1.176.1 | sast-injection (INJ-001 string-formatted-query, INJ-002 dangerous-exec-command, INJ-004 xss ResponseWriter) | sample-go+sample-multi: 8 findings; verified 3 rows; artifact `testdata/scan-artifacts/open-source/20260905T084457Z/semgrep.json` | 埕碩 許 |
| 2026-09-07 | mobsfscan | 1.0.0（規則集內含 semgrep 66 檔） | mast-storage（STORAGE-002/003/004）、mast-crypto（CRYPTO-001/002）、mast-network（NETWORK-001/002）、mast-platform（PLATFORM-002/004/006/007/009）、mast-code（CODE-002）、mast-resilience（RESILIENCE-001/002/003） | sample-android：14 條 semgrep 命中 + 11 條 manifest／best-practice；sample-ios：5 + 6。verified 16 列。artifact `testdata/scan-artifacts/open-source/20260907T001858Z/` | 埕碩 許 |
| 2026-09-24 | Fortify SCA | 26.1.0.0059（Rulepacks 2026.1.1.0001） | sast-request-abuse（UPLOAD-001、CSRF-001）、sast-errors（ERR-001）、sast-crypto（CRYPTO-001/002）、sast-injection（INJ-001）、sast-api-authz（API-002）、dast-tls-cookie（COOKIE-002） | 真實專案的內部報告（檢測日 2026-04-24；報告、路徑與程式碼不入庫）：Go／HTML／JS 專案 27 項 4 類、C# 專案 15 項 7 類。verified 4 列、partial 6 列。模式 2 反查模擬：校準前 42 項只精確對到 12 項，校準後 42 項全對到 | 埕碩 許 |

## 行動端驗證的執行方式與限制

**mobsfscan 的內建 semgrep 呼叫在本機環境失敗**（`Failed to register segfault
signal handler`），原始碼規則一條都沒跑到，只有 manifest 與 best-practices
類（不走 semgrep）有輸出。

處理方式：**改用 mobsfscan 隨附的規則集，直接以 semgrep 執行**——
規則 id 與 mobsfscan 完全相同，只是換了執行器。

```bash
R=~/.local/pipx/venvs/mobsfscan/lib/python3.14/site-packages/mobsfscan/rules/semgrep
semgrep --config "$R" --metrics=off --json -o out.json testdata/sample-android
```

因此該批產物有兩種檔案，用途不同：

| 檔案 | 來源 | 涵蓋 |
|---|---|---|
| `semgrep-mobsfscan-*.json` | semgrep + mobsfscan 規則集 | 原始碼規則（Kotlin／Swift） |
| `mobsfscan-*.json` | mobsfscan 本身 | manifest／plist 分析與 best-practices（缺席類） |

**這批驗證證明的是「規則會對這樣的程式碼命中」，不是「規則名稱與商用報告一致」。**
Fortify／Checkmarx 等商用工具的行動端對照仍為未驗證，且本專案不收錄。


## 商用報告校準（2026-09-24）

報告依 `../tools/verify_commercial.md` 留在本機，**不入庫**；知識庫只記規則名稱、
等級與遮蔽後的證據標記 `internal-verified:2026-04-24`。
在 Go／HTML／JS 專案觀察到的標 `verified`；只在 C# 專案觀察到的標 `partial`——
規則名稱確認存在，但本知識庫的範例語言不含 C#。

**更正的規則名稱：**

| 原寫 | 實測 | 影響 |
|---|---|---|
| `Unrestricted File Upload` | `Often Misused: File Upload` | 校準前這組 23 項全部反查不到，會被報成「本知識庫尚未涵蓋」 |
| `Weak Cryptographic Hash: Insecure PBKDF2 Iteration Count` | `Weak Cryptographic Hash: Insecure PBE Iteration Count` | 只比對冒號前的主類別會錯對到 `SAST-CRYPTO-001` |

另新增兩個子類別（皆 C#，`partial`）：`Mass Assignment: Request Parameters Bound via Input Formatter`
（`SAST-API-002`）、`Cookie Security: HTTPOnly not Set on Application Cookie`（`DAST-COOKIE-002`）。

**等級：** 原本就有對照列的 8 個類別中，7 個的實測等級低於表上原值
（例如 `Weak Cryptographic Hash` 表上 Critical–High，實測 Low）。
已校準的列改用實測等級；`SQL Injection` 維持 Critical——它是污點規則，
等級隨資料來源浮動，單一個 Low 樣本不足以改典型值。

**這份報告證明的是「規則名稱與觸發樣式」，不是「知識庫的判定正確」**——
沒有原始碼，無法逐項確認真漏洞或誤判。
