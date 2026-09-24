# 掃描器驗證紀錄

| 日期 | 工具 | 版本 | 對應 checks | 結果摘要 | 操作者 |
|------|------|------|-------------|----------|--------|
| 2026-09-05 | gosec | dev (securego/gosec/v2@latest) | sast-injection (INJ-001 G202, INJ-002 G204); sast-errors (ERR-002 G104) | sample-go: 10 findings; verified 3 rows; artifact `testdata/scan-artifacts/open-source/20260905T084457Z/gosec.json` | 埕碩 許 |
| 2026-09-05 | bandit | 1.9.4 | sast-injection (INJ-001 B608, INJ-002 B602); sast-authz (AUTHZ-004 B103) | sample-multi (+insecure.py): 4 findings; verified 3 rows; artifact `testdata/scan-artifacts/open-source/20260905T084457Z/bandit.json` | 埕碩 許 |
| 2026-09-05 | semgrep | 1.176.1 | sast-injection (INJ-001 string-formatted-query, INJ-002 dangerous-exec-command, INJ-004 xss ResponseWriter) | sample-go+sample-multi: 8 findings; verified 3 rows; artifact `testdata/scan-artifacts/open-source/20260905T084457Z/semgrep.json` | 埕碩 許 |
| 2026-09-07 | mobsfscan | 1.0.0（規則集內含 semgrep 66 檔） | mast-storage（STORAGE-002/003/004）、mast-crypto（CRYPTO-001/002）、mast-network（NETWORK-001/002）、mast-platform（PLATFORM-002/004/006/007/009）、mast-code（CODE-002）、mast-resilience（RESILIENCE-001/002/003） | sample-android：14 條 semgrep 命中 + 11 條 manifest／best-practice；sample-ios：5 + 6。verified 16 列。artifact `testdata/scan-artifacts/open-source/20260907T001858Z/` | 埕碩 許 |
| 2026-09-24 | Fortify SCA | 26.1.0.0059（Rulepacks 2026.1.1.0001） | sast-request-abuse（UPLOAD-001、CSRF-001）、sast-errors（ERR-001）、sast-crypto（CRYPTO-001/002）、sast-injection（INJ-001）、sast-api-authz（API-002）、dast-tls-cookie（COOKIE-002） | 真實專案的內部報告（檢測日 2026-04-24；報告、路徑與程式碼不入庫）：Go／HTML／JS 專案 27 項 4 類、C# 專案 15 項 7 類。verified 4 列、partial 6 列。模式 2 反查模擬：校準前 42 項只精確對到 12 項，校準後 42 項全對到 | 埕碩 許 |
| 2026-09-24 | semgrep／bandit／npm audit／pip-audit | semgrep 1.178.0（規則取自 GitHub semgrep-rules a84ff9c）；bandit 1.9.4；npm 10.9.7；pip-audit 2.10.1 | sast-injection（INJ-005/006）、sast-request-abuse（REDIRECT-001）、sast-dependencies（DEP-001） | sample-untrusted-data：semgrep 對 vulnerable.* 命中 12 項（另 1 項為無關的 CSRF 提示）、bandit 5 項；fixed.* 只剩 Go 的 open-redirect（污點規則認不得自寫檢查）。INJ-007 兩工具皆無規則命中。verified 12 列；artifact `testdata/scan-artifacts/open-source/20260924T115741Z/` | 埕碩 許 |

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


## 0.4.0 新增 check 的實跑（2026-09-24）

Fixture `testdata/sample-untrusted-data/` 每種語言各有一份 `vulnerable.*` 與 `fixed.*`，
同時驗證「壞寫法會被標」與「過關寫法不再被標」。

**semgrep 官方規則庫（semgrep.dev）在本次環境連不上**，改從 GitHub 取 `semgrep-rules`
原始碼，以本機目錄執行：

```bash
R=/path/to/semgrep-rules
semgrep --metrics=off --json -o semgrep.json \
  --config $R/python/lang/security --config $R/python/flask/security \
  --config $R/go/lang/security --config $R/javascript/express/security \
  --config $R/javascript/lang/security testdata/sample-untrusted-data
```

本機執行時 `check_id` 帶有規則目錄的路徑前綴；各 check 證據欄寫的是去掉前綴後的部分
（例如 `python.flask.security.open-redirect`）。

| check | 壞寫法（vulnerable.*） | 過關寫法（fixed.*） |
|---|---|---|
| INJ-005 XXE | semgrep `use-defused-xml`、`express-libxml-noent`；bandit B405、B314 | 無命中 |
| INJ-006 反序列化 | semgrep `avoid-pickle`、`avoid-pyyaml-load`、`insecure-deserialization`、`express-third-party-object-deserialization`、`go-unsafe-deserialization-interface`；bandit B403、B301、B506 | 無命中 |
| INJ-007 標頭注入 | **無命中**（semgrep、bandit 皆無對應規則） | 無命中 |
| REDIRECT-001 | semgrep 三語言規則皆命中 | Go 的污點規則仍命中（認不得 `safeNext`）；Python、JS 無命中 |

**lxml：** `resolve_entities=True` 兩工具都不標——bandit 1.9 已移除 B320／B410。
另以 lxml 4.9.4 與 5.0.0 實測：4.9.4 預設會讀入 `file:///etc/hostname`，5.0.0 起預設拒絕外部實體。

**標頭注入的框架行為**（Go 1.24、Werkzeug 3.1.8、Node 22）：CR/LF 分別被換成空白、丟 `ValueError`、
丟 `ERR_INVALID_CHAR`；以字串自組的 `Set-Cookie` 帶 `; Domain=evil.example` 三者都原樣送出。

**DEP-001：** 為避免公開 repo 觸發 Dependabot 警報，含已知漏洞版本的 manifest **不入庫**，
只放在 artifact 目錄（`deps-probe-requirements.txt` 為 `PyYAML==5.3`，`deps-probe-package.json` 為
`lodash` `4.17.15`）。`pip-audit` 報出 `PYSEC-2020-96` 等 4 項；`npm audit` 報出 `lodash` high。
`govulncheck` 的漏洞資料庫（vuln.go.dev）在本次環境連不上，維持 `unverified`。

商用工具的新增列一律 `unverified`；Checkmarx 只收有把握存在的名稱，沒把握的不列。
