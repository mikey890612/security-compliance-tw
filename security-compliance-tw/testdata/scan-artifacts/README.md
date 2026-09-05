# scan-artifacts

本目錄存放掃描器驗證過程產生的原始產出。**除本 README 與各子目錄的 `.gitkeep` 外，其餘檔案預設不進版控。**

## 目錄用途

| 子目錄 | 用途 | 是否 commit |
|--------|------|-------------|
| `open-source/` | 對 `testdata/sample-go`、`sample-multi` 等 fixture 執行 gosec / bandit / semgrep 後的原始 JSON | 否（僅 `.gitkeep`） |
| `commercial/` | 預留給日後經紅acted 的商用掃描報告（Fortify / Checkmarx / AWVS 等） | 否（僅 `.gitkeep`） |

## 追蹤規則

- 已追蹤：`README.md`、`open-source/.gitkeep`、`commercial/.gitkeep`
- 忽略：兩子目錄下其餘所有檔案（見 repo-root `.gitignore`）
- 若要把某次開源跑掃結果留作公開範例，請改放到 `security-compliance-tw/examples/` 並在該處 README 說明

## 相關文件

- 開源驗證流程：`../../tools/verify_scanners.md`
- 商用延後驗證：`../../../docs/usage/scanner-verification.md`
- 驗證紀錄 stub：`../../references/scanner-verification-log.md`
