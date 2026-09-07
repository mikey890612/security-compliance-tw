# 掃描器驗證紀錄

| 日期 | 工具 | 版本 | 對應 checks | 結果摘要 | 操作者 |
|------|------|------|-------------|----------|--------|
| 2026-09-05 | gosec | dev (securego/gosec/v2@latest) | sast-injection (INJ-001 G202, INJ-002 G204); sast-errors (ERR-002 G104) | sample-go: 10 findings; verified 3 rows; artifact `testdata/scan-artifacts/open-source/20260905T084457Z/gosec.json` | 埕碩 許 |
| 2026-09-05 | bandit | 1.9.4 | sast-injection (INJ-001 B608, INJ-002 B602); sast-authz (AUTHZ-004 B103) | sample-multi (+insecure.py): 4 findings; verified 3 rows; artifact `testdata/scan-artifacts/open-source/20260905T084457Z/bandit.json` | 埕碩 許 |
| 2026-09-05 | semgrep | 1.176.1 | sast-injection (INJ-001 string-formatted-query, INJ-002 dangerous-exec-command, INJ-004 xss ResponseWriter) | sample-go+sample-multi: 8 findings; verified 3 rows; artifact `testdata/scan-artifacts/open-source/20260905T084457Z/semgrep.json` | 埕碩 許 |
| 2026-09-07 | mobsfscan | 1.0.0（規則集內含 semgrep 66 檔） | mast-storage（STORAGE-002/003/004）、mast-crypto（CRYPTO-001/002）、mast-network（NETWORK-001/002）、mast-platform（PLATFORM-002/004/006/007）、mast-code（CODE-002）、mast-resilience（RESILIENCE-001/002/003） | sample-android：14 條 semgrep 命中 + 11 條 manifest／best-practice；sample-ios：5 + 6。verified 18 列。artifact `testdata/scan-artifacts/open-source/20260907T001858Z/` | 埕碩 許 |

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

