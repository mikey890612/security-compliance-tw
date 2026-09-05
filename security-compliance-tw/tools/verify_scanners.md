# 開源掃描器驗證操作說明

本文件說明如何用本機安裝的開源掃描器，對現有 fixture 實跑，並把命中結果回填到知識庫掃描器表的 `狀態`／`證據` 欄。

> **注意：** `tools/run_open_scanners.sh` 由 Task 4 提供。本文件先描述預期用法；腳本尚未合併前請依下列步驟手動等價執行，或等 Task 4 完成後再跑腳本。

## 1. 前置條件

請安裝下列 CLI（缺哪個就跳過哪個；整輪驗證不因缺工具而失敗）：

| 工具 | 建議安裝方式 | 主要語言／目標 |
|------|--------------|----------------|
| `gosec` | `go install github.com/securego/gosec/v2/cmd/gosec@latest` | Go（`testdata/sample-go`） |
| `bandit` | `pip install bandit` | Python（`testdata/sample-multi` 內 Python 檔） |
| `semgrep` | `pip install semgrep` 或官方安裝腳本 | 多語（同上 fixtures） |

確認：

```bash
gosec -version    # 或 gosec --version
bandit --version
semgrep --version
```

工作目錄請設在 plugin 根：`security-compliance-tw/`。

## 2. 執行 runner（Task 4）

```bash
cd security-compliance-tw
bash tools/run_open_scanners.sh
```

預期行為：

1. 在 `testdata/scan-artifacts/open-source/` 下建立時間戳子目錄
2. 對 `testdata/sample-go` 跑 gosec；對 `testdata/sample-multi`（與既有 Go fixture）跑 bandit／semgrep（工具存在才跑）
3. 寫出 `gosec.json`、`bandit.json`、`semgrep.json`（有跑到的才有檔）
4. 印出路徑與 finding 筆數；有 finding 仍 exit 0（本流程把 finding 當成功訊號）
5. 工具未安裝時印 skip 訊息並繼續，整體仍 exit 0

手動等價（腳本尚未就緒時）：

```bash
OUT=testdata/scan-artifacts/open-source/$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$OUT"
# 範例：gosec
command -v gosec >/dev/null && gosec -fmt=json -out="$OUT/gosec.json" ./testdata/sample-go/... || echo "skip gosec"
# 範例：bandit（路徑依 sample-multi 實際 Python 檔調整）
command -v bandit >/dev/null && bandit -r -f json -o "$OUT/bandit.json" testdata/sample-multi || echo "skip bandit"
# 範例：semgrep
command -v semgrep >/dev/null && semgrep --json --output "$OUT/semgrep.json" testdata/sample-go testdata/sample-multi || echo "skip semgrep"
```

## 3. 產出位置

原始 JSON 落在：

```
testdata/scan-artifacts/open-source/<run-id>/
  gosec.json
  bandit.json
  semgrep.json
```

這些檔案被 `.gitignore` 忽略，**不要**強制 `git add -f` 進公開 repo。公開證據欄只寫相對路徑字串（見下節）。

## 4. 把列提升為 `verified`

對每個工具有 ≥1 筆 finding 時：

1. **對規則 ID**：在 `references/checks/*.md` 的 `### 掃描器怎麼標` 表中，找到「工具」與「規則」與 finding 相符（或既有規則字串最接近）的那一列
2. **改狀態**：`狀態` 設為 `verified`（僅部分命中或規則近似時可用 `partial`）
3. **填證據**：`證據` 設為相對路徑，例如  
   `scan-artifacts/open-source/<run-id>/gosec.json#rule=G201`
4. **重跑驗證器**：

   ```bash
   python3 tools/validate_kb.py
   ```

   必須通過；`verified`／`partial` 列不得把證據留成 `—`
5. **記 log**：在 `references/scanner-verification-log.md` 追加一列（日期、工具、版本、對應 checks、結果摘要、操作者）

未命中的列維持 `unverified`。商用工具列請走 `docs/usage/scanner-verification.md`，本文件不涵蓋。

## 相關路徑

| 項目 | 路徑 |
|------|------|
| Fixtures | `testdata/sample-go`、`testdata/sample-multi` |
| Artifacts | `testdata/scan-artifacts/` |
| 驗證紀錄 | `references/scanner-verification-log.md` |
| 商用延後流程 | `../../docs/usage/scanner-verification.md` |
| KB validator | `tools/validate_kb.py` |
