# 更新紀錄

版本號以 `.claude-plugin/plugin.json` 為準。已安裝的版本看
`~/.security-compliance-tw/plugin/.claude-plugin/plugin.json`；
專案裡由 `sec-harden` 產生的規則檔，版本寫在標記區塊的第一行。

- **patch**（0.2.**x**）：修正文字、數字、連結，判定結果不變
- **minor**（0.**x**.0）：新增或更正 check、掃描器對照、skill 的流程——判定結果可能改變，建議更新
- **major**（**x**.0.0）：check-id 異動或移除——舊的 `findings.md`、`false-positives.md` 可能對不上

## 0.2.0（未發布）

**建議更新**：`sec-audit` 判讀 Fortify 報告的結果會不同。

- `sec-audit`：Fortify 對照依一份真實專案的報告校準。檔案上傳的規則名更正為
  `Often Misused: File Upload`——**舊版會把這類發現誤報成「本知識庫尚未涵蓋」**。
  等級改用實測值，多數比舊版低
- `sec-audit` 模式 2：依規則名稱分組判讀、用含子類別的全名反查、優先序以報告上的等級為準、
  第三方套件（`vendor/`）的發現另行處置
- `sec-harden`：寫 Android／iOS 程式時會觸發；行動端先用速查，速查沒涵蓋的情境才讀完整 check
- 專案規則檔（`AGENTS.md`、Cursor `.mdc` 等）的標記帶版本號，可比對專案是否需要重裝
- 三支 skill 找不到知識庫時會停下來，請使用者執行 `install.sh`，不再憑印象作答
- 修正安裝後會失效的文件連結，以及多處過期的則數與條數

維護者：`tools/validate_kb.py` 新增文件數字、路徑、check 檔登錄、ROOT 段落、
版本與本檔的一致性檢查；新增 `testdata/sample-go-web`。

## 0.1.0（2026-09-07）

版本號在此之前未維護，以 2026-09-07 的 main 為基準：知識庫 90 則 check
（伺服器與 Web、行動端、MDM），三支 skill 與一鍵安裝。
