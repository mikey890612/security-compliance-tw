# 第三方授權聲明 / Third-Party Notices

本 plugin 目錄隨安裝複製到使用者電腦；下列第三方內容的授權聲明必須隨之散布，因此放在這裡，
而不是只放在 repo 根目錄的 `NOTICE.md`。

---

## Cloudflare security-audit-skill

- 來源：<https://github.com/cloudflare/security-audit-skill>（commit `c1c8a8c`，2026-09-14）
- 使用方式：**改寫與摘要**為繁體中文，未逐字收錄；未隨附上游的 `report-schema.json` 與 `validate-*.cjs` 腳本
- 受影響的檔案：
  - `references/deep-audit.md`——六階段方法、三種判定、嚴重度錨點、反模式（改寫自 `SKILL.md`、`RECONNAISSANCE.md`、`HUNTING.md`、`VALIDATION-AND-REPORTING.md`）
  - `references/deep-audit-safety.md`——執行安全與沙箱規則（改寫自 `SKILL.md`、`HUNTING.md`）
  - `references/deep-audit-ai.md`——AI／LLM／代理攻擊類別（改寫自 `AI-AND-LLM.md`；OWASP 對照為本專案另加）
  - `references/deep-audit-hunting.md`——各領域攻擊類別摘要（改寫自 `ATTACK-CLASSES.md` 與各領域指南；check 對照為本專案另加）

```
MIT License

Copyright (c) 2025-2026 Cloudflare, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
