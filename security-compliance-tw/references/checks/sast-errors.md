# SAST：錯誤處理與資源釋放

這類問題掃描器抓得很淺——多半只看「錯誤有沒有流向回應」「回傳值有沒有被讀」
「catch 的型別多寬」「釋放動作在不在 defer / with / finally 裡」。
換句話說，過關與否取決於**寫法的結構**，不是取決於邏輯上有沒有真的處理。

本檔不含法規或 OWASP 編號。對照關係一律查 `../mapping.md`。

## SAST-ERR-001 · 錯誤訊息與堆疊追蹤外洩

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| Fortify | System Information Leak / System Information Leak: External | High | unverified | — |
| Checkmarx | Information_Exposure_Through_an_Error_Message | Medium | unverified | — |
| Semgrep | `*.security.*.stack-trace-exposure*` / `python.flask.security.audit.debug-enabled` | ERROR | unverified | — |
| SonarQube | S4507（上線仍啟用除錯功能）/ S1989（例外由 servlet 方法逸出） | Security Hotspot / — | unverified | — |
| gosec | —（無專屬規則） | — | unverified | — |
| bandit | B201（flask_debug_true） | HIGH | unverified | — |
| CodeQL | `js/stack-trace-exposure` / `py/stack-trace-exposure` | error | unverified | — |
| AWVS / ZAP | Application error message / Information Disclosure - Debug Error Messages | Medium / Low | unverified | — |

### 壞味道

```go
if err != nil {
	http.Error(w, err.Error(), http.StatusInternalServerError) // 驅動層訊息直接吐出
	return
}

fmt.Fprintf(w, "db error: %v", err)
w.Write(debug.Stack())
```

```python
app.run(debug=True)  # 例外頁面含完整堆疊與互動式 console

try:
    do_work()
except Exception as e:
    return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500
```

```javascript
res.status(500).send(err.stack);

app.use((err, req, res, next) => {
  res.status(500).json({ message: err.message, stack: err.stack });
});
```

Express 若**沒有**自訂 error handler，非 production 模式下預設會把堆疊寫進回應，
掃描器與 DAST 都會抓到——「沒寫程式碼」本身就是壞味道。

### 過關寫法

樣式是**內外分離**：對外只給程式內常數訊息加一組系統產生的關聯 ID，
對內把完整錯誤寫進日誌。污點分析看的是「err 有沒有流到 response writer」，
只要這條邊斷掉就不再標記。

```go
if err != nil {
	reqID := middleware.GetReqID(r.Context())
	log.Printf("query users failed reqID=%s err=%v", reqID, err) // err 只流向日誌
	http.Error(w, "internal server error, ref: "+reqID, http.StatusInternalServerError)
	return
}
```

```python
@app.errorhandler(Exception)
def on_error(e):
    ref = uuid.uuid4().hex
    app.logger.exception("unhandled error ref=%s", ref)
    return jsonify({"error": "internal server error", "ref": ref}), 500

# debug 一律由環境變數決定，預設關閉
app.run(debug=os.getenv("APP_DEBUG") == "1")
```

```javascript
app.use((err, req, res, next) => {
  const ref = crypto.randomUUID();
  logger.error({ ref, err }, "unhandled error");
  res.status(500).json({ error: "internal server error", ref });
});
```

日誌本身也要注意：把整包請求內容或含個資的參數寫進 log，會換成另一類告警。
只記錄錯誤物件、關聯 ID 與必要的識別欄位。

### 常見誤判與處置

- **debug 開關只出現在開發設定或 `if __name__ == "__main__"` 區塊**——
  bandit B201 只看到 `debug=True` 字面值，不看部署方式。
  處置：改由環境變數注入且預設 False（如上），直接消除告警，
  比在 `false-positives.md` 寫一段部署說明省事。

- **驗證失敗訊息回傳欄位原因**——例如「email 格式不正確」。
  Fortify 把任何 `err` 流向回應都算外洩，但這類訊息是設計上必要。
  處置：讓驗證錯誤走獨立型別（自訂 `ValidationError`），
  回應只組合訊息模板與欄位名白名單，不要串接底層 `err.Error()`；
  污點路徑一斷，多數工具就不報，也不必寫誤判說明。

- **錯誤訊息寫進管理後台頁面**——內部人員看得到堆疊。
  處置：這不是誤判。內部介面同樣要走關聯 ID，堆疊只留在日誌系統。

### 判定準則

真漏洞：來自例外物件、堆疊追蹤、資料庫驅動、檔案系統或設定檔的字串，
進入 HTTP 回應主體、回應標頭、或任何前端可見的頁面。

真漏洞：生產環境設定啟用 debug、verbose error page 或框架預設錯誤頁。

誤判：回應內容是程式內常數模板，僅串接系統產生的關聯 ID 或白名單欄位名，
且完整錯誤僅寫入日誌。

---

## SAST-ERR-002 · 錯誤回傳值未檢查

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| Fortify | Poor Error Handling: Return Value Ignored | Low | unverified | — |
| Checkmarx | —（依語言套件而異） | — | unverified | — |
| Semgrep | —（多以語言原生 linter 覆蓋） | — | unverified | — |
| SonarQube | S2201（忽略無副作用函式回傳值）/ S899（忽略狀態碼回傳值） | — | unverified | — |
| gosec | G104（Audit errors not checked） | LOW | unverified | — |
| bandit | B110（try_except_pass）/ B112（try_except_continue） | LOW | unverified | — |
| errcheck（Go） | 預設全部；`-blank` 另抓 `_ =` | — | unverified | — |
| CodeQL | —（無單一對應查詢） | — | unverified | — |

### 壞味道

```go
_ = json.Unmarshal(body, &req) // 解析失敗仍往下用 req
db.Exec("UPDATE accounts SET balance = ? WHERE id = ?", bal, id) // 回傳值整個丟棄
w.Write(payload)

f, _ := os.Create(path)
f.Write(data)
f.Close() // 寫入端的 Close 錯誤被吞：資料可能沒落地
```

```python
try:
    process(payload)
except:      # 裸 except
    pass

try:
    os.remove(tmp)
except Exception:
    pass     # 靜默吞錯，失敗完全不可觀測
```

```javascript
try { req = JSON.parse(body); } catch (e) {}

fs.writeFile(path, data, () => {}); // callback 的 err 參數沒看
saveAudit(entry);                   // 沒 await、沒 .catch()，reject 被丟掉
```

`_ =` 不是解法。部分 gosec 版本把明確空白指派視為「已表態」而放過，
但 errcheck 加 `-blank`、Fortify、Checkmarx 照樣標記——不要靠 `_ =` 過關。

### 過關寫法

工具認的是「回傳的 error 有沒有被讀進條件判斷或被往上傳」。
寫成 `if err := ...; err != nil` 這個結構最穩，各家規則都有對應樣式。

```go
if err := json.Unmarshal(body, &req); err != nil {
	return fmt.Errorf("decode request: %w", err)
}

if _, err := db.Exec("UPDATE accounts SET balance = ? WHERE id = ?", bal, id); err != nil {
	return fmt.Errorf("update balance: %w", err)
}

// 寫入端：Close 的錯誤必須往外傳（需搭配具名回傳值 (err error)）
f, err := os.Create(path)
if err != nil {
	return err
}
defer func() {
	if cerr := f.Close(); cerr != nil && err == nil {
		err = cerr
	}
}()
```

```python
try:
    process(payload)
except ValueError as e:
    logger.warning("payload rejected: %s", e)
    raise BadRequest("invalid payload") from e

# 「預期中的失敗」要用具體型別表達，不要用裸 except
try:
    os.remove(tmp)
except FileNotFoundError:
    pass  # 檔案已不存在即為預期結果
except OSError:
    logger.exception("remove temp file failed: %s", tmp)

# 或直接用 suppress，語意明確且多數規則不再報
with contextlib.suppress(FileNotFoundError):
    os.remove(tmp)
```

```javascript
try {
  req = JSON.parse(body);
} catch (err) {
  logger.warn({ err }, "invalid json body");
  return res.status(400).json({ error: "invalid json" });
}

await fs.promises.writeFile(path, data); // 失敗會 reject，交給上層 handler
saveAudit(entry).catch((err) => logger.error({ err }, "audit write failed"));
```

### 常見誤判與處置

- **`defer resp.Body.Close()` 被標未檢查回傳**——讀取端的 Close 失敗確實無可補救，
  errcheck 與 Fortify 仍會報。
  處置：讀取端可標記誤判並註明「僅讀取、無資料遺失風險」；
  **寫入端不可比照辦理**——寫入的 Close 失敗代表資料可能沒落地，必須檢查並往外傳。

- **`except FileNotFoundError: pass` 這類預期中的錯誤**——bandit B110 只看 `pass`，
  不看例外型別有多窄。
  處置：改用 `contextlib.suppress(...)`，或在 `pass` 上方註明為何無需處理。
  改寫比寫誤判說明省事，且下一輪掃描不會再冒出來。

- **日誌寫入失敗被忽略**——`logger.Write` 的回傳值幾乎沒人檢查。
  處置：若是稽核日誌（可歸責性用途），失敗必須有替代告警管道，屬真問題；
  若是除錯日誌，標記誤判並註明用途。

### 判定準則

真漏洞：安全相關動作的回傳錯誤被忽略，且失敗後控制流仍走成功路徑——
包含身分驗證、授權判斷、加解密、簽章驗證、稽核日誌寫入、交易提交。

真漏洞：錯誤被吞掉且沒有任何日誌，失敗完全不可觀測。

可接受：錯誤被讀入條件判斷、被記錄、或被包裝往上傳，且失敗時控制流會中止。

可接受：忽略的是無安全影響且無資料遺失風險的清理動作，並在原地註明理由
（用具體例外型別或 `contextlib.suppress`，不要用裸 except 或 `_ =`）。

---

## SAST-ERR-003 · 資源未正確釋放

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| Fortify | Unreleased Resource: Streams / Database / Files | High | unverified | — |
| Checkmarx | Unclosed_Objects | Medium | unverified | — |
| Semgrep | —（無穩定通用規則） | — | unverified | — |
| SonarQube | S2095（資源應被關閉） | Blocker | unverified | — |
| gosec | G307（defer 的 Close 回傳 error；較新版本已移除此規則）/ G104 | MEDIUM / LOW | unverified | — |
| bandit | —（無專屬規則） | — | unverified | — |
| CodeQL | `java/database-resource-leak` / `py/should-use-with` | — | unverified | — |

### 壞味道

```go
resp, err := http.Get(url)
if err != nil {
	return err
}
body, _ := io.ReadAll(resp.Body) // resp.Body 沒關 → 連線池耗盡

rows, _ := db.Query(q) // rows 沒關 → 連線洩漏
for rows.Next() {
	// ...
	if bad {
		return ErrBad // 這條路徑更不會釋放
	}
}
```

```python
f = open(path, "w")
f.write(data)   # write 拋例外就永遠不會關
f.close()

conn = psycopg2.connect(dsn)
cur = conn.cursor()
cur.execute(q)  # 沒有 with、沒有 finally
```

```javascript
const client = await pool.connect();
const r = await client.query(q); // 這行拋出就漏連線
client.release();

const fd = fs.openSync(path, "w");
fs.writeSync(fd, data);
fs.closeSync(fd);
```

### 過關寫法

三種語言各有一種掃描器內建認得的「結構化釋放」語法：Go 的 `defer`、
Python 的 `with`、JavaScript 的 `try/finally`。
只要釋放動作放進這三種結構，資料流分析就會判定所有路徑都會釋放。

```go
resp, err := http.Get(url)
if err != nil {
	return err
}
defer resp.Body.Close() // 取得後「立刻」defer，中間不要插入可能 return 的分支

rows, err := db.Query(q)
if err != nil {
	return err
}
defer rows.Close()
```

```python
with open(path, "w") as f:
    f.write(data)

with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
    cur.execute(q)

# 數量不定時用 ExitStack，不要自己寫 try/finally 巢狀
with contextlib.ExitStack() as stack:
    files = [stack.enter_context(open(p)) for p in paths]
```

```javascript
const client = await pool.connect();
try {
  const r = await client.query(q);
  return r.rows;
} finally {
  client.release(); // 例外與正常返回都會執行
}

const fh = await fs.promises.open(path, "w");
try {
  await fh.write(data);
} finally {
  await fh.close();
}
```

### 常見誤判與處置

- **釋放由框架接管**——Go 的 `http.Request.Body` 由 server 關閉、
  Python 的 ORM session 由 middleware 收尾、連線池自行回收。
  Fortify 與 Checkmarx 追不到跨層釋放。
  處置：標記誤判，佐證寫明釋放發生的框架層與檔案行號。

- **長生命週期單例不關閉**——連線池、全域 logger、metrics exporter
  本來就活到程序結束。
  處置：標記誤判並註明生命週期；若有 graceful shutdown，一併指出關閉位置。

- **迴圈內 defer 被標記**——這**不是誤判**。Go 的 `defer` 到函式結束才執行，
  迴圈跑一萬次就累積一萬個未釋放資源。
  處置：把迴圈本體抽成獨立函式讓 defer 在每輪結束時生效，或改為顯式 Close。

### 判定準則

真漏洞：資源取得後，存在任何一條控制流不會執行釋放——包含提前 return、
error 分支、panic 與例外路徑。

真漏洞：釋放動作寫在 `try` 區塊內或 `if` 分支內，而非 `finally` / `defer` / `with`。

真漏洞：Go 在迴圈內 `defer` 釋放，且迴圈次數受外部輸入影響。

誤判：釋放由框架、連線池或 shutdown 流程接管，且能明確指出接管的位置。

---

## SAST-ERR-004 · 捕捉過廣的例外

### 掃描器怎麼標

| 工具 | 規則 | 預設等級 | 狀態 | 證據 |
|---|---|---|---|---|
| Fortify | Poor Error Handling: Overly Broad Catch / Overly Broad Throws | Low | unverified | — |
| Checkmarx | —（無穩定對應查詢） | — | unverified | — |
| Semgrep | —（多以語言原生 linter 覆蓋） | — | unverified | — |
| SonarQube | S1181（捕捉 Throwable/Error）/ S2221（捕捉 Exception）/ S108（空區塊） | —（依品質配置） | unverified | — |
| gosec | —（Go 無例外機制；對應的是 `recover()` 全吞） | — | unverified | — |
| bandit | B110（try_except_pass）/ B112（try_except_continue） | LOW | unverified | — |
| pylint | W0702（bare-except）/ W0718（broad-exception-caught） | Warning | unverified | — |
| ESLint | `no-empty`（`allowEmptyCatch: false`） | 依設定 | unverified | — |

### 壞味道

```go
defer func() {
	if r := recover(); r != nil {
		// 全吞：不記錄、不回傳錯誤，請求看起來像成功
	}
}()

if err := verifySignature(msg, sig); err != nil {
	// 驗簽失敗被當成通過
}
return handle(msg)
```

```python
try:
    charge(order)
except Exception:          # 幾乎什麼都接
    return {"ok": True}    # 失敗被回報成成功

try:
    verify_signature(msg, sig)
except:                    # 裸 except：SystemExit / KeyboardInterrupt 也吞
    log.info("skip")
```

```javascript
try {
  await verifyToken(token);
} catch (e) {
  // 驗證失敗，卻繼續往下走
}
return next();
```

### 過關寫法

三個要素缺一不可：**捕捉最窄的型別**、**保留原始錯誤**、
**失敗時控制流必須中止**。掃描器實際看的是 catch 的型別寬度與區塊內容，
所以空 catch 或只有 `pass` 一定被標，補上記錄與失敗回應才會消失。

```go
defer func() {
	if r := recover(); r != nil {
		log.Printf("panic in handler: %v\n%s", r, debug.Stack()) // 記到日誌
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}()

// 分支處理特定錯誤，其餘一律往上傳，不要就地吞掉
if errors.Is(err, sql.ErrNoRows) {
	return ErrNotFound
}
if err != nil {
	return fmt.Errorf("load order: %w", err)
}
```

```python
try:
    charge(order)
except PaymentDeclined as e:
    logger.warning("declined order=%s: %s", order.id, e)
    raise HTTPException(status_code=402, detail="payment declined") from e
except (ConnectionError, TimeoutError) as e:
    logger.exception("payment gateway unreachable")
    raise HTTPException(status_code=503, detail="try again later") from e

# 最外層統一 handler 可以接 Exception，但必須「記錄 + 回傳失敗」
@app.errorhandler(Exception)
def on_error(e):
    logger.exception("unhandled")
    return {"error": "internal server error"}, 500
```

```javascript
try {
  await verifyToken(token);
} catch (err) {
  if (err instanceof TokenExpiredError) {
    return res.status(401).json({ error: "token expired" });
  }
  logger.error({ err }, "token verification failed");
  return res.status(401).json({ error: "unauthorized" }); // 失敗就是失敗
}
```

### 常見誤判與處置

- **最外層框架 error handler 捕捉全部例外**——這是設計，不是缺陷。
  處置：確保該處同時做到「完整記錄」與「回傳明確失敗狀態」，
  多數工具就不再視為空 catch；仍被標記時標記誤判，
  佐證註明它是唯一的 top-level handler 與其檔案行號。

- **Go 的 `recover()` 用來避免單一請求打掛整個 process**——合理做法。
  處置：recover 之後有記錄且回傳 5xx 即可標記誤判；
  **若 recover 後繼續走成功路徑，是真漏洞**，不得以「防止 crash」為由結案。

- **重試迴圈的 `except Exception: continue`（bandit B112）**——
  處置：改成只捕捉可重試的型別（如 `TimeoutError`、`ConnectionError`）並設重試上限，
  超過上限就往上拋。改寫後告警自然消失，且行為更正確。

### 判定準則

真漏洞：捕捉範圍涵蓋所有例外，且捕捉後控制流繼續走成功路徑——
尤其是身分驗證、授權、簽章驗證、付款、額度扣減這類判斷。

真漏洞：catch / except 區塊為空、只有 `pass`、只有 `continue`、或只有註解。

真漏洞：使用裸 `except:`，或捕捉到 `Throwable` / `Error` 這種層級。

可接受：最外層統一 handler 捕捉廣義例外，但有完整記錄並回傳失敗狀態。

可接受：捕捉具體型別後轉譯為領域錯誤並往上拋，原始錯誤以 `%w` 或 `from e` 保留。
