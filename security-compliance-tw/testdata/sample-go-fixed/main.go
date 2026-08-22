// sample-go 的修補對照組。與 ../sample-go/main.go 逐行對應，
// 依 references/checks/*.md 的「過關寫法」修正下列項目：
//
//	SAST-INJ-001  SQL 注入        → 驅動層 placeholder
//	SAST-INJ-002  命令注入        → 不經 shell，argv 逐一傳入
//	SAST-INJ-003  路徑尋訪        → 正規化 → 前綴比對 → 才開檔
//	SAST-ERR-002  錯誤回傳值未檢查 → if err := ...; err != nil
//	DAST-HDR-001/002/003 安全標頭  → 單一 middleware 包住 mux
//	DAST-TLS-001  傳輸未加密      → ListenAndServeTLS + MinVersion TLS 1.2
//
// 刻意未處理：SAST-AUTHZ-001。該項屬需求層決策，需先導入身分機制
// 才能建立單一具名授權入口，見 security-audit/findings.md 第 4 項。
package main

import (
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var db *sql.DB

const dataRoot = "/var/data"

var errPathEscapesRoot = errors.New("path escapes root")

// resolveUnderRoot 是 SAST-INJ-003 的固定三步：正規化 → 確認仍在根目錄內 → 才回傳。
// 順序不可顛倒——先檢查再 Join 等於沒檢查。
func resolveUnderRoot(root, userInput string) (string, error) {
	target := filepath.Join(root, filepath.Clean("/"+userInput))
	if !strings.HasPrefix(target, filepath.Clean(root)+string(os.PathSeparator)) {
		return "", errPathEscapesRoot
	}
	return target, nil
}

// SAST-INJ-001 + SAST-ERR-002
func getUser(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")

	// 參數化查詢：污點分析對標準函式庫的 placeholder 有內建 cleanse 規則
	rows, err := db.Query("SELECT id, name FROM users WHERE name = ?", name)
	if err != nil {
		// err 只流向日誌，回應僅給常數訊息（避免 SAST-ERR-001 / DAST-LEAK-001）
		log.Printf("query users failed: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id   int64
			user string
		)
		if err := rows.Scan(&id, &user); err != nil {
			log.Printf("scan user row failed: %v", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "%d %s\n", id, user)
	}
	if err := rows.Err(); err != nil {
		log.Printf("iterate user rows failed: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}

// SAST-INJ-002 + SAST-INJ-003 + SAST-ERR-002
func convert(w http.ResponseWriter, r *http.Request) {
	target, err := resolveUnderRoot(dataRoot, r.URL.Query().Get("file"))
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// 不經 shell：參數當成 argv 逐一傳入，沒有 metacharacter 可以逃逸
	if err := exec.Command("convert", target, "out.png").Run(); err != nil {
		log.Printf("convert %s failed: %v", target, err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	fmt.Fprintln(w, "ok")
}

// SAST-INJ-003 + SAST-ERR-002
func readFile(w http.ResponseWriter, r *http.Request) {
	target, err := resolveUnderRoot(dataRoot, r.URL.Query().Get("file"))
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	data, err := os.ReadFile(target)
	if err != nil {
		log.Printf("read %s failed: %v", target, err)
		// 不區分「不存在」與「無權限」，避免以錯誤訊息探測檔案是否存在
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if _, err := w.Write(data); err != nil {
		log.Printf("write response failed: %v", err)
	}
}

// DAST-HDR-001/002/003：集中在 middleware 一次設完，包在 mux 外層涵蓋所有路由。
// 散在各 handler 必漏，DAST 只要掃到一條沒有標頭的路徑就成立。
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		// X-Frame-Options 與 CSP frame-ancestors 兩者都設：舊掃描器只認前者
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/user", getUser)
	mux.HandleFunc("/convert", convert)
	mux.HandleFunc("/file", readFile)

	// DAST-TLS-001：明列允許的協定版本與 AEAD 套件，不使用 ALL / HIGH 這類集合名稱
	srv := &http.Server{
		Addr:    ":8443",
		Handler: securityHeaders(mux),
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
			// 註：check 檔的過關寫法另含 PreferServerCipherSuites: true，
			// 但該欄位自 Go 1.18 起已被忽略，設了無效果，故此處省略。
		},
	}

	// SAST-ERR-002：綁定失敗必須可觀測，不能讓程序靜默結束
	if err := srv.ListenAndServeTLS(os.Getenv("TLS_CERT"), os.Getenv("TLS_KEY")); err != nil {
		log.Fatalf("server stopped: %v", err)
	}
}
