package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"log"
	"net/http"
)

const (
	csrfCookie  = "csrf"
	maxFormBody = 11 << 20
)

// withCSRF 對狀態變更請求比對 X-CSRF-Token 標頭或 csrf_token 欄位與 Cookie 內的 token。
func withCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := csrfToken(r)
		if token == "" {
			var err error
			if token, err = newToken(); err != nil {
				log.Printf("csrf token: %v", err)
				http.Error(w, "服務暫時無法使用", http.StatusInternalServerError)
				return
			}
			http.SetCookie(w, &http.Cookie{
				Name:     csrfCookie,
				Value:    token,
				Path:     "/",
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
			})
			r.AddCookie(&http.Cookie{Name: csrfCookie, Value: token})
		}

		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
			sent := r.Header.Get("X-CSRF-Token")
			if sent == "" {
				sent = r.PostFormValue("csrf_token")
			}
			if subtle.ConstantTimeCompare([]byte(sent), []byte(token)) != 1 {
				http.Error(w, "請重新整理頁面後再試", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func csrfToken(r *http.Request) string {
	c, err := r.Cookie(csrfCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
