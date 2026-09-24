package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// 只接受站內相對路徑；其餘一律導回首頁。檢查的是最後要送出的字串。
func safeNext(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return "/"
	}
	next := u.RequestURI()
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.Contains(next, `\`) {
		return "/"
	}
	return next
}

func loginRedirectFixed(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusFound)
}

type settings struct {
	Theme    string `json:"theme"`
	PageSize int    `json:"page_size"`
}

func importSettingsFixed(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var s settings
	if err := json.Unmarshal(body, &s); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

var allowedThemes = map[string]bool{"light": true, "dark": true}

func savePreferenceFixed(w http.ResponseWriter, r *http.Request) {
	theme := r.URL.Query().Get("theme")
	if !allowedThemes[theme] {
		theme = "light"
	}
	http.SetCookie(w, &http.Cookie{Name: "theme", Value: theme, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	w.WriteHeader(http.StatusNoContent)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/login/done", loginRedirect)
	mux.HandleFunc("/settings/import", importSettings)
	mux.HandleFunc("/preference", savePreference)
	mux.HandleFunc("/v2/login/done", loginRedirectFixed)
	mux.HandleFunc("/v2/settings/import", importSettingsFixed)
	mux.HandleFunc("/v2/preference", savePreferenceFixed)
	_ = http.ListenAndServe("127.0.0.1:8080", mux)
}
