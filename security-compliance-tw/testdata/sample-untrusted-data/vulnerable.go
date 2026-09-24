package main

import (
	"encoding/json"
	"io"
	"net/http"
)

// 登入後導回：next 直接取自查詢字串。
func loginRedirect(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	http.Redirect(w, r, next, http.StatusFound)
}

// 匯入設定：解到 interface{}。
func importSettings(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var v interface{}
	if err := json.Unmarshal(body, &v); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// 偏好設定：用字串自組 Set-Cookie。
func savePreference(w http.ResponseWriter, r *http.Request) {
	theme := r.URL.Query().Get("theme")
	w.Header().Add("Set-Cookie", "theme="+theme+"; Path=/")
	w.Header().Set("X-Theme", theme)
	w.WriteHeader(http.StatusNoContent)
}
