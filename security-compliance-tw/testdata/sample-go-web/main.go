package main

import (
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"
)

var pages = template.Must(template.ParseGlob("templates/*.html"))

func main() {
	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", noListing(http.FileServer(http.Dir("static")))))

	mux.HandleFunc("GET /profile", page("profile.html"))
	mux.HandleFunc("GET /import", page("import.html"))
	mux.HandleFunc("GET /attachments", page("attachment.html"))

	mux.HandleFunc("POST /profile/avatar", uploadHandler(avatarPolicy))
	mux.HandleFunc("POST /import", uploadHandler(sheetPolicy))
	mux.HandleFunc("POST /attachments", uploadHandler(attachmentPolicy))
	mux.HandleFunc("POST /editor/images", uploadHandler(editorImagePolicy))

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           withCSRF(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

// noListing 讓目錄路徑回 404，不列出檔案清單。
func noListing(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "" || strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func page(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := map[string]string{"CSRFToken": csrfToken(r)}
		if err := pages.ExecuteTemplate(w, name, data); err != nil {
			log.Printf("render %s: %v", name, err)
			http.Error(w, "頁面暫時無法顯示", http.StatusInternalServerError)
		}
	}
}
