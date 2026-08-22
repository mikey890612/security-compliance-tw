package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
)

var db *sql.DB

// 應命中 SAST-INJ-001
func getUser(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	q := "SELECT * FROM users WHERE name = '" + name + "'"
	rows, _ := db.Query(q)
	defer rows.Close()
	fmt.Fprintln(w, "ok")
}

// 應命中 SAST-INJ-002
func convert(w http.ResponseWriter, r *http.Request) {
	f := r.URL.Query().Get("file")
	exec.Command("sh", "-c", "convert "+f+" out.png").Run()
}

// 應命中 SAST-INJ-003
func readFile(w http.ResponseWriter, r *http.Request) {
	data, _ := os.ReadFile("/var/data/" + r.URL.Query().Get("file"))
	w.Write(data)
}

// 應命中 DAST-HDR-001/002/003：沒有任何安全標頭 middleware
func main() {
	http.HandleFunc("/user", getUser)
	http.HandleFunc("/convert", convert)
	http.HandleFunc("/file", readFile)
	http.ListenAndServe(":8080", nil)
}
