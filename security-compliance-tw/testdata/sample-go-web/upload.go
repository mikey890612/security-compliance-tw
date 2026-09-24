package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

// 上傳檔存在網站根目錄之外，不經由 /static 提供。
const uploadRoot = "/var/lib/sample-go-web/uploads"

type uploadPolicy struct {
	field    string
	dir      string
	maxBytes int64
	allowed  map[string]string // http.DetectContentType 的結果 → 存檔副檔名
}

var (
	avatarPolicy = uploadPolicy{
		field: "avatar", dir: "avatars", maxBytes: 2 << 20,
		allowed: map[string]string{"image/png": ".png", "image/jpeg": ".jpg"},
	}
	sheetPolicy = uploadPolicy{
		field: "sheet", dir: "imports", maxBytes: 10 << 20,
		allowed: map[string]string{"application/zip": ".xlsx"},
	}
	attachmentPolicy = uploadPolicy{
		field: "attachment", dir: "attachments", maxBytes: 10 << 20,
		allowed: map[string]string{"application/pdf": ".pdf", "image/png": ".png", "image/jpeg": ".jpg"},
	}
	editorImagePolicy = uploadPolicy{
		field: "file", dir: "editor", maxBytes: 2 << 20,
		allowed: map[string]string{"image/png": ".png", "image/jpeg": ".jpg"},
	}
)

var (
	errFileType = errors.New("file type not allowed")
	errTooLarge = errors.New("file too large")
)

func uploadHandler(p uploadPolicy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, p.maxBytes+(1<<20))
		f, _, err := r.FormFile(p.field)
		if err != nil {
			log.Printf("upload %s: %v", p.field, err)
			http.Error(w, "上傳失敗", http.StatusBadRequest)
			return
		}
		defer f.Close()

		id, err := store(p, f)
		if err != nil {
			log.Printf("upload %s: %v", p.field, err)
			http.Error(w, "上傳失敗", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{"id": id}); err != nil {
			log.Printf("upload %s: write response: %v", p.field, err)
		}
	}
}

// store 以檔頭判斷類型、限制大小，並以系統產生的名稱存檔；使用者提供的檔名一律不用。
func store(p uploadPolicy, src io.Reader) (string, error) {
	head := make([]byte, 512)
	n, err := io.ReadFull(src, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return "", err
	}
	ext, ok := p.allowed[http.DetectContentType(head[:n])]
	if !ok {
		return "", errFileType
	}

	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	name := hex.EncodeToString(raw) + ext
	path := filepath.Join(uploadRoot, p.dir, name)

	dst, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	if err := copyLimited(dst, head[:n], src, p.maxBytes); err != nil {
		_ = dst.Close()
		if rmErr := os.Remove(path); rmErr != nil {
			log.Printf("remove partial upload: %v", rmErr)
		}
		return "", err
	}
	return name, dst.Close()
}

func copyLimited(dst io.Writer, head []byte, rest io.Reader, max int64) error {
	if _, err := dst.Write(head); err != nil {
		return err
	}
	remaining := max - int64(len(head))
	written, err := io.Copy(dst, io.LimitReader(rest, remaining+1))
	if err != nil {
		return err
	}
	if written > remaining {
		return errTooLarge
	}
	return nil
}
