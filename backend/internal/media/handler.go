package media

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kalvin/warta/internal/auth"
)

const (
	AudioMaxSeconds = 420 // 7 minutes
	VideoMaxSeconds = 300 // 5 minutes
	MaxFileBytes    = 500 * 1024 * 1024 // 500MB hard limit per upload
)

var allowedMIME = map[string]string{
	"image/jpeg":  "image",
	"image/png":   "image",
	"image/gif":   "image",
	"image/webp":  "image",
	"audio/mpeg":  "audio",
	"audio/ogg":   "audio",
	"audio/wav":   "audio",
	"audio/mp4":   "audio",
	"video/mp4":   "video",
	"video/webm":  "video",
	"video/ogg":   "video",
}

type Handler struct {
	db          *pgxpool.Pool
	jwtSecret   string
	storagePath string
}

func RegisterRoutes(mux *http.ServeMux, db *pgxpool.Pool, jwtSecret string) {
	storagePath := os.Getenv("STORAGE_PATH")
	if storagePath == "" {
		storagePath = "/app/uploads"
	}
	os.MkdirAll(storagePath, 0755)

	h := &Handler{db: db, jwtSecret: jwtSecret, storagePath: storagePath}
	mux.HandleFunc("POST /api/media/upload", auth.WithAuth(jwtSecret, h.Upload))
	mux.HandleFunc("GET /api/media/quota", auth.WithAuth(jwtSecret, h.GetQuota))
	mux.HandleFunc("DELETE /api/media/{id}", auth.WithAuth(jwtSecret, h.Delete))
}

func (h *Handler) Upload(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(auth.ClaimsKey).(*auth.Claims)
	ctx := r.Context()

	// Check user quota first
	var usedBytes, limitBytes int64
	h.db.QueryRow(ctx,
		"SELECT storage_used_bytes, storage_limit_bytes FROM users WHERE id=$1",
		claims.UserID,
	).Scan(&usedBytes, &limitBytes)

	// Parse multipart — limit to MaxFileBytes
	r.Body = http.MaxBytesReader(w, r.Body, MaxFileBytes)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		jsonError(w, "File too large or bad form data", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		jsonError(w, "No file provided", http.StatusBadRequest)
		return
	}
	defer file.Close()

	postID := r.FormValue("post_id")

	// Detect MIME
	buf := make([]byte, 512)
	n, _ := file.Read(buf)
	mimeType := http.DetectContentType(buf[:n])
	// Also trust the header Content-Type for audio/video since DetectContentType is limited
	if ct := header.Header.Get("Content-Type"); ct != "" {
		mimeType = ct
	}
	// Strip params like "video/mp4; codecs=..."
	if idx := strings.Index(mimeType, ";"); idx != -1 {
		mimeType = strings.TrimSpace(mimeType[:idx])
	}

	mediaType, ok := allowedMIME[mimeType]
	if !ok {
		jsonError(w, "File type not allowed. Supported: images (JPEG, PNG, GIF, WebP), audio (MP3, OGG, WAV), video (MP4, WebM)", http.StatusBadRequest)
		return
	}

	// File size
	fileSize := header.Size
	if usedBytes+fileSize > limitBytes {
		remaining := limitBytes - usedBytes
		jsonError(w, fmt.Sprintf(
			"Storage quota exceeded. You have %s remaining of your 1024 MB. Please compress your files before uploading.",
			formatBytes(remaining),
		), http.StatusRequestEntityTooLarge)
		return
	}

	// Duration check placeholder (would need ffprobe in production)
	// For now we trust the client's reported duration if provided
	durationStr := r.FormValue("duration_secs")
	var duration *int
	if durationStr != "" {
		d, _ := strconv.Atoi(durationStr)
		if mediaType == "audio" && d > AudioMaxSeconds {
			jsonError(w, fmt.Sprintf("Audio too long. Maximum is %d minutes (7 minutes).", AudioMaxSeconds/60), http.StatusBadRequest)
			return
		}
		if mediaType == "video" && d > VideoMaxSeconds {
			jsonError(w, fmt.Sprintf("Video too long. Maximum is %d minutes (5 minutes).", VideoMaxSeconds/60), http.StatusBadRequest)
			return
		}
		duration = &d
	}

	// Save file
	ext := filepath.Ext(header.Filename)
	newFilename := uuid.New().String() + ext
	// Organise by user
	userDir := filepath.Join(h.storagePath, claims.UserID[:8])
	os.MkdirAll(userDir, 0755)
	destPath := filepath.Join(userDir, newFilename)

	dest, err := os.Create(destPath)
	if err != nil {
		jsonError(w, "Could not save file", http.StatusInternalServerError)
		return
	}
	defer dest.Close()

	// Reset reader and copy
	file.Seek(0, 0)
	written, err := io.Copy(dest, file)
	if err != nil || written != fileSize {
		os.Remove(destPath)
		jsonError(w, "Upload failed", http.StatusInternalServerError)
		return
	}

	// Relative path for serving
	storagePath := claims.UserID[:8] + "/" + newFilename

	// DB record
	var mediaID string
	var postIDPtr *string
	if postID != "" {
		postIDPtr = &postID
	}
	err = h.db.QueryRow(ctx,
		`INSERT INTO media (post_id, user_id, media_type, filename, storage_path, mime_type, size_bytes, duration_secs)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
		postIDPtr, claims.UserID, mediaType, header.Filename, storagePath, mimeType, written, duration,
	).Scan(&mediaID)
	if err != nil {
		os.Remove(destPath)
		jsonError(w, "Could not record upload", http.StatusInternalServerError)
		return
	}

	// Update storage usage
	h.db.Exec(ctx,
		"UPDATE users SET storage_used_bytes=storage_used_bytes+$1 WHERE id=$2",
		written, claims.UserID,
	)

	compressionHint := ""
	if mediaType == "image" {
		compressionHint = "Tip: Use an image compression app (like Squoosh or TinyPNG) before uploading to save your storage quota."
	} else if mediaType == "video" {
		compressionHint = "Tip: Use HandBrake to compress your video before uploading. It saves a lot of storage space."
	} else if mediaType == "audio" {
		compressionHint = "Tip: Use Audacity or an MP3 compressor to reduce audio file size before uploading."
	}

	jsonOK(w, map[string]any{
		"id":               mediaID,
		"url":              "/uploads/" + storagePath,
		"media_type":       mediaType,
		"size_bytes":       written,
		"compression_hint": compressionHint,
		"quota": map[string]any{
			"used_bytes":  usedBytes + written,
			"limit_bytes": limitBytes,
			"used_pct":    fmt.Sprintf("%.1f%%", float64(usedBytes+written)/float64(limitBytes)*100),
		},
	})
}

func (h *Handler) GetQuota(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(auth.ClaimsKey).(*auth.Claims)
	var used, limit int64
	h.db.QueryRow(r.Context(),
		"SELECT storage_used_bytes, storage_limit_bytes FROM users WHERE id=$1",
		claims.UserID,
	).Scan(&used, &limit)
	jsonOK(w, map[string]any{
		"used_bytes":      used,
		"limit_bytes":     limit,
		"used_readable":   formatBytes(used),
		"limit_readable":  formatBytes(limit),
		"remaining_bytes": limit - used,
		"used_pct":        fmt.Sprintf("%.1f", float64(used)/float64(limit)*100),
	})
}

func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(auth.ClaimsKey).(*auth.Claims)
	id := r.PathValue("id")
	ctx := r.Context()

	var userID, storagePath string
	var sizeBytes int64
	err := h.db.QueryRow(ctx,
		"SELECT user_id, storage_path, size_bytes FROM media WHERE id=$1", id,
	).Scan(&userID, &storagePath, &sizeBytes)
	if err != nil {
		jsonError(w, "Not found", http.StatusNotFound)
		return
	}
	if userID != claims.UserID && !claims.IsAdmin {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Delete file
	fullPath := filepath.Join(h.storagePath, storagePath)
	os.Remove(fullPath)

	// DB
	h.db.Exec(ctx, "DELETE FROM media WHERE id=$1", id)
	h.db.Exec(ctx,
		"UPDATE users SET storage_used_bytes=GREATEST(0, storage_used_bytes-$1) WHERE id=$2",
		sizeBytes, userID,
	)
	jsonOK(w, map[string]string{"message": "Deleted"})
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func jsonOK(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// Suppress unused import
var _ = time.Now
