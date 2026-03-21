package users

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kalvin/warta/internal/auth"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	db        *pgxpool.Pool
	jwtSecret string
}

func RegisterRoutes(mux *http.ServeMux, db *pgxpool.Pool, jwtSecret string) {
	h := &Handler{db: db, jwtSecret: jwtSecret}
	mux.HandleFunc("GET /api/users/me", auth.WithAuth(jwtSecret, h.Me))
	mux.HandleFunc("PUT /api/users/me", auth.WithAuth(jwtSecret, h.UpdateMe))
	mux.HandleFunc("PUT /api/users/me/password", auth.WithAuth(jwtSecret, h.ChangePassword))
	mux.HandleFunc("GET /api/users/{id}", auth.WithAuth(jwtSecret, h.GetUser))
	mux.HandleFunc("GET /api/users", auth.WithAuth(jwtSecret, h.ListUsers))
	// Admin routes
	mux.HandleFunc("GET /api/admin/users", auth.WithAuth(jwtSecret, h.AdminListUsers))
}

func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(auth.ClaimsKey).(*auth.Claims)
	h.getUserByID(w, r, claims.UserID, true)
}

func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	h.getUserByID(w, r, id, false)
}

func (h *Handler) getUserByID(w http.ResponseWriter, r *http.Request, id string, isSelf bool) {
	type UserProfile struct {
		ID                string    `json:"id"`
		Username          string    `json:"username"`
		DisplayName       string    `json:"display_name"`
		Bio               string    `json:"bio"`
		AvatarPath        string    `json:"avatar_path"`
		IsAdmin           bool      `json:"is_admin"`
		CreatedAt         time.Time `json:"created_at"`
		// Only for self
		Email             string    `json:"email,omitempty"`
		ThemePref         string    `json:"theme_pref,omitempty"`
		StorageUsedBytes  int64     `json:"storage_used_bytes,omitempty"`
		StorageLimitBytes int64     `json:"storage_limit_bytes,omitempty"`
	}
	var u UserProfile
	var email, theme string
	var storageUsed, storageLimit int64

	err := h.db.QueryRow(r.Context(), `
		SELECT id, username, display_name, bio, avatar_path, is_admin, created_at,
			email, theme_pref, storage_used_bytes, storage_limit_bytes
		FROM users WHERE id=$1 AND is_active=TRUE`, id,
	).Scan(&u.ID, &u.Username, &u.DisplayName, &u.Bio, &u.AvatarPath,
		&u.IsAdmin, &u.CreatedAt, &email, &theme, &storageUsed, &storageLimit)
	if err != nil {
		jsonError(w, "User not found", http.StatusNotFound)
		return
	}
	if isSelf {
		u.Email = email
		u.ThemePref = theme
		u.StorageUsedBytes = storageUsed
		u.StorageLimitBytes = storageLimit
	}
	jsonOK(w, u)
}

func (h *Handler) UpdateMe(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(auth.ClaimsKey).(*auth.Claims)
	var req struct {
		DisplayName string `json:"display_name"`
		Bio         string `json:"bio"`
		ThemePref   string `json:"theme_pref"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.ThemePref != "" && req.ThemePref != "auto" && req.ThemePref != "light" && req.ThemePref != "dark" {
		jsonError(w, "theme_pref must be auto, light, or dark", http.StatusBadRequest)
		return
	}

	h.db.Exec(r.Context(), `
		UPDATE users SET
			display_name = COALESCE(NULLIF($1, ''), display_name),
			bio = COALESCE(NULLIF($2, ''), bio),
			theme_pref = COALESCE(NULLIF($3, ''), theme_pref),
			updated_at = NOW()
		WHERE id=$4`,
		req.DisplayName, req.Bio, req.ThemePref, claims.UserID,
	)
	jsonOK(w, map[string]string{"message": "Profile updated"})
}

func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(auth.ClaimsKey).(*auth.Claims)
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if len(req.NewPassword) < 8 {
		jsonError(w, "New password must be at least 8 characters", http.StatusBadRequest)
		return
	}
	var hash string
	h.db.QueryRow(r.Context(), "SELECT password_hash FROM users WHERE id=$1", claims.UserID).Scan(&hash)
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.CurrentPassword)) != nil {
		jsonError(w, "Current password is incorrect", http.StatusForbidden)
		return
	}
	newHash, _ := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	h.db.Exec(r.Context(),
		"UPDATE users SET password_hash=$1, updated_at=NOW() WHERE id=$2",
		string(newHash), claims.UserID,
	)
	// Invalidate all other sessions
	h.db.Exec(r.Context(), "DELETE FROM sessions WHERE user_id=$1", claims.UserID)
	jsonOK(w, map[string]string{"message": "Password changed. Please log in again."})
}

func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	// Public listing — just username, display name, avatar
	rows, err := h.db.Query(r.Context(), `
		SELECT id, username, display_name, avatar_path
		FROM users WHERE is_active=TRUE ORDER BY display_name ASC
	`)
	if err != nil {
		jsonError(w, "Server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type UserSummary struct {
		ID          string `json:"id"`
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		AvatarPath  string `json:"avatar_path"`
	}
	var users []UserSummary
	for rows.Next() {
		var u UserSummary
		rows.Scan(&u.ID, &u.Username, &u.DisplayName, &u.AvatarPath)
		users = append(users, u)
	}
	if users == nil {
		users = []UserSummary{}
	}
	jsonOK(w, users)
}

func (h *Handler) AdminListUsers(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(auth.ClaimsKey).(*auth.Claims)
	if !claims.IsAdmin {
		jsonError(w, "Admins only", http.StatusForbidden)
		return
	}
	rows, err := h.db.Query(r.Context(), `
		SELECT id, username, email, display_name, is_admin, is_active,
			storage_used_bytes, storage_limit_bytes, created_at
		FROM users ORDER BY created_at DESC
	`)
	if err != nil {
		jsonError(w, "Server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type AdminUserRow struct {
		ID                string    `json:"id"`
		Username          string    `json:"username"`
		Email             string    `json:"email"`
		DisplayName       string    `json:"display_name"`
		IsAdmin           bool      `json:"is_admin"`
		IsActive          bool      `json:"is_active"`
		StorageUsedBytes  int64     `json:"storage_used_bytes"`
		StorageLimitBytes int64     `json:"storage_limit_bytes"`
		CreatedAt         time.Time `json:"created_at"`
	}
	var users []AdminUserRow
	for rows.Next() {
		var u AdminUserRow
		rows.Scan(&u.ID, &u.Username, &u.Email, &u.DisplayName,
			&u.IsAdmin, &u.IsActive, &u.StorageUsedBytes, &u.StorageLimitBytes, &u.CreatedAt)
		users = append(users, u)
	}
	if users == nil {
		users = []AdminUserRow{}
	}
	jsonOK(w, users)
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
