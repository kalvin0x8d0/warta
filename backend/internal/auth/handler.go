package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	db        *pgxpool.Pool
	jwtSecret string
}

type Claims struct {
	UserID  string `json:"user_id"`
	IsAdmin bool   `json:"is_admin"`
	jwt.RegisteredClaims
}

func RegisterRoutes(mux *http.ServeMux, db *pgxpool.Pool, jwtSecret string) {
	h := &Handler{db: db, jwtSecret: jwtSecret}
	mux.HandleFunc("POST /api/setup", h.Setup)
	mux.HandleFunc("POST /api/auth/register", h.Register)
	mux.HandleFunc("POST /api/auth/login", h.Login)
	mux.HandleFunc("POST /api/auth/logout", h.Logout)
	mux.HandleFunc("POST /api/invites", h.CreateInvite)
	mux.HandleFunc("DELETE /api/invites/{code}", h.RevokeInvite)
	mux.HandleFunc("GET /api/invites", h.ListInvites)
	mux.HandleFunc("GET /api/invites/{code}/check", h.CheckInvite)
}

// Setup — first run only, creates the first admin
func (h *Handler) Setup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var completed bool
	err := h.db.QueryRow(ctx, "SELECT completed FROM setup_state WHERE id=1").Scan(&completed)
	if err != nil || completed {
		jsonError(w, "Setup already completed or unavailable", http.StatusForbidden)
		return
	}
	var req struct {
		Username    string `json:"username"`
		Email       string `json:"email"`
		Password    string `json:"password"`
		DisplayName string `json:"display_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if len(req.Password) < 8 {
		jsonError(w, "Password must be at least 8 characters", http.StatusBadRequest)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		jsonError(w, "Server error", http.StatusInternalServerError)
		return
	}
	var userID string
	err = h.db.QueryRow(ctx,
		`INSERT INTO users (username, email, password_hash, display_name, is_admin)
		 VALUES ($1, $2, $3, $4, TRUE) RETURNING id`,
		req.Username, req.Email, string(hash), req.DisplayName,
	).Scan(&userID)
	if err != nil {
		jsonError(w, "Could not create admin: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.db.Exec(ctx, "UPDATE setup_state SET completed=TRUE, completed_at=NOW() WHERE id=1")
	jsonOK(w, map[string]string{"message": "Admin created. Setup complete.", "user_id": userID})
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req struct {
		InviteCode  string `json:"invite_code"`
		Username    string `json:"username"`
		Email       string `json:"email"`
		Password    string `json:"password"`
		DisplayName string `json:"display_name"`
		PublicKey   string `json:"public_key"` // E2EE key from client
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Validate invite
	var inviteID string
	var useCount, maxUses int
	var expiresAt *time.Time
	var isActive bool
	err := h.db.QueryRow(ctx,
		`SELECT id, use_count, max_uses, expires_at, is_active FROM invites WHERE code=$1`,
		req.InviteCode,
	).Scan(&inviteID, &useCount, &maxUses, &expiresAt, &isActive)
	if err != nil {
		jsonError(w, "Invalid invite code", http.StatusBadRequest)
		return
	}
	if !isActive || useCount >= maxUses {
		jsonError(w, "Invite is no longer valid", http.StatusBadRequest)
		return
	}
	if expiresAt != nil && time.Now().After(*expiresAt) {
		jsonError(w, "Invite has expired", http.StatusBadRequest)
		return
	}

	if len(req.Password) < 8 {
		jsonError(w, "Password must be at least 8 characters", http.StatusBadRequest)
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)

	var userID string
	err = h.db.QueryRow(ctx,
		`INSERT INTO users (username, email, password_hash, display_name, public_key)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		req.Username, req.Email, string(hash), req.DisplayName, req.PublicKey,
	).Scan(&userID)
	if err != nil {
		if strings.Contains(err.Error(), "unique") {
			jsonError(w, "Username or email already taken", http.StatusConflict)
		} else {
			jsonError(w, "Could not create account", http.StatusInternalServerError)
		}
		return
	}

	// Mark invite used
	h.db.Exec(ctx,
		`UPDATE invites SET use_count=use_count+1, used_by=$1,
		 is_active=CASE WHEN use_count+1 >= max_uses THEN FALSE ELSE is_active END
		 WHERE id=$2`,
		userID, inviteID,
	)

	token, _ := h.issueToken(userID, false)
	jsonOK(w, map[string]string{"token": token, "user_id": userID})
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req struct {
		Login    string `json:"login"` // username or email
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request", http.StatusBadRequest)
		return
	}
	var userID, hash string
	var isAdmin, isActive bool
	err := h.db.QueryRow(ctx,
		`SELECT id, password_hash, is_admin, is_active FROM users
		 WHERE username=$1 OR email=$1`,
		req.Login,
	).Scan(&userID, &hash, &isAdmin, &isActive)
	if err != nil {
		jsonError(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	if !isActive {
		jsonError(w, "Account is disabled", http.StatusForbidden)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		jsonError(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token, expiresAt := h.issueToken(userID, isAdmin)

	// Store session
	tokenHash := hashToken(token)
	h.db.Exec(ctx,
		`INSERT INTO sessions (user_id, token_hash, ip_address, user_agent, expires_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		userID, tokenHash, r.RemoteAddr, r.UserAgent(), expiresAt,
	)

	jsonOK(w, map[string]any{
		"token":      token,
		"user_id":    userID,
		"is_admin":   isAdmin,
		"expires_at": expiresAt,
	})
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token != "" {
		h.db.Exec(r.Context(), "DELETE FROM sessions WHERE token_hash=$1", hashToken(token))
	}
	jsonOK(w, map[string]string{"message": "Logged out"})
}

func (h *Handler) CreateInvite(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.requireAuth(r)
	if !ok {
		jsonError(w, "Unauthorised", http.StatusUnauthorized)
		return
	}
	expiryDays, _ := strconv.Atoi(os.Getenv("INVITE_EXPIRY_DAYS"))
	if expiryDays == 0 {
		expiryDays = 7
	}
	expiresAt := time.Now().Add(time.Duration(expiryDays) * 24 * time.Hour)

	var code, inviteID string
	err := h.db.QueryRow(r.Context(),
		`INSERT INTO invites (created_by, expires_at) VALUES ($1, $2) RETURNING code, id`,
		claims.UserID, expiresAt,
	).Scan(&code, &inviteID)
	if err != nil {
		jsonError(w, "Could not create invite", http.StatusInternalServerError)
		return
	}
	baseURL := os.Getenv("APP_BASE_URL")
	jsonOK(w, map[string]any{
		"code":       code,
		"id":         inviteID,
		"invite_url": baseURL + "/join/" + code,
		"expires_at": expiresAt,
	})
}

func (h *Handler) RevokeInvite(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.requireAuth(r)
	if !ok {
		jsonError(w, "Unauthorised", http.StatusUnauthorized)
		return
	}
	code := r.PathValue("code")
	var createdBy string
	err := h.db.QueryRow(r.Context(),
		"SELECT created_by FROM invites WHERE code=$1", code,
	).Scan(&createdBy)
	if err != nil {
		jsonError(w, "Invite not found", http.StatusNotFound)
		return
	}
	// Only creator or admin can revoke
	if createdBy != claims.UserID && !claims.IsAdmin {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	h.db.Exec(r.Context(), "UPDATE invites SET is_active=FALSE WHERE code=$1", code)
	jsonOK(w, map[string]string{"message": "Invite revoked"})
}

func (h *Handler) ListInvites(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.requireAuth(r)
	if !ok {
		jsonError(w, "Unauthorised", http.StatusUnauthorized)
		return
	}
	var query string
	var args []any
	if claims.IsAdmin {
		query = `SELECT i.id, i.code, i.use_count, i.max_uses, i.is_active, i.expires_at,
			u.username as created_by_username
			FROM invites i JOIN users u ON u.id=i.created_by ORDER BY i.created_at DESC`
	} else {
		query = `SELECT i.id, i.code, i.use_count, i.max_uses, i.is_active, i.expires_at,
			u.username as created_by_username
			FROM invites i JOIN users u ON u.id=i.created_by
			WHERE i.created_by=$1 ORDER BY i.created_at DESC`
		args = []any{claims.UserID}
	}
	rows, err := h.db.Query(r.Context(), query, args...)
	if err != nil {
		jsonError(w, "Server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type InviteRow struct {
		ID          string     `json:"id"`
		Code        string     `json:"code"`
		UseCount    int        `json:"use_count"`
		MaxUses     int        `json:"max_uses"`
		IsActive    bool       `json:"is_active"`
		ExpiresAt   *time.Time `json:"expires_at"`
		CreatedBy   string     `json:"created_by"`
	}
	var list []InviteRow
	for rows.Next() {
		var inv InviteRow
		rows.Scan(&inv.ID, &inv.Code, &inv.UseCount, &inv.MaxUses, &inv.IsActive, &inv.ExpiresAt, &inv.CreatedBy)
		list = append(list, inv)
	}
	jsonOK(w, list)
}

func (h *Handler) CheckInvite(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	var useCount, maxUses int
	var isActive bool
	var expiresAt *time.Time
	err := h.db.QueryRow(r.Context(),
		`SELECT use_count, max_uses, is_active, expires_at FROM invites WHERE code=$1`, code,
	).Scan(&useCount, &maxUses, &isActive, &expiresAt)
	if err != nil {
		jsonError(w, "Invalid invite", http.StatusNotFound)
		return
	}
	valid := isActive && useCount < maxUses && (expiresAt == nil || time.Now().Before(*expiresAt))
	jsonOK(w, map[string]bool{"valid": valid})
}

// ─── Helpers ────────────────────────────────────────────────────────────────

func (h *Handler) issueToken(userID string, isAdmin bool) (string, time.Time) {
	expiresAt := time.Now().Add(168 * time.Hour) // 7 days
	claims := &Claims{
		UserID:  userID,
		IsAdmin: isAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        uuid.New().String(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := token.SignedString([]byte(h.jwtSecret))
	return signed, expiresAt
}

func (h *Handler) requireAuth(r *http.Request) (*Claims, bool) {
	token := bearerToken(r)
	if token == "" {
		return nil, false
	}
	parsed, err := jwt.ParseWithClaims(token, &Claims{}, func(t *jwt.Token) (any, error) {
		return []byte(h.jwtSecret), nil
	})
	if err != nil || !parsed.Valid {
		return nil, false
	}
	claims, ok := parsed.Claims.(*Claims)
	return claims, ok
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}

func hashToken(token string) string {
	// Simple hash for session storage — not for password use
	sum := 0
	for _, c := range token {
		sum += int(c)
	}
	return strconv.Itoa(sum) + token[len(token)-8:]
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

// RequireAuth exported for use by other handlers
func RequireAuth(jwtSecret string, r *http.Request) (*Claims, bool) {
	token := bearerToken(r)
	if token == "" {
		return nil, false
	}
	parsed, err := jwt.ParseWithClaims(token, &Claims{}, func(t *jwt.Token) (any, error) {
		return []byte(jwtSecret), nil
	})
	if err != nil || !parsed.Valid {
		return nil, false
	}
	claims, ok := parsed.Claims.(*Claims)
	return claims, ok
}

// Context key
type contextKey string
const ClaimsKey contextKey = "claims"

func WithAuth(jwtSecret string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := RequireAuth(jwtSecret, r)
		if !ok {
			jsonError(w, "Unauthorised", http.StatusUnauthorized)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ClaimsKey, claims)))
	}
}
