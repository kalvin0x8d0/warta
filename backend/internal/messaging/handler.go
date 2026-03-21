package messaging

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kalvin/warta/internal/auth"
)

// E2EE Design:
// - Each user generates an ECDH keypair in the browser (Web Crypto API)
// - Public key stored on server at registration/update
// - To send a message:
//   1. Sender fetches recipient's public key
//   2. Sender performs ECDH key agreement to derive shared secret
//   3. Sender encrypts message with AES-GCM using derived key
//   4. Only ciphertext + ephemeral pubkey + nonce stored on server
//   5. Server NEVER sees plaintext
// - "Safety first: messages are end-to-end encrypted. If you lose access
//   to your account, message history cannot be recovered."

type Handler struct {
	db        *pgxpool.Pool
	jwtSecret string
	hub       *Hub
}

// Hub manages active WebSocket connections
type Hub struct {
	mu          sync.RWMutex
	connections map[string]*websocket.Conn // userID → conn
}

func newHub() *Hub {
	return &Hub{connections: make(map[string]*websocket.Conn)}
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true }, // nginx handles origin
}

func RegisterRoutes(mux *http.ServeMux, db *pgxpool.Pool, jwtSecret string) {
	h := &Handler{db: db, jwtSecret: jwtSecret, hub: newHub()}
	mux.HandleFunc("GET /ws", h.WebSocket)
	mux.HandleFunc("GET /api/messages/{userID}", auth.WithAuth(jwtSecret, h.GetConversation))
	mux.HandleFunc("POST /api/messages/{userID}", auth.WithAuth(jwtSecret, h.SendMessage))
	mux.HandleFunc("GET /api/messages", auth.WithAuth(jwtSecret, h.ListConversations))
	mux.HandleFunc("GET /api/users/{userID}/pubkey", auth.WithAuth(jwtSecret, h.GetPublicKey))
	mux.HandleFunc("PUT /api/users/me/pubkey", auth.WithAuth(jwtSecret, h.UpdatePublicKey))
}

func (h *Handler) WebSocket(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.RequireAuth(h.jwtSecret, r)
	if !ok {
		// Try token from query param for WS (headers aren't easy in browser WS)
		r2 := r.Clone(r.Context())
		r2.Header.Set("Authorization", "Bearer "+r.URL.Query().Get("token"))
		claims, ok = auth.RequireAuth(h.jwtSecret, r2)
		if !ok {
			http.Error(w, "Unauthorised", http.StatusUnauthorized)
			return
		}
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	h.hub.mu.Lock()
	h.hub.connections[claims.UserID] = conn
	h.hub.mu.Unlock()

	defer func() {
		h.hub.mu.Lock()
		delete(h.hub.connections, claims.UserID)
		h.hub.mu.Unlock()
	}()

	// Keep connection alive, handle pings
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func (h *Handler) SendMessage(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(auth.ClaimsKey).(*auth.Claims)
	recipientID := r.PathValue("userID")
	ctx := r.Context()

	// Verify recipient exists
	var exists bool
	h.db.QueryRow(ctx, "SELECT is_active FROM users WHERE id=$1", recipientID).Scan(&exists)
	if !exists {
		jsonError(w, "Recipient not found", http.StatusNotFound)
		return
	}

	var req struct {
		// All encrypted on client side — server stores opaque blobs
		Ciphertext      string `json:"ciphertext"`       // base64 AES-GCM ciphertext
		EphemeralPubkey string `json:"ephemeral_pubkey"` // base64 sender ephemeral EC pubkey
		Nonce           string `json:"nonce"`            // base64 AES-GCM nonce/IV
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Ciphertext == "" {
		jsonError(w, "Invalid request — message must be encrypted on client", http.StatusBadRequest)
		return
	}

	var msgID string
	err := h.db.QueryRow(ctx,
		`INSERT INTO messages (sender_id, recipient_id, ciphertext, ephemeral_pubkey, nonce)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		claims.UserID, recipientID, req.Ciphertext, req.EphemeralPubkey, req.Nonce,
	).Scan(&msgID)
	if err != nil {
		jsonError(w, "Could not send message", http.StatusInternalServerError)
		return
	}

	// Push real-time notification to recipient if online
	h.hub.mu.RLock()
	recipientConn, online := h.hub.connections[recipientID]
	h.hub.mu.RUnlock()
	if online {
		notification, _ := json.Marshal(map[string]any{
			"type":       "new_message",
			"sender_id":  claims.UserID,
			"message_id": msgID,
		})
		recipientConn.WriteMessage(websocket.TextMessage, notification)
	}

	jsonOK(w, map[string]any{
		"id":      msgID,
		"safety":  "🔒 Safety first: messages are end-to-end encrypted. The server never sees your message content.",
	})
}

func (h *Handler) GetConversation(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(auth.ClaimsKey).(*auth.Claims)
	otherUserID := r.PathValue("userID")
	ctx := r.Context()

	rows, err := h.db.Query(ctx, `
		SELECT id, sender_id, recipient_id, ciphertext, ephemeral_pubkey, nonce, is_read, created_at
		FROM messages
		WHERE (sender_id=$1 AND recipient_id=$2) OR (sender_id=$2 AND recipient_id=$1)
		ORDER BY created_at ASC
	`, claims.UserID, otherUserID)
	if err != nil {
		jsonError(w, "Could not load messages", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type Message struct {
		ID              string    `json:"id"`
		SenderID        string    `json:"sender_id"`
		RecipientID     string    `json:"recipient_id"`
		Ciphertext      string    `json:"ciphertext"`
		EphemeralPubkey string    `json:"ephemeral_pubkey"`
		Nonce           string    `json:"nonce"`
		IsRead          bool      `json:"is_read"`
		CreatedAt       time.Time `json:"created_at"`
	}
	var messages []Message
	for rows.Next() {
		var m Message
		rows.Scan(&m.ID, &m.SenderID, &m.RecipientID,
			&m.Ciphertext, &m.EphemeralPubkey, &m.Nonce, &m.IsRead, &m.CreatedAt)
		messages = append(messages, m)
	}
	if messages == nil {
		messages = []Message{}
	}

	// Mark as read
	h.db.Exec(ctx,
		"UPDATE messages SET is_read=TRUE WHERE recipient_id=$1 AND sender_id=$2 AND is_read=FALSE",
		claims.UserID, otherUserID,
	)

	jsonOK(w, map[string]any{
		"messages": messages,
		"note":     "Messages are end-to-end encrypted. Decrypt them using the recipient's private key on your device.",
	})
}

func (h *Handler) ListConversations(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(auth.ClaimsKey).(*auth.Claims)
	ctx := r.Context()

	rows, err := h.db.Query(ctx, `
		SELECT DISTINCT ON (other_user)
			CASE WHEN sender_id=$1 THEN recipient_id ELSE sender_id END as other_user,
			m.created_at,
			m.is_read,
			u.username, u.display_name, u.avatar_path,
			COUNT(*) FILTER (WHERE m.recipient_id=$1 AND m.is_read=FALSE) OVER (PARTITION BY
				CASE WHEN sender_id=$1 THEN recipient_id ELSE sender_id END
			) as unread_count
		FROM messages m
		JOIN users u ON u.id = CASE WHEN sender_id=$1 THEN recipient_id ELSE sender_id END
		WHERE sender_id=$1 OR recipient_id=$1
		ORDER BY other_user, m.created_at DESC
	`, claims.UserID)
	if err != nil {
		jsonError(w, "Could not load conversations", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type Convo struct {
		OtherUserID   string    `json:"other_user_id"`
		LastMessageAt time.Time `json:"last_message_at"`
		IsRead        bool      `json:"is_read"`
		Username      string    `json:"username"`
		DisplayName   string    `json:"display_name"`
		AvatarPath    string    `json:"avatar_path"`
		UnreadCount   int       `json:"unread_count"`
	}
	var convos []Convo
	for rows.Next() {
		var c Convo
		rows.Scan(&c.OtherUserID, &c.LastMessageAt, &c.IsRead,
			&c.Username, &c.DisplayName, &c.AvatarPath, &c.UnreadCount)
		convos = append(convos, c)
	}
	if convos == nil {
		convos = []Convo{}
	}
	jsonOK(w, convos)
}

func (h *Handler) GetPublicKey(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userID")
	var pubKey string
	err := h.db.QueryRow(r.Context(),
		"SELECT public_key FROM users WHERE id=$1 AND is_active=TRUE", userID,
	).Scan(&pubKey)
	if err != nil {
		jsonError(w, "User not found", http.StatusNotFound)
		return
	}
	jsonOK(w, map[string]string{"public_key": pubKey})
}

func (h *Handler) UpdatePublicKey(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(auth.ClaimsKey).(*auth.Claims)
	var req struct {
		PublicKey string `json:"public_key"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if req.PublicKey == "" {
		jsonError(w, "public_key required", http.StatusBadRequest)
		return
	}
	h.db.Exec(r.Context(),
		"UPDATE users SET public_key=$1, updated_at=NOW() WHERE id=$2",
		req.PublicKey, claims.UserID,
	)
	jsonOK(w, map[string]string{"message": "Public key updated"})
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
