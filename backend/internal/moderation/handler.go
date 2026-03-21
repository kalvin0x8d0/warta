package moderation

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kalvin/warta/internal/auth"
)

type Handler struct {
	db        *pgxpool.Pool
	jwtSecret string
}

func RegisterRoutes(mux *http.ServeMux, db *pgxpool.Pool, jwtSecret string) {
	h := &Handler{db: db, jwtSecret: jwtSecret}
	mux.HandleFunc("POST /api/mod/vote", auth.WithAuth(jwtSecret, h.Vote))
	mux.HandleFunc("GET /api/mod/queue", auth.WithAuth(jwtSecret, h.Queue))
	mux.HandleFunc("POST /api/mod/admin/remove", auth.WithAuth(jwtSecret, h.AdminRemove))
	mux.HandleFunc("POST /api/mod/admin/restore", auth.WithAuth(jwtSecret, h.AdminRestore))
	mux.HandleFunc("POST /api/mod/admin/user/disable", auth.WithAuth(jwtSecret, h.AdminDisableUser))
}

func (h *Handler) Vote(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(auth.ClaimsKey).(*auth.Claims)
	ctx := r.Context()

	var req struct {
		TargetType string `json:"target_type"` // post or comment
		TargetID   string `json:"target_id"`
		Vote       string `json:"vote"`   // remove or keep
		Reason     string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if req.Vote != "remove" && req.Vote != "keep" {
		jsonError(w, "Vote must be 'remove' or 'keep'", http.StatusBadRequest)
		return
	}
	if req.TargetType != "post" && req.TargetType != "comment" {
		jsonError(w, "target_type must be 'post' or 'comment'", http.StatusBadRequest)
		return
	}

	// Upsert vote
	_, err := h.db.Exec(ctx,
		`INSERT INTO mod_votes (target_type, target_id, voter_id, vote, reason)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (target_type, target_id, voter_id) DO UPDATE SET vote=$4, reason=$5`,
		req.TargetType, req.TargetID, claims.UserID, req.Vote, req.Reason,
	)
	if err != nil {
		jsonError(w, "Could not record vote", http.StatusInternalServerError)
		return
	}

	// Check threshold — get total active users and vote counts
	var totalUsers int
	h.db.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE is_active=TRUE").Scan(&totalUsers)

	var removeVotes, keepVotes int
	h.db.QueryRow(ctx,
		`SELECT
			COUNT(*) FILTER (WHERE vote='remove'),
			COUNT(*) FILTER (WHERE vote='keep')
		 FROM mod_votes WHERE target_type=$1 AND target_id=$2`,
		req.TargetType, req.TargetID,
	).Scan(&removeVotes, &keepVotes)

	totalVotes := removeVotes + keepVotes
	var autoRemoved bool

	// 2/3 majority of voters (minimum 3 votes to avoid abuse in tiny groups)
	if totalVotes >= 3 && float64(removeVotes)/float64(totalVotes) >= 2.0/3.0 {
		// Auto-remove
		if req.TargetType == "post" {
			h.db.Exec(ctx,
				`UPDATE posts SET is_removed=TRUE, removed_by=NULL, removed_at=NOW(),
				 removal_reason='Removed by community vote (2/3 majority)' WHERE id=$1`,
				req.TargetID,
			)
		} else {
			h.db.Exec(ctx,
				"UPDATE comments SET is_removed=TRUE WHERE id=$1", req.TargetID,
			)
		}
		autoRemoved = true
	}

	jsonOK(w, map[string]any{
		"remove_votes": removeVotes,
		"keep_votes":   keepVotes,
		"total_votes":  totalVotes,
		"auto_removed": autoRemoved,
		"threshold":    "2/3 of votes needed to remove (minimum 3 votes)",
	})
}

func (h *Handler) Queue(w http.ResponseWriter, r *http.Request) {
	// Show content with at least 1 remove vote that hasn't been removed yet
	claims := r.Context().Value(auth.ClaimsKey).(*auth.Claims)
	if !claims.IsAdmin {
		jsonError(w, "Admins only", http.StatusForbidden)
		return
	}
	ctx := r.Context()

	rows, err := h.db.Query(ctx, `
		SELECT mv.target_type, mv.target_id,
			COUNT(*) FILTER (WHERE mv.vote='remove') as remove_votes,
			COUNT(*) FILTER (WHERE mv.vote='keep') as keep_votes,
			MAX(mv.created_at) as last_vote
		FROM mod_votes mv
		LEFT JOIN posts p ON mv.target_type='post' AND p.id=mv.target_id AND p.is_removed=FALSE
		LEFT JOIN comments c ON mv.target_type='comment' AND c.id=mv.target_id AND c.is_removed=FALSE
		WHERE (p.id IS NOT NULL OR c.id IS NOT NULL)
		GROUP BY mv.target_type, mv.target_id
		HAVING COUNT(*) FILTER (WHERE mv.vote='remove') > 0
		ORDER BY last_vote DESC
	`)
	if err != nil {
		jsonError(w, "Could not load queue", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type QueueItem struct {
		TargetType   string    `json:"target_type"`
		TargetID     string    `json:"target_id"`
		RemoveVotes  int       `json:"remove_votes"`
		KeepVotes    int       `json:"keep_votes"`
		LastVote     time.Time `json:"last_vote"`
	}
	var items []QueueItem
	for rows.Next() {
		var q QueueItem
		rows.Scan(&q.TargetType, &q.TargetID, &q.RemoveVotes, &q.KeepVotes, &q.LastVote)
		items = append(items, q)
	}
	if items == nil {
		items = []QueueItem{}
	}
	jsonOK(w, items)
}

func (h *Handler) AdminRemove(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(auth.ClaimsKey).(*auth.Claims)
	if !claims.IsAdmin {
		jsonError(w, "Admins only", http.StatusForbidden)
		return
	}
	var req struct {
		TargetType string `json:"target_type"`
		TargetID   string `json:"target_id"`
		Reason     string `json:"reason"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.TargetType == "post" {
		h.db.Exec(r.Context(),
			`UPDATE posts SET is_removed=TRUE, removed_by=$1, removed_at=NOW(), removal_reason=$2 WHERE id=$3`,
			claims.UserID, req.Reason, req.TargetID,
		)
	} else {
		h.db.Exec(r.Context(), "UPDATE comments SET is_removed=TRUE WHERE id=$1", req.TargetID)
	}
	jsonOK(w, map[string]string{"message": "Removed"})
}

func (h *Handler) AdminRestore(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(auth.ClaimsKey).(*auth.Claims)
	if !claims.IsAdmin {
		jsonError(w, "Admins only", http.StatusForbidden)
		return
	}
	var req struct {
		TargetType string `json:"target_type"`
		TargetID   string `json:"target_id"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.TargetType == "post" {
		h.db.Exec(r.Context(),
			"UPDATE posts SET is_removed=FALSE, removed_by=NULL, removed_at=NULL, removal_reason='' WHERE id=$1",
			req.TargetID,
		)
	} else {
		h.db.Exec(r.Context(), "UPDATE comments SET is_removed=FALSE WHERE id=$1", req.TargetID)
	}
	// Clear votes
	h.db.Exec(r.Context(),
		"DELETE FROM mod_votes WHERE target_type=$1 AND target_id=$2",
		req.TargetType, req.TargetID,
	)
	jsonOK(w, map[string]string{"message": "Restored"})
}

func (h *Handler) AdminDisableUser(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(auth.ClaimsKey).(*auth.Claims)
	if !claims.IsAdmin {
		jsonError(w, "Admins only", http.StatusForbidden)
		return
	}
	var req struct {
		UserID  string `json:"user_id"`
		Disable bool   `json:"disable"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	h.db.Exec(r.Context(), "UPDATE users SET is_active=$1 WHERE id=$2 AND is_admin=FALSE",
		!req.Disable, req.UserID,
	)
	msg := "User enabled"
	if req.Disable {
		msg = "User disabled"
	}
	jsonOK(w, map[string]string{"message": msg})
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
