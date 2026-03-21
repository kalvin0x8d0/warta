package posts

import (
	"encoding/json"
	"net/http"
	"strconv"
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
	mux.HandleFunc("GET /api/posts", auth.WithAuth(jwtSecret, h.Feed))
	mux.HandleFunc("POST /api/posts", auth.WithAuth(jwtSecret, h.Create))
	mux.HandleFunc("GET /api/posts/{id}", auth.WithAuth(jwtSecret, h.GetPost))
	mux.HandleFunc("DELETE /api/posts/{id}", auth.WithAuth(jwtSecret, h.Delete))
	mux.HandleFunc("POST /api/posts/{id}/react", auth.WithAuth(jwtSecret, h.React))
	mux.HandleFunc("GET /api/posts/{id}/comments", auth.WithAuth(jwtSecret, h.GetComments))
	mux.HandleFunc("POST /api/posts/{id}/comments", auth.WithAuth(jwtSecret, h.AddComment))
	mux.HandleFunc("DELETE /api/posts/{postID}/comments/{commentID}", auth.WithAuth(jwtSecret, h.DeleteComment))
}

func (h *Handler) Feed(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(auth.ClaimsKey).(*auth.Claims)
	ctx := r.Context()

	// Pagination
	before := r.URL.Query().Get("before") // cursor: created_at of last item
	limitStr := r.URL.Query().Get("limit")
	limit, _ := strconv.Atoi(limitStr)
	if limit <= 0 || limit > 50 {
		limit = 20
	}

	// Filtering
	parentFilter := r.URL.Query().Get("parent")
	typeFilter := r.URL.Query().Get("type")

	query := `
		SELECT p.id, p.post_type, p.content, p.title, p.parent_id, p.created_at,
			u.id as author_id, u.username, u.display_name, u.avatar_path,
			COUNT(DISTINCT r.id) as reaction_count,
			COUNT(DISTINCT c.id) as comment_count,
			EXISTS(SELECT 1 FROM reactions rx WHERE rx.post_id=p.id AND rx.user_id=$1) as user_reacted,
			EXISTS(SELECT 1 FROM posts lf WHERE lf.parent_id=p.id AND lf.post_type='longform' AND lf.is_removed=FALSE) as has_longform
		FROM posts p
		JOIN users u ON u.id = p.author_id
		LEFT JOIN reactions r ON r.post_id = p.id
		LEFT JOIN comments c ON c.post_id = p.id AND c.is_removed=FALSE
		WHERE p.is_removed = FALSE
	`
	args := []any{claims.UserID}
	argN := 2

	if parentFilter != "" {
		query += ` AND p.parent_id = $` + strconv.Itoa(argN)
		args = append(args, parentFilter)
		argN++
	}
	if typeFilter != "" {
		query += ` AND p.post_type = $` + strconv.Itoa(argN)
		args = append(args, typeFilter)
		argN++
	}
	// Default feed: show top-level posts only (no children)
	if parentFilter == "" && typeFilter == "" {
		query += ` AND p.parent_id IS NULL`
	}

	if before != "" {
		query += ` AND p.created_at < $` + strconv.Itoa(argN)
		args = append(args, before)
		argN++
	}
	query += ` GROUP BY p.id, u.id ORDER BY p.created_at DESC LIMIT $` + strconv.Itoa(argN)
	args = append(args, limit)

	rows, err := h.db.Query(ctx, query, args...)
	if err != nil {
		jsonError(w, "Could not load feed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type PostItem struct {
		ID            string    `json:"id"`
		PostType      string    `json:"post_type"`
		Content       string    `json:"content"`
		Title         string    `json:"title"`
		ParentID      *string   `json:"parent_id"`
		CreatedAt     time.Time `json:"created_at"`
		AuthorID      string    `json:"author_id"`
		Username      string    `json:"username"`
		DisplayName   string    `json:"display_name"`
		AvatarPath    string    `json:"avatar_path"`
		ReactionCount int       `json:"reaction_count"`
		CommentCount  int       `json:"comment_count"`
		UserReacted   bool      `json:"user_reacted"`
		HasLongform   bool      `json:"has_longform"`
		Media         []any     `json:"media"`
	}

	var feed []PostItem
	var postIDs []string

	for rows.Next() {
		var p PostItem
		rows.Scan(
			&p.ID, &p.PostType, &p.Content, &p.Title, &p.ParentID, &p.CreatedAt,
			&p.AuthorID, &p.Username, &p.DisplayName, &p.AvatarPath,
			&p.ReactionCount, &p.CommentCount, &p.UserReacted, &p.HasLongform,
		)
		p.Media = []any{}
		feed = append(feed, p)
		postIDs = append(postIDs, p.ID)
	}

	// Attach media
	if len(postIDs) > 0 {
		mediaRows, _ := h.db.Query(ctx,
			`SELECT post_id, id, media_type, filename, storage_path, mime_type, size_bytes, duration_secs, width, height
			 FROM media WHERE post_id = ANY($1)`, postIDs,
		)
		defer mediaRows.Close()
		type MediaItem struct {
			ID           string  `json:"id"`
			MediaType    string  `json:"media_type"`
			Filename     string  `json:"filename"`
			URL          string  `json:"url"`
			MimeType     string  `json:"mime_type"`
			SizeBytes    int64   `json:"size_bytes"`
			DurationSecs *int    `json:"duration_secs,omitempty"`
			Width        *int    `json:"width,omitempty"`
			Height       *int    `json:"height,omitempty"`
		}
		for mediaRows.Next() {
			var postID, id, mt, fn, sp, mime string
			var size int64
			var dur, w, h *int
			mediaRows.Scan(&postID, &id, &mt, &fn, &sp, &mime, &size, &dur, &w, &h)
			for i := range feed {
				if feed[i].ID == postID {
					feed[i].Media = append(feed[i].Media, MediaItem{
						ID: id, MediaType: mt, Filename: fn,
						URL: "/uploads/" + sp, MimeType: mime, SizeBytes: size,
						DurationSecs: dur, Width: w, Height: h,
					})
				}
			}
		}
	}

	jsonOK(w, map[string]any{"posts": feed, "count": len(feed)})
}

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(auth.ClaimsKey).(*auth.Claims)
	ctx := r.Context()

	var req struct {
		PostType string `json:"post_type"` // micro or longform
		Content  string `json:"content"`
		Title    string `json:"title"`
		ParentID string `json:"parent_id"` // if longform expanding a micro
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if req.PostType == "" {
		req.PostType = "micro"
	}
	if len(req.Content) == 0 {
		jsonError(w, "Content cannot be empty", http.StatusBadRequest)
		return
	}
	if req.PostType == "micro" && len(req.Content) > 280 {
		jsonError(w, "Micro post cannot exceed 280 characters", http.StatusBadRequest)
		return
	}
	if req.PostType == "longform" && len(req.Content) > 40000 {
		jsonError(w, "Post too long", http.StatusBadRequest)
		return
	}

	var parentID *string
	if req.ParentID != "" {
		parentID = &req.ParentID
	}

	var postID string
	err := h.db.QueryRow(ctx,
		`INSERT INTO posts (author_id, post_type, content, title, parent_id)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		claims.UserID, req.PostType, req.Content, req.Title, parentID,
	).Scan(&postID)
	if err != nil {
		jsonError(w, "Could not create post", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"id": postID, "message": "Post created"})
}

func (h *Handler) GetPost(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(auth.ClaimsKey).(*auth.Claims)
	id := r.PathValue("id")
	ctx := r.Context()

	var post struct {
		ID            string    `json:"id"`
		PostType      string    `json:"post_type"`
		Content       string    `json:"content"`
		Title         string    `json:"title"`
		ParentID      *string   `json:"parent_id"`
		CreatedAt     time.Time `json:"created_at"`
		AuthorID      string    `json:"author_id"`
		Username      string    `json:"username"`
		DisplayName   string    `json:"display_name"`
		AvatarPath    string    `json:"avatar_path"`
		ReactionCount int       `json:"reaction_count"`
		CommentCount  int       `json:"comment_count"`
		UserReacted   bool      `json:"user_reacted"`
	}
	err := h.db.QueryRow(ctx, `
		SELECT p.id, p.post_type, p.content, p.title, p.parent_id, p.created_at,
			u.id, u.username, u.display_name, u.avatar_path,
			COUNT(DISTINCT r.id),
			COUNT(DISTINCT c.id),
			EXISTS(SELECT 1 FROM reactions rx WHERE rx.post_id=p.id AND rx.user_id=$2)
		FROM posts p
		JOIN users u ON u.id=p.author_id
		LEFT JOIN reactions r ON r.post_id=p.id
		LEFT JOIN comments c ON c.post_id=p.id AND c.is_removed=FALSE
		WHERE p.id=$1 AND p.is_removed=FALSE
		GROUP BY p.id, u.id`, id, claims.UserID,
	).Scan(
		&post.ID, &post.PostType, &post.Content, &post.Title, &post.ParentID, &post.CreatedAt,
		&post.AuthorID, &post.Username, &post.DisplayName, &post.AvatarPath,
		&post.ReactionCount, &post.CommentCount, &post.UserReacted,
	)
	if err != nil {
		jsonError(w, "Post not found", http.StatusNotFound)
		return
	}
	jsonOK(w, post)
}

func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(auth.ClaimsKey).(*auth.Claims)
	id := r.PathValue("id")
	ctx := r.Context()

	var authorID string
	err := h.db.QueryRow(ctx, "SELECT author_id FROM posts WHERE id=$1 AND is_removed=FALSE", id).Scan(&authorID)
	if err != nil {
		jsonError(w, "Post not found", http.StatusNotFound)
		return
	}
	if authorID != claims.UserID && !claims.IsAdmin {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	reason := "Deleted by "
	if claims.IsAdmin {
		reason += "admin"
	} else {
		reason += "author"
	}
	h.db.Exec(ctx,
		`UPDATE posts SET is_removed=TRUE, removed_by=$1, removed_at=NOW(), removal_reason=$2 WHERE id=$3`,
		claims.UserID, reason, id,
	)
	jsonOK(w, map[string]string{"message": "Post removed"})
}

func (h *Handler) React(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(auth.ClaimsKey).(*auth.Claims)
	id := r.PathValue("id")
	ctx := r.Context()

	// Toggle reaction
	var existing string
	err := h.db.QueryRow(ctx,
		"SELECT id FROM reactions WHERE post_id=$1 AND user_id=$2", id, claims.UserID,
	).Scan(&existing)

	if err == nil {
		// Remove reaction
		h.db.Exec(ctx, "DELETE FROM reactions WHERE post_id=$1 AND user_id=$2", id, claims.UserID)
		jsonOK(w, map[string]bool{"reacted": false})
	} else {
		// Add reaction
		h.db.Exec(ctx, "INSERT INTO reactions (post_id, user_id) VALUES ($1, $2)", id, claims.UserID)
		jsonOK(w, map[string]bool{"reacted": true})
	}
}

func (h *Handler) GetComments(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rows, err := h.db.Query(r.Context(), `
		SELECT c.id, c.content, c.created_at, c.parent_comment_id,
			u.id, u.username, u.display_name, u.avatar_path
		FROM comments c
		JOIN users u ON u.id=c.author_id
		WHERE c.post_id=$1 AND c.is_removed=FALSE
		ORDER BY c.created_at ASC`, id,
	)
	if err != nil {
		jsonError(w, "Could not load comments", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type Comment struct {
		ID              string    `json:"id"`
		Content         string    `json:"content"`
		CreatedAt       time.Time `json:"created_at"`
		ParentCommentID *string   `json:"parent_comment_id"`
		AuthorID        string    `json:"author_id"`
		Username        string    `json:"username"`
		DisplayName     string    `json:"display_name"`
		AvatarPath      string    `json:"avatar_path"`
	}
	var comments []Comment
	for rows.Next() {
		var c Comment
		rows.Scan(&c.ID, &c.Content, &c.CreatedAt, &c.ParentCommentID,
			&c.AuthorID, &c.Username, &c.DisplayName, &c.AvatarPath)
		comments = append(comments, c)
	}
	if comments == nil {
		comments = []Comment{}
	}
	jsonOK(w, comments)
}

func (h *Handler) AddComment(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(auth.ClaimsKey).(*auth.Claims)
	postID := r.PathValue("id")
	var req struct {
		Content         string `json:"content"`
		ParentCommentID string `json:"parent_comment_id"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if len(req.Content) == 0 || len(req.Content) > 2000 {
		jsonError(w, "Comment must be 1-2000 characters", http.StatusBadRequest)
		return
	}
	var parentID *string
	if req.ParentCommentID != "" {
		parentID = &req.ParentCommentID
	}
	var commentID string
	err := h.db.QueryRow(r.Context(),
		`INSERT INTO comments (post_id, author_id, content, parent_comment_id)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		postID, claims.UserID, req.Content, parentID,
	).Scan(&commentID)
	if err != nil {
		jsonError(w, "Could not add comment", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"id": commentID})
}

func (h *Handler) DeleteComment(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(auth.ClaimsKey).(*auth.Claims)
	commentID := r.PathValue("commentID")
	var authorID string
	h.db.QueryRow(r.Context(), "SELECT author_id FROM comments WHERE id=$1", commentID).Scan(&authorID)
	if authorID != claims.UserID && !claims.IsAdmin {
		jsonError(w, "Forbidden", http.StatusForbidden)
		return
	}
	h.db.Exec(r.Context(), "UPDATE comments SET is_removed=TRUE WHERE id=$1", commentID)
	jsonOK(w, map[string]string{"message": "Comment removed"})
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
