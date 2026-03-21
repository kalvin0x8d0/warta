package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/cors"

	"github.com/kalvin/warta/internal/auth"
	"github.com/kalvin/warta/internal/media"
	"github.com/kalvin/warta/internal/messaging"
	"github.com/kalvin/warta/internal/moderation"
	"github.com/kalvin/warta/internal/posts"
	"github.com/kalvin/warta/internal/users"
)

func main() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL not set")
	}
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET not set")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("Cannot connect to database: %v", err)
	}
	defer pool.Close()

	// Wait for DB
	for i := 0; i < 10; i++ {
		if err := pool.Ping(ctx); err == nil {
			break
		}
		log.Println("Waiting for database...")
		time.Sleep(2 * time.Second)
	}
	log.Println("Database connected")

	mux := http.NewServeMux()

	// Register all route groups
	auth.RegisterRoutes(mux, pool, jwtSecret)
	users.RegisterRoutes(mux, pool, jwtSecret)
	posts.RegisterRoutes(mux, pool, jwtSecret)
	media.RegisterRoutes(mux, pool, jwtSecret)
	messaging.RegisterRoutes(mux, pool, jwtSecret)
	moderation.RegisterRoutes(mux, pool, jwtSecret)

	// CORS — only our own frontend
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{os.Getenv("APP_BASE_URL")},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	})

	srv := &http.Server{
		Addr:         ":8080",
		Handler:      c.Handler(mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 300 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Println("Warta backend listening on :8080")
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
