package main

import (
	"log"
	"net/http"
	"os"
	"time"
 
	"TrustMail/internal/handlers"
	"TrustMail/internal/middleware"
	storage "TrustMail/internal/storage"
)

func main() {

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET environment variable is required")
	}

	store, err := storage.New("data/store.json")
	if err != nil {
		log.Fatalf("failed to initialize storage: %v" , err)
	}

	autHandler := &handlers.AuthHandler{
		Store: store,
		JWTSecret: jwtSecret,
		TokenTTL: 24 * time.Hour,
	}

	verifyHandler := &handlers.VerifyHandler{Store: store}

	bulkHandler := &handlers.BulkHandler{Store: store}

	analyticsHandler := &handlers.AnalyticsHandler{Store: store}

	adminHandler := &handlers.AdminHandler{Store: store}

	requireAuth := middleware.RequireAuth(store, jwtSecret)

	mux := http.NewServeMux()

	// public

	mux.HandleFunc("POST /api/auth/register" , autHandler.Register)
	mux.HandleFunc("POST /api/auth/login", autHandler.Login)
	
	mux.HandleFunc("GET /api/health" , func(w http.ResponseWriter , r *http.Request){
		w.Header().Set("Content-Type" , "application/json")
		w.Write([]byte(`{"status": "ok"}`))
	})

	// authenticated

	mux.Handle("GET /api/auth/me " , requireAuth(http.HandlerFunc(autHandler.Me)))
    mux.Handle("GET /api/verify " , requireAuth(http.HandlerFunc(verifyHandler.Verify)))
	mux.Handle("GET /api/history " , requireAuth(http.HandlerFunc(verifyHandler.History)))
	mux.Handle("GET /api/bulk-verify " , requireAuth(http.HandlerFunc(bulkHandler.BulkVerify)))
	mux.Handle("GET /api/analytics " , requireAuth(http.HandlerFunc(analyticsHandler.Summary)))

	// admin 

	mux.Handle("GET /api/admin/users", requireAuth(middleware.RequireAdmin(http.HandlerFunc(adminHandler.ListUsers))))
 
	handler := middleware.CORS(mux)
 
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
 
	log.Printf("Email Verifier Pro API listening on :%s\n", port)
	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatal(err)
	}
}

