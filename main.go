package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/Tikkaaa3/chirpy/internal/auth"
	"github.com/Tikkaaa3/chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	platform       string
	secret         string
}

type User struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
}

func (cfg *apiConfig) userCreateHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Password string `"json:password"`
		Email    string `json:"email"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		w.WriteHeader(500)
		return
	}
	hash, err := auth.HashPassword(params.Password)
	if err != nil {
		log.Printf("Error hashing password: %s", err)
		w.WriteHeader(500)
		return
	}

	user, err := cfg.dbQueries.CreateUser(r.Context(), database.CreateUserParams{
		Email:          params.Email,
		HashedPassword: hash})

	if err != nil {
		log.Printf("Error creating user: %s", err)
		w.WriteHeader(500)
		return
	}
	response := User{
		ID:        user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email:     user.Email,
	}

	dat, err := json.Marshal(response)
	if err != nil {
		log.Printf("Error marshalling JSON: %s", err)
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	w.Write(dat)

}

func (cfg *apiConfig) userLoginHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		w.WriteHeader(500)
		return
	}

	if params.Password == "" {
		w.WriteHeader(401)
		return
	}

	user, err := cfg.dbQueries.GetUser(r.Context(), params.Email)
	if err != nil {
		log.Printf("%s", err)
		w.WriteHeader(401)
		return
	}

	match, err := auth.CheckPasswordHash(params.Password, user.HashedPassword)
	if err != nil {
		log.Printf("Error checking password: %s", err)
		w.WriteHeader(401)
		return
	}
	if match {
		accessToken, err := auth.MakeJWT(user.ID, cfg.secret, time.Hour)
		if err != nil {
			log.Printf("Error getting token: %s", err)
			return
		}

		refreshToken, _ := auth.MakeRefreshToken()
		refreshParams := database.CreateRefreshTokenParams{
			Token: refreshToken,
			UserID: uuid.NullUUID{
				UUID:  user.ID,
				Valid: true,
			}, ExpiresAt: time.Now().Add(60 * 24 * time.Hour)}

		_, _ = cfg.dbQueries.CreateRefreshToken(r.Context(), refreshParams)

		dat, err := json.Marshal(User{
			ID:           user.ID,
			CreatedAt:    user.CreatedAt,
			UpdatedAt:    user.UpdatedAt,
			Email:        user.Email,
			Token:        accessToken,
			RefreshToken: refreshToken,
		})
		if err != nil {
			fmt.Println(err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(dat)
	} else {
		w.WriteHeader(401)
	}
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) countHandler(w http.ResponseWriter, r *http.Request) {
	s := fmt.Sprintf(`<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, cfg.fileserverHits.Load())
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(s))
}

func (cfg *apiConfig) getChirpHandler(w http.ResponseWriter, r *http.Request) {
	type resBody struct {
		ID        uuid.UUID     `json:"id"`
		CreatedAt time.Time     `json:"created_at"`
		UpdatedAt time.Time     `json:"updated_at"`
		Body      string        `json:"body"`
		UserID    uuid.NullUUID `json:"user_id"`
	}
	id := r.PathValue("chirpID")
	if id == "" {
		w.WriteHeader(404)
		return

	}
	parsedID, err := uuid.Parse(id)
	if err != nil {
		fmt.Println(err)
	}
	chirp, err := cfg.dbQueries.GetChirp(r.Context(), parsedID)
	if err != nil {
		w.WriteHeader(404)
		return
	}
	dat, err := json.Marshal(resBody{
		ID:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserID:    chirp.UserID,
	})
	if err != nil {
		fmt.Println(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(dat)
}

func (cfg *apiConfig) getChirpsHandler(w http.ResponseWriter, r *http.Request) {
	type resBody struct {
		ID        uuid.UUID     `json:"id"`
		CreatedAt time.Time     `json:"created_at"`
		UpdatedAt time.Time     `json:"updated_at"`
		Body      string        `json:"body"`
		UserID    uuid.NullUUID `json:"user_id"`
	}
	chirps, err := cfg.dbQueries.GetChirps(r.Context())
	if err != nil {
		fmt.Println(err)
	}

	var res []resBody
	for _, v := range chirps {
		res = append(res, resBody{
			ID:        v.ID,
			CreatedAt: v.CreatedAt,
			UpdatedAt: v.UpdatedAt,
			Body:      v.Body,
			UserID:    v.UserID,
		})
	}

	dat, err := json.Marshal(res)
	if err != nil {
		fmt.Println(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(dat)
}

func (cfg *apiConfig) refreshHandler(w http.ResponseWriter, r *http.Request) {
	token, _ := auth.GetBearerToken(r.Header)
	user, err := cfg.dbQueries.GetUserFromRefreshToken(r.Context(), token)
	jwt, _ := auth.MakeJWT(user.ID, cfg.secret, time.Hour)
	if err != nil {
		w.WriteHeader(401)
		return
	}
	type resBody struct {
		Token string `json:"token"`
	}
	res := resBody{
		Token: jwt,
	}
	dat, err := json.Marshal(res)
	if err != nil {
		fmt.Println(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(dat)

}

func (cfg *apiConfig) revokeHandler(w http.ResponseWriter, r *http.Request) {
	token, _ := auth.GetBearerToken(r.Header)
	_, err := cfg.dbQueries.RevokeRefreshToken(r.Context(), token)
	if err != nil {
		w.WriteHeader(401)
	}

	w.WriteHeader(204)

}

func (cfg *apiConfig) chirpsHandler(w http.ResponseWriter, r *http.Request) {
	type bodyParams struct {
		Body   string        `json:"body"`
		UserID uuid.NullUUID `json:"user_id"`
	}

	decoder := json.NewDecoder(r.Body)
	params := bodyParams{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		w.WriteHeader(500)
		return
	}

	if len(params.Body) > 140 {
		type returnVals struct {
			Err string `json:"error"`
		}
		respBody := returnVals{
			Err: "Chirp is too long",
		}
		dat, err := json.Marshal(respBody)
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		w.Write(dat)

	} else {
		type returnVals struct {
			ID        uuid.UUID     `json:"id"`
			CreatedAt time.Time     `json:"created_at"`
			UpdatedAt time.Time     `json:"updated_at"`
			Body      string        `json:"body"`
			UserID    uuid.NullUUID `json:"user_id"`
		}

		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			log.Printf("%s", err)
			w.WriteHeader(500)
			return
		}
		id, err := auth.ValidateJWT(token, cfg.secret)
		dbUserID := uuid.NullUUID{UUID: id, Valid: true}
		if err != nil {
			log.Printf("Unauthorized: %s", err)
			w.WriteHeader(401)
			return
		}

		chirp, err := cfg.dbQueries.Chirp(r.Context(), database.ChirpParams{
			Body:   params.Body,
			UserID: dbUserID,
		})

		respBody := returnVals{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID,
		}
		dat, err := json.Marshal(respBody)
		if err != nil {
			log.Printf("Error marshalling JSON: %s", err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write(dat)

	}

}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits.Store(0)
	if cfg.platform == "dev" {
		cfg.dbQueries.ResetUsers(r.Context())
		cfg.dbQueries.ResetChirps(r.Context())
		w.Write([]byte("OK"))
	} else {
		w.WriteHeader(403)
		w.Write([]byte("Forbidden"))
	}
}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")
	secret := os.Getenv("SECRET")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Println(err)
	}
	dbQueries := database.New(db)
	const port = "8080"

	mux := http.NewServeMux()
	apiCfg := &apiConfig{
		fileserverHits: atomic.Int32{},
		dbQueries:      dbQueries,
		platform:       platform,
		secret:         secret,
	}

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	// Readiness endpoint
	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Fileserver moved to /app/
	fs := http.StripPrefix("/app", http.FileServer(http.Dir(".")))
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(fs))

	// Metrics + reset
	mux.HandleFunc("GET /admin/metrics", apiCfg.countHandler)
	mux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)

	// Create user
	mux.HandleFunc("POST /api/users", apiCfg.userCreateHandler)
	// Get user
	mux.HandleFunc("POST /api/login", apiCfg.userLoginHandler)

	// Chirp
	mux.HandleFunc("POST /api/chirps", apiCfg.chirpsHandler)
	mux.HandleFunc("GET /api/chirps", apiCfg.getChirpsHandler)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirpHandler)

	// Tokens
	mux.HandleFunc("POST /api/refresh", apiCfg.refreshHandler)
	mux.HandleFunc("POST /api/revoke", apiCfg.revokeHandler)

	log.Printf("Serving on port: %s\n", port)
	log.Fatal(srv.ListenAndServe())
}
