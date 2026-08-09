package handlers

import (
	"TrustMail/internal/auth"
	"TrustMail/internal/middleware"
	"TrustMail/internal/models"
	"TrustMail/internal/util"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	storage "TrustMail/internal/storage"

)

type AuthHandler struct {
	Store     *storage.Store
	JWTSecret string
	TokenTTL  time.Duration
}

type registerRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type authResponse struct {
	Token string            `json:"token"`
	User  models.PublicUser `json:"user"`
}

var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9_]3, 20)$`)

const defaultDailyLimit = 200

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid  request body")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.TrimSpace(req.Email)

	if !usernameRe.MatchString(req.Username) {
		writeError(w, http.StatusBadRequest, "username must be 3-20 charachters: letters, numbers, underscores")
		return
	}

	if !strings.Contains(req.Email, "@") || len(req.Email) < 5 {
		writeError(w, http.StatusBadRequest, "please provide a valid email")
		return
	}
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "password must be atleast 8 characters")
		return
	}

	salt, err := auth.GenerateSalt()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not register user")
		return
	}

	user := &models.User{
		ID:           util.NewID(),
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: auth.HashPassword(req.Password, salt),
		PasswordSalt: salt,
		Role:         "user",
		CreatedAt:    time.Now().Format(time.RFC3339),
		DailyLimit:   strconv.Itoa(defaultDailyLimit),
	}

	if err := h.Store.CreateUser(user); err != nil {
		if err == storage.ErrUserExists {
			writeError(w, http.StatusConflict, "that username is already taken")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not register user")
		return

	}

	token, err := auth.GenerateToken(user.ID, user.Username, user.Role, h.JWTSecret, h.TokenTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue token")
		return
	}

	writeJSON(w, http.StatusCreated, authResponse{Token: token, User: user.Public()})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	user, err := h.Store.GetUserByUsername(strings.TrimSpace(req.Username))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	if !auth.VerifyPassword(req.Password, user.PasswordSalt, user.PasswordHash) {
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	token, err := auth.GenerateToken(user.ID, user.Username, user.Role, h.JWTSecret, h.TokenTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue token")
		return
	}

	writeJSON(w, http.StatusOK, authResponse{Token: token, User: user.Public()})
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r)
	if user == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	writeJSON(w, http.StatusOK, user.Public())

}


