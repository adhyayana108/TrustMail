package handlers

import (
	"net/http"
	
	storage "TrustMail/internal/storage"
)

type AdminHandler struct {
	Store *storage.Store
}

type adminUserView struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	Role        string `json:"role"`
	UsageCount  int    `json:"usageCount"`
	DailyLimit  int    `json:"dailyLimit"`
	TotalChecks int    `json:"totalChecks"`
}

func (h *AdminHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	users := h.Store.AllUsers()
	out := make([]adminUserView, 0, len(users))
	for _, u := range users {
		out = append(out, adminUserView{
			ID:          u.ID,
			Username:    u.Username,
			Email:       u.Email,
			Role:        u.Role,
			UsageCount:  u.UsageCount,
			DailyLimit:  defaultDailyLimit,
			TotalChecks: len(h.Store.GetHistory(u.ID)),
		})
	}
	writeJSON(w, http.StatusOK, out)
}
