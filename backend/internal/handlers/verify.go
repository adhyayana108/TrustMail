package handlers

import (
	"TrustMail/internal/dnscheck"
	"TrustMail/internal/middleware"
	"TrustMail/internal/models"
	storage "TrustMail/internal/storage"
	"net/http"
	"strings"
)

type VerifyHandler struct {
	Store *storage.Store
}

func (h *VerifyHandler) Verify(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r)

	if user == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	domain := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("domain")))

	if domain == "" {
		writeError(w, http.StatusBadRequest, "domain query parameter is required")
		return
	}

	ok, err := h.Store.TryConsumeUsage(user.ID, 1)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not check usage quota")
		return
	}

	if !ok {
		writeError(w, http.StatusTooManyRequests, "daily verification limit reached, try again tomorrow")
		return
	}

	rec := dnscheck.Check(r.Context(), domain)
	rec.UserID = user.ID

	if err := h.Store.AddVerification(rec); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save result")
		return
	}

	writeJSON(w, http.StatusOK, rec)
}

func (h *VerifyHandler) History(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r)
	if user == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	history := h.Store.GetHistory(user.ID)

	reversed := make([]*models.VerificationRecord, len(history))
	for i, rec := range history {
		reversed[len(history)-1-i] = rec
	}
	writeJSON(w, http.StatusOK, reversed)
}
