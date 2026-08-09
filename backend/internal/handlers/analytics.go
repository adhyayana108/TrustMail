package handlers

import (
	"TrustMail/internal/middleware"
	storage "TrustMail/internal/storage"
	"net/http"
)

type AnalyticsHandler struct {
	Store *storage.Store
}

type analyticsResponse struct {
	TotalChecked  int      `json:"totalChecked"`
	Valid         int      `json:"valid"`
	Invalid       int      `json:"invalid"`
	HasMXCount    int      `json:"hasMXCount"`
	HasSPFCount   int      `json:"hasSPFCount"`
	HasDMARCCount int      `json:"hasDMARCCount"`
	RecentDomains []string `json:"recentDomains"`
}

func (h *AnalyticsHandler) Summary(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r)
	if user == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	history := h.Store.GetHistory(user.ID)
	resp:= analyticsResponse{TotalChecked: len(history)} 
	for _, rec := range history {
		if rec.Valid {
			resp.Valid++
		} else {
			resp.Invalid++
		}
		if rec.HasMX {
			resp.HasMXCount++
		}
		if rec.HasSPF {
			resp.HasSPFCount++
		}
		if rec.HasDMARC {
			resp.HasDMARCCount++
		}
	}

	const recentLimit = 10 
	start := len(history) - recentLimit
	if start < 0 {
		start = 0
	}
	for _, rec := range history[start:] {
		resp.RecentDomains = append(resp.RecentDomains, rec.Domain)
	}

	writeJSON(w , http.StatusOK, resp)
}
