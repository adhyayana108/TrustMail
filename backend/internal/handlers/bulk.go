package handlers

import (
	"TrustMail/internal/dnscheck"
	"TrustMail/internal/middleware"
	"TrustMail/internal/models"
	storage "TrustMail/internal/storage"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

type BulkHandler struct {
	Store *storage.Store
}

const (
	maxBulkDomains  = 500
	bulkConcurrency = 10
	maxUploadBytes  = 2 << 20
)

func (h *BulkHandler) BulkVerify(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r)
	if user == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	if err := r.ParseMultipartForm(maxUploadBytes); err != nil {
		writeError(w, http.StatusBadRequest, "could not parse upload (max 2MB)")
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, `missing "file" field in form upload`)
		return
	}
	defer file.Close()

	domains, err := extractDomains(file)
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not read CSV: "+err.Error())
		return
	}

	if len(domains) == 0 {
		writeError(w, http.StatusBadRequest, "no domain found in the uploaded file")
		return
	}

	if len(domains) > maxBulkDomains {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("too many domains (max %d per upload)", maxBulkDomains))
		return
	}

	ok, err := h.Store.TryConsumeUsage(user.ID, len(domains))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not check usage quota")
		return
	}
	if !ok {
		writeError(w, http.StatusTooManyRequests, "this upload would exceed your daily verification limit")
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	flusher, canFlush := w.(http.Flusher)

	var mu sync.Mutex
	var results []*models.VerificationRecord

	dnscheck.BulkCheck(r.Context(), domains, bulkConcurrency, func(processed, total int, rec *models.VerificationRecord) {
		rec.UserID = user.ID

		event := models.BulkProgress{Processed: processed, Total: total, Result: rec, Done: processed == total}
		line, _ := json.Marshal(event)

		mu.Lock()
		results = append(results, rec)
		w.Write(line)
		w.Write([]byte("\n"))
		if canFlush {
			flusher.Flush()
		}
		mu.Unlock()
	})

	if len(results) > 0 {
		_ = h.Store.AddVerifications(user.ID, results)
	}
}
func extractDomains(r io.Reader) ([]string, error) {
	reader := csv.NewReader(r)
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true

	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	domainCol := 0
	startRow := 0
	if len(records) > 0 {
		for i, cell := range records[0] {
			if strings.EqualFold(strings.TrimSpace(cell), "domain") {
				domainCol = i
				startRow = 1
				break
			}
		}
	}

	seen := make(map[string]bool)
	var domains []string
	for _, row := range records[startRow:] {
		if domainCol >= len(row) {
			continue
		}
		d := strings.ToLower(strings.TrimSpace(row[domainCol]))
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		domains = append(domains, d)
	}
	return domains, nil
}
