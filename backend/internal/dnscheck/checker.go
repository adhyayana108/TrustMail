package dnscheck

import (
	"TrustMail/internal/models"
	"TrustMail/internal/util"
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

const lookupTimeout = 5 * time.Second

func Check(ctx context.Context, domain string) *models.VerificationRecord {
	rec := &models.VerificationRecord{
		ID:        util.NewID(),
		Domain:    domain,
		CheckedAt: time.Now(),
	}

	resolver := net.DefaultResolver

	mxCtx, cancelMX := context.WithTimeout(ctx, lookupTimeout)
	mxRecords, err := resolver.LookupMX(mxCtx, domain)
	cancelMX()
	if err != nil {
		rec.Error = err.Error()
	}

	if len(mxRecords) > 0 {
		rec.HasMX = true
	}

	txtCtx, cancelTXT := context.WithTimeout(ctx, lookupTimeout)
	txtRecords, err := resolver.LookupTXT(txtCtx, domain)
	cancelTXT()
	if err == nil {
		for _, r := range txtRecords {
			if strings.HasPrefix(r, "v=spf1") {
				rec.HasSPF = true
				rec.SPFRecord = r
				break
			}
		}
	}

	dmarcCtx, cancelDMARC := context.WithTimeout(ctx, lookupTimeout)
	dmarcRecords, err := resolver.LookupTXT(dmarcCtx, "_dmarc."+domain)
	cancelDMARC()

	if err == nil {
		for _, r := range dmarcRecords {
			if strings.HasPrefix(r, "v=DMARC1") {
				rec.HasDMARC = true
				rec.DMARCRecord = r
				break
			}
		}
	}

	rec.Valid = rec.HasMX && rec.HasSPF && rec.HasDMARC
	return rec
}

// bulkcheck

func BulkCheck(ctx context.Context, domains []string, concurrency int, onProgress func(processed, total int, rec *models.VerificationRecord)) []*models.VerificationRecord {
	total := len(domains)
	results := make([]*models.VerificationRecord, total)

	type job struct {
		idx    int
		domain string
	}

	if concurrency < 1 {
		concurrency = 1
	}

	jobs := make(chan job)
	var wg sync.WaitGroup
	var mu sync.Mutex
	processed := 0

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				rec := Check(ctx, j.domain)
				results[j.idx] = rec

				mu.Lock()
				processed++
				p := processed
				mu.Unlock()

				if onProgress != nil {
					onProgress(p, total, rec)
				}
			}
		}()
	}

	go func() {
		for i, d := range domains {
			jobs <- job{idx: i, domain: strings.TrimSpace(d)}
		}
		close(jobs)
	}()

	wg.Wait()
	return results
}
