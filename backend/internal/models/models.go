package models

import "time"

// user

type User struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	Email        string `json:"email"`
	PasswordHash string `json:"passwordHash"`
	PasswordSalt string `json:"passwordSalt"`
	Role         string `json:"role"`
	CreatedAt    string `json:"createdAt"`
	DailyLimit   string `json:"dailyLimit"`
	UsageCount   int    `json:"usageCount"`
	UsageDate    string `json:"usageDate"`
}

// publicUser

type PublicUser struct {
	ID         string `json:"id"`
	Username   string `json:"username"`
	Email      string `json:"email"`
	Role       string `json:"role"`
	DailyLimit string `json:"dailyLimit"`
	UsageCount int    `json:"usageCount"`
}

func (u *User) Public() PublicUser {
	return PublicUser{
		ID:         u.ID,
		Username:   u.Username,
		Email:      u.Email,
		Role:       u.Role,
		DailyLimit: u.DailyLimit,
		UsageCount: u.UsageCount,
	}
}

// verificationRecord

type VerificationRecord struct {
	ID          string    `json:"id"`
	UserID      string    `json:"userId"`
	Domain      string    `json:"domain"`
	HasMX       bool      `json:"hasMX"`
	HasSPF      bool      `json:"hasSPF"`
	SPFRecord   string    `json:"spfRecord"`
	HasDMARC    bool      `json:"hasDMARC"`
	DMARCRecord string    `json:"dmarcRecord"`
	Valid       bool      `json:"valid"`
	Error       string    `json:"error,omitempty"`
	CheckedAt   time.Time `json:"checkedAt"`
}

// bulkProgress

type BulkProgress struct {
	Processed int                 `json:"processed"`
	Total     int                 `json:"total"`
	Result    *VerificationRecord `json:"result,omitempty"`
	Done      bool                `json:"done"`
}
