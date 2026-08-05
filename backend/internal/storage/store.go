package store

import (
	"TrustMail/internal/models"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

var (
	ErrUserExists   = errors.New("username already exists")
	ErrUserNotFound = errors.New("user not found")
)

type diskData struct {
	Users       map[string]*models.User                 `json:"users"`
	UsersByName map[string]string                       `json:"usersByName"`
	History     map[string][]*models.VerificationRecord `json:"history"`
}

type Store struct {
	mu   sync.RWMutex
	path string
	d    *diskData
}

func New(path string) (*Store, error) {
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}

	s := &Store{
		path: path,
		d: &diskData{
			Users:       make(map[string]*models.User),
			UsersByName: make(map[string]string),
			History:     make(map[string][]*models.VerificationRecord),
		},
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // fresh installation
		}
		return err
	}
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, s.d)
}

// saveLocked

func (s *Store) saveLocked() error {
	raw, err := json.MarshalIndent(s.d, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// CreateUser

func (s *Store) CreateUser(u *models.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.d.UsersByName[u.Username]; exists {
		return ErrUserExists
	}
	s.d.Users[u.ID] = u
	s.d.UsersByName[u.Username] = u.ID
	return s.saveLocked()
}

// GetUsersByUsername

func (s *Store) GetUserByUsername(username string) (*models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.d.UsersByName[username]
	if !ok {
		return nil, ErrUserNotFound
	}
	u, ok := s.d.Users[id]
	if !ok {
		return nil, ErrUserNotFound
	}
	cp := *u
	return &cp, nil
}

// GetUserByID

func (s *Store) GetUserByID(id string) (*models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.d.Users[id]
	if !ok {
		return nil, ErrUserNotFound
	}

	cp := *u
	return &cp, nil

}

// AllUsers

func (s *Store) AllUsers() []*models.User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*models.User, 0, len(s.d.Users))
	for _, u := range s.d.Users {
		cp := *u
		out = append(out, &cp)
	}
	return out
}

func (s *Store) TryConsumeUsage(userID string, cost int) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.d.Users[userID]
	if !ok {
		return false, ErrUserNotFound
	}

	today := time.Now().UTC().Format("2006-01-02")
	if u.UsageDate != today {
		u.UsageDate = today
		u.UsageCount = 0
	}

	dailyLimit, err := strconv.Atoi(u.DailyLimit)
	if err != nil {
		return false, err
	}

	if u.UsageCount+cost > dailyLimit {
		return false, nil
	}
	u.UsageCount += cost
	return true, s.saveLocked()

}

// AddVerification

func (s *Store) AddVerification(rec *models.VerificationRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d.History[rec.UserID] = append(s.d.History[rec.UserID], rec)
	return s.saveLocked()
}

// AddVerifications

func (s *Store) AddVerifications(userID string, recs []*models.VerificationRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d.History[userID] = append(s.d.History[userID], recs...)
	return s.saveLocked()
}

// GetHistory

func (s *Store) GetHistory(userID string) []*models.VerificationRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*models.VerificationRecord, len(s.d.History[userID]))
	copy(out, s.d.History[userID])
	return out
}
