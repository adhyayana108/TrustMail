package storage

import (
	"path/filepath"
	"testing"
	"time"

	"TrustMail/internal/models"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "store.json")
	s, err := New(path)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	return s
}

func TestCreateAndGetUser(t *testing.T) {
	s := newTestStore(t)
	u := &models.User{ID: "u1", Username: "alice", Email: "alice@example.com", DailyLimit: "100"}
	if err := s.CreateUser(u); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	byName, err := s.GetUserByUsername("alice")
		if err != nil {

			t.Fatalf("GetUserByUsername failed: %v", err)

		}
	if byName.ID != "u1"	{
		t.Fatalf("expected user id u1, got %s", byName.ID)
	}

	byID, err := s.GetUserByID("u1")
	if err != nil {
		t.Fatalf("GetUserByID failed: %v", err)
	}
	if byID.Username != "alice" {
		t.Fatalf("expected username alice, got %s", byID.Username)
	}
}

func TestCreateUserRejectsDuplicateUsername(t *testing.T) {
	s := newTestStore(t)
	_ = s.CreateUser(&models.User{ID: "u1", Username: "bob", DailyLimit: "100"})
 
	err := s.CreateUser(&models.User{ID: "u2", Username: "bob", DailyLimit: "100"})
	if err != ErrUserExists {
		t.Fatalf("expected ErrUserExists, got %v", err)
	}
}

func TestTryConsumeUsageEnforcesDailyLimit(t *testing.T) {
	s := newTestStore(t)
	_ = s.CreateUser(&models.User{ID: "u1", Username: "carol", DailyLimit: "5"})
 
	ok, err := s.TryConsumeUsage("u1", 3)
	if err != nil || !ok {
		t.Fatalf("expected first consume of 3 to succeed, got ok=%v err=%v", ok, err)
	}
 
	ok, err = s.TryConsumeUsage("u1", 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected second consume of 3 (total 6 > limit 5) to be rejected")
	}

	u, _ := s.GetUserByID("u1")
	if u.UsageCount != 3 {
		t.Fatalf("expected usage count to remain 3 after rejected consume, got %d", u.UsageCount)
	}
}

func TestAddAndGetVerificationHistory(t *testing.T) {
	s := newTestStore(t)
	_ = s.CreateUser(&models.User{ID: "u1", Username: "dave", DailyLimit: "100"})
 
	rec := &models.VerificationRecord{ID: "r1", UserID: "u1", Domain: "example.com", CheckedAt: time.Now()}
	if err := s.AddVerification(rec); err != nil {
		t.Fatalf("AddVerification failed: %v", err)
	}

	history := s.GetHistory("u1")
	if len(history) != 1 || history[0].Domain != "example.com" {
		t.Fatalf("unexpected history: %+v", history)
	}
}

func TestStorePersistsAcrossReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
 
	s1, err := New(path)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	_ = s1.CreateUser(&models.User{ID: "u1", Username: "erin", DailyLimit: "100"})
 
	s2, err := New(path)
	if err != nil {
		t.Fatalf("reloading store failed: %v", err)
	}
	u, err := s2.GetUserByUsername("erin")
	if err != nil {
		t.Fatalf("expected user to persist across reload: %v", err)
	}
	if u.ID != "u1" {
		t.Fatalf("expected persisted user id u1, got %s", u.ID)

}



}


