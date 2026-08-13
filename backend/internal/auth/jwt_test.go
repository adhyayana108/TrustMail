package auth

import (
	"testing"
	"time"
)

func TestGenerateAndParseTokenRoundTrip(t *testing.T) {
	token, err := GenerateToken("user-123", "alice", "user", "test-secret", time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}
claims, err := ParseToken(token, "test-secret")
	if err != nil {
		t.Fatalf("ParseToken failed on a freshly generated token: %v", err)
	}
	if claims.UserID != "user-123" || claims.Username != "alice" || claims.Role != "user" {
		t.Fatalf("claims did not round-trip correctly: %+v", claims)
	}
}

func TestParseTokenRejectsWrongSecret(t *testing.T) {
	token, _ := GenerateToken("user-123", "alice", "user", "correct-secret", time.Hour)
 
	if _, err := ParseToken(token, "wrong-secret"); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for a token signed with a different secret, got %v", err)
	}
}

func TestParseTokenRejectsExpiredToken(t *testing.T) {
	token, _ := GenerateToken("user-123", "alice", "user", "test-secret", -time.Minute)
 
	if _, err := ParseToken(token, "test-secret"); err != ErrExpiredToken {
		t.Fatalf("expected ErrExpiredToken for an already-expired token, got %v", err)
	}
}

func TestParseTokenRejectsMalformedToken(t *testing.T) {
	if _,err := ParseToken("not-a-real-token" , "test-secret") ; err!= ErrInvalidToken {
		t.Fatalf("expected ErrInvalidaToken for a malformed token, got %v", err)
	}
}

