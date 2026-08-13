package auth

import "testing"

func TestHashPasswordIsDeterministicForSameSalt(t *testing.T) {
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}
 
	h1 := HashPassword("correct horse battery staple", salt)
	h2 := HashPassword("correct horse battery staple", salt)
	if h1 != h2 {
		t.Fatalf("expected identical hashes for identical password+salt, got %q and %q", h1, h2)
	}
}

func TestVerifyPasswordAcceptsCorrectPassword(t *testing.T) {
	salt, _ := GenerateSalt()
	hash := HashPassword("hunter2-but-eight-chars", salt)
 
	if !VerifyPassword("hunter2-but-eight-chars", salt, hash) {
		t.Fatal("expected VerifyPassword to accept the correct password")
	}
}

func TestVerifyPasswordRejectsWrongPassword(t *testing.T) {
	salt, _ := GenerateSalt()
	hash := HashPassword("the-real-password", salt)
 
	if VerifyPassword("not-the-real-password", salt, hash) {
		t.Fatal("expected VerifyPassword to reject an incorrect password")
	}
}

func TestDifferentSaltsProduceDifferentHashes(t *testing.T) {
	saltA, _ := GenerateSalt()
	saltB, _ := GenerateSalt()
	if saltA == saltB {
		t.Fatal("GenerateSalt produced two identical salts back to back — check crypto/rand wiring")
	}
 
	hashA := HashPassword("same-password-123", saltA)
	hashB := HashPassword("same-password-123", saltB)
	if hashA == hashB {
		t.Fatal("expected different salts to produce different hashes for the same password")
	}
}
