package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

const (
	pbkdf2Iterations = 100_000
	saltLength       = 16
	keyLength        = 32
)

func GenerateSalt() (string, error) {
	b := make([]byte, saltLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func pbkdf2(password, salt []byte, iteration, keyLen int) []byte {
	hashLen := sha256.Size
	numBlocks := (keyLen + hashLen - 1) / hashLen
	derived := make([]byte, 0, numBlocks*hashLen)

	for blockIndex := 1; blockIndex <= numBlocks; blockIndex++ {
		block := []byte{
			byte(blockIndex >> 24),
			byte(blockIndex >> 16),
			byte(blockIndex >> 8),
			byte(blockIndex),
		}

		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		mac.Write(block)
		u := mac.Sum(nil)

		result := make([]byte, len(u))
		copy(result, u)

		for i := 1; i < iteration; i++ {
			mac.Reset()
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range result {
				result[j] ^= u[j]
			}
		}
		derived = append(derived, result...)

	}

	return derived[:keyLen]

}

func HashPassword(password, salt string) string {
	derived := pbkdf2([]byte(password), []byte(salt), pbkdf2Iterations, keyLength)
	return hex.EncodeToString(derived)
}

func VerifyPassword(password, salt, expectedHash string) bool {
	computed := HashPassword(password, salt)
	return subtle.ConstantTimeCompare([]byte(computed), []byte(expectedHash)) == 1
}
