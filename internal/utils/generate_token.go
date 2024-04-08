package utils

import (
	"crypto/rand"
	"encoding/hex"
)

// GenerateVerificationToken generates a secure, random token for email verification.
func GenerateVerificationToken() (string, error) {
	tokenBytes := make([]byte, 16) // Generates a 128-bit token
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(tokenBytes), nil
}
