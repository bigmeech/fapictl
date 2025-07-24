package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

type PKCEChallenge struct {
	Verifier  string
	Challenge string
	Method    string
}

func GeneratePKCEChallenge() (*PKCEChallenge, error) {
	// Generate code verifier (43-128 characters)
	verifier, err := generateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("failed to generate code verifier: %w", err)
	}

	// Generate code challenge using S256 method
	challenge := generateCodeChallenge(verifier)

	return &PKCEChallenge{
		Verifier:  verifier,
		Challenge: challenge,
		Method:    "S256",
	}, nil
}

func generateCodeVerifier() (string, error) {
	// Generate 32 random bytes (256 bits)
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	// Base64 URL encode without padding
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func VerifyPKCEChallenge(verifier, challenge string) bool {
	expectedChallenge := generateCodeChallenge(verifier)
	return expectedChallenge == challenge
}
