package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestGeneratePKCEChallenge(t *testing.T) {
	challenge, err := GeneratePKCEChallenge()
	if err != nil {
		t.Fatalf("GeneratePKCEChallenge() error = %v", err)
	}

	// Test verifier properties
	if len(challenge.Verifier) < 43 || len(challenge.Verifier) > 128 {
		t.Errorf("Verifier length = %d, want between 43-128", len(challenge.Verifier))
	}

	// Test verifier contains only allowed characters (RFC 7636)
	for _, char := range challenge.Verifier {
		if !((char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '.' ||
			char == '_' || char == '~') {
			t.Errorf("Verifier contains invalid character: %c", char)
		}
	}

	// Test challenge is base64url encoded SHA256 hash of verifier
	expectedHash := sha256.Sum256([]byte(challenge.Verifier))
	expectedChallenge := base64.RawURLEncoding.EncodeToString(expectedHash[:])

	if challenge.Challenge != expectedChallenge {
		t.Errorf("Challenge = %s, want %s", challenge.Challenge, expectedChallenge)
	}

	// Test method is S256
	if challenge.Method != "S256" {
		t.Errorf("Method = %s, want S256", challenge.Method)
	}
}

func TestGeneratePKCEChallenge_Uniqueness(t *testing.T) {
	// Generate multiple challenges and ensure they're unique
	challenges := make(map[string]bool)

	for i := 0; i < 100; i++ {
		challenge, err := GeneratePKCEChallenge()
		if err != nil {
			t.Fatalf("GeneratePKCEChallenge() error = %v", err)
		}

		if challenges[challenge.Verifier] {
			t.Errorf("Duplicate verifier generated: %s", challenge.Verifier)
		}
		challenges[challenge.Verifier] = true
	}
}

func TestGeneratePKCEChallenge_RFC7636Compliance(t *testing.T) {
	challenge, err := GeneratePKCEChallenge()
	if err != nil {
		t.Fatalf("GeneratePKCEChallenge() error = %v", err)
	}

	// RFC 7636: code_verifier = 43*128unreserved
	// unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
	if len(challenge.Verifier) < 43 {
		t.Errorf("Verifier too short: %d characters, minimum 43 required", len(challenge.Verifier))
	}

	if len(challenge.Verifier) > 128 {
		t.Errorf("Verifier too long: %d characters, maximum 128 allowed", len(challenge.Verifier))
	}

	// Test challenge format
	if !strings.Contains("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", string(challenge.Challenge[0])) {
		// Challenge should be base64url encoded, so first character should be valid
		// This is a basic sanity check
	}

	// Test no padding in base64url encoding
	if strings.Contains(challenge.Challenge, "=") {
		t.Errorf("Challenge contains padding, should use base64url encoding without padding")
	}
}

func TestPKCEChallenge_VerifierChallengeRelation(t *testing.T) {
	// Test multiple times to ensure consistency
	for i := 0; i < 10; i++ {
		challenge, err := GeneratePKCEChallenge()
		if err != nil {
			t.Fatalf("GeneratePKCEChallenge() error = %v", err)
		}

		// Manually compute challenge from verifier
		hash := sha256.Sum256([]byte(challenge.Verifier))
		expectedChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

		if challenge.Challenge != expectedChallenge {
			t.Errorf("Challenge verification failed")
			t.Errorf("  Verifier: %s", challenge.Verifier)
			t.Errorf("  Got Challenge: %s", challenge.Challenge)
			t.Errorf("  Expected Challenge: %s", expectedChallenge)
		}
	}
}

// Benchmark PKCE generation performance
func BenchmarkGeneratePKCEChallenge(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GeneratePKCEChallenge()
		if err != nil {
			b.Fatalf("GeneratePKCEChallenge() error = %v", err)
		}
	}
}
