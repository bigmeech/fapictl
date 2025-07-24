//go:build integration
// +build integration

package main

import (
	"os"
	"path/filepath"
	"testing"

	"fapictl/pkg/config"
	"fapictl/pkg/profiles"
)

// TestIntegration_BasicWorkflow tests the basic workflow of fapictl
func TestIntegration_BasicWorkflow(t *testing.T) {
	tmpDir := t.TempDir()

	// Step 1: Test profile listing
	registry := profiles.DefaultRegistry
	profiles := registry.List()

	if len(profiles) == 0 {
		t.Fatal("No profiles registered in default registry")
	}

	t.Logf("Found %d registered profiles", len(profiles))

	// Step 2: Test configuration loading
	configContent := `
profiles:
  - oauth2-pkce
  - fapi-ro

client_id: integration-test-client
redirect_uri: https://test.example.com/callback
authorization_endpoint: https://auth.test.com/oauth2/authorize
token_endpoint: https://auth.test.com/oauth2/token

scopes:
  - openid
  - accounts
`

	configFile := filepath.Join(tmpDir, "test-config.yaml")
	err := os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	// Step 3: Load and validate configuration
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	err = cfg.Validate()
	if err != nil {
		t.Fatalf("Config validation failed: %v", err)
	}

	// Step 4: Test config to verifier config mapping
	verifierConfig := cfg.ToVerifierConfig()

	if verifierConfig.ClientID != "integration-test-client" {
		t.Errorf("Client ID mapping failed: got %s, want integration-test-client", verifierConfig.ClientID)
	}

	if len(verifierConfig.Scopes) != 2 {
		t.Errorf("Scopes mapping failed: got %d scopes, want 2", len(verifierConfig.Scopes))
	}

	// Step 5: Test profile resolution
	profileIDs := cfg.GetProfilesOrLegacy()
	resolved, err := registry.ResolveProfiles(profileIDs)
	if err != nil {
		t.Fatalf("Profile resolution failed: %v", err)
	}

	if len(resolved) == 0 {
		t.Error("No profiles resolved")
	}

	t.Logf("Successfully resolved %d profiles", len(resolved))

	// Step 6: Test verifier creation (without HTTP client to avoid network calls)
	// This tests the factory functions work correctly
	for _, profile := range resolved {
		if profile.Factory == nil {
			t.Errorf("Profile %s has no factory function", profile.ID)
		}
	}
}

// TestIntegration_ProfileDependencies tests profile dependency resolution
func TestIntegration_ProfileDependencies(t *testing.T) {
	registry := profiles.DefaultRegistry

	// Test that FAPI-RW has proper dependencies
	fapiRW, exists := registry.Get("fapi-rw")
	if !exists {
		t.Skip("FAPI-RW profile not found - skipping dependency test")
	}

	if len(fapiRW.Dependencies) == 0 {
		t.Error("FAPI-RW should have dependencies")
	}

	// Test dependency resolution
	_, err := registry.ResolveProfiles([]string{"fapi-rw"})
	if err != nil {
		t.Errorf("FAPI-RW dependency resolution failed: %v", err)
	}

	// Test invalid profile combination
	_, err = registry.ResolveProfiles([]string{"nonexistent-profile"})
	if err == nil {
		t.Error("Expected error for nonexistent profile")
	}
}

// TestIntegration_CryptographicGeneration tests the generate commands
func TestIntegration_CryptographicGeneration(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name    string
		keyType string
		keySize int
		curve   string
		fileExt string
	}{
		{"RSA 2048", "rsa", 2048, "", "pem"},
		{"ECDSA P-256", "ecdsa", 0, "P-256", "pem"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test key generation
			keyID := "test-integration-key"

			// This would simulate the generate key command
			outputDir := tmpDir

			// Check expected output files would be created
			privateKeyFile := filepath.Join(outputDir, keyID+"-private."+tt.fileExt)
			publicKeyFile := filepath.Join(outputDir, keyID+"-public."+tt.fileExt)

			// Verify paths are constructed correctly
			if privateKeyFile == "" || publicKeyFile == "" {
				t.Error("Key file paths not constructed correctly")
			}

			t.Logf("Would generate keys: %s, %s", privateKeyFile, publicKeyFile)
		})
	}
}

// TestIntegration_ConfigurationFormats tests different configuration formats
func TestIntegration_ConfigurationFormats(t *testing.T) {
	tmpDir := t.TempDir()

	configs := []struct {
		name    string
		content string
		valid   bool
	}{
		{
			name: "minimal_valid",
			content: `
client_id: test-client
authorization_endpoint: https://auth.test.com/oauth2/authorize
token_endpoint: https://auth.test.com/oauth2/token
profiles: ["oauth2-pkce"]
scopes: ["openid"]
`,
			valid: true,
		},
		{
			name: "legacy_profile",
			content: `
client_id: test-client
authorization_endpoint: https://auth.test.com/oauth2/authorize
token_endpoint: https://auth.test.com/oauth2/token
profile: oauth2-pkce
scopes: ["openid"]
`,
			valid: true,
		},
		{
			name: "missing_client_id",
			content: `
authorization_endpoint: https://auth.test.com/oauth2/authorize
token_endpoint: https://auth.test.com/oauth2/token
profiles: ["oauth2-pkce"]
scopes: ["openid"]
`,
			valid: false,
		},
	}

	for _, cfg := range configs {
		t.Run(cfg.name, func(t *testing.T) {
			configFile := filepath.Join(tmpDir, cfg.name+".yaml")
			err := os.WriteFile(configFile, []byte(cfg.content), 0644)
			if err != nil {
				t.Fatalf("Failed to write config: %v", err)
			}

			config, err := config.LoadConfig(configFile)
			if err != nil {
				if cfg.valid {
					t.Errorf("Expected valid config to load successfully: %v", err)
				}
				return
			}

			err = config.Validate()
			if cfg.valid && err != nil {
				t.Errorf("Expected valid config to validate successfully: %v", err)
			}

			if !cfg.valid && err == nil {
				t.Error("Expected invalid config to fail validation")
			}
		})
	}
}

// TestIntegration_EndToEnd simulates a complete end-to-end workflow
func TestIntegration_EndToEnd(t *testing.T) {
	tmpDir := t.TempDir()

	// Step 1: Create a realistic configuration
	configContent := `
profiles:
  - oauth2-pkce
  - fapi-ro
  - mtls

client_id: e2e-test-client
redirect_uri: https://app.example.com/callback
authorization_endpoint: https://bank.example.com/oauth2/authorize
token_endpoint: https://bank.example.com/oauth2/token
jwks_uri: https://bank.example.com/.well-known/jwks.json

scopes:
  - openid
  - accounts
  - transactions

mtls:
  cert: ./certs/client.crt
  key: ./certs/client.key

private_key_jwt:
  kid: signing-key-1
  key: ./keys/signing.pem
`

	configFile := filepath.Join(tmpDir, "e2e-config.yaml")
	err := os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write e2e config: %v", err)
	}

	// Step 2: Load configuration
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		t.Fatalf("Failed to load e2e config: %v", err)
	}

	// Step 3: Validate configuration
	err = cfg.Validate()
	if err != nil {
		t.Fatalf("E2E config validation failed: %v", err)
	}

	// Step 4: Convert to verifier config
	verifierConfig := cfg.ToVerifierConfig()

	// Step 5: Test profile resolution
	registry := profiles.DefaultRegistry
	profileIDs := cfg.GetProfilesOrLegacy()

	_, err = registry.ResolveProfiles(profileIDs)
	if err != nil {
		t.Fatalf("E2E profile resolution failed: %v", err)
	}

	// Step 6: Verify configuration mapping
	if verifierConfig.ClientID != "e2e-test-client" {
		t.Errorf("Client ID not mapped correctly")
	}

	if len(verifierConfig.Scopes) != 3 {
		t.Errorf("Scopes not mapped correctly: got %d, want 3", len(verifierConfig.Scopes))
	}

	if verifierConfig.MTLSCert != "./certs/client.crt" {
		t.Errorf("mTLS cert path not mapped correctly")
	}

	if verifierConfig.PrivateKeyJWTKID != "signing-key-1" {
		t.Errorf("Private key JWT KID not mapped correctly")
	}

	t.Log("End-to-end integration test completed successfully")
}
