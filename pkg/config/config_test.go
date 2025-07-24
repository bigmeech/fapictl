package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfig_ValidConfig(t *testing.T) {
	// Create temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	configContent := `
profiles:
  - oauth2-pkce
  - fapi-ro

client_id: test-client
redirect_uri: https://example.com/callback
authorization_endpoint: https://auth.example.com/oauth2/authorize
token_endpoint: https://auth.example.com/oauth2/token

scopes:
  - openid
  - accounts
`

	err := os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	config, err := LoadConfig(configFile)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	// Test basic fields
	if config.ClientID != "test-client" {
		t.Errorf("ClientID = %s, want test-client", config.ClientID)
	}

	if config.RedirectURI != "https://example.com/callback" {
		t.Errorf("RedirectURI = %s, want https://example.com/callback", config.RedirectURI)
	}

	// Test profiles
	expectedProfiles := []string{"oauth2-pkce", "fapi-ro"}
	if len(config.Profiles) != len(expectedProfiles) {
		t.Errorf("Profiles length = %d, want %d", len(config.Profiles), len(expectedProfiles))
	}

	for i, profile := range expectedProfiles {
		if config.Profiles[i] != profile {
			t.Errorf("Profiles[%d] = %s, want %s", i, config.Profiles[i], profile)
		}
	}

	// Test scopes
	expectedScopes := []string{"openid", "accounts"}
	if len(config.Scopes) != len(expectedScopes) {
		t.Errorf("Scopes length = %d, want %d", len(config.Scopes), len(expectedScopes))
	}
}

func TestLoadConfig_LegacyProfile(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	configContent := `
profile: fapi-ro
client_id: test-client
redirect_uri: https://example.com/callback
authorization_endpoint: https://auth.example.com/oauth2/authorize
token_endpoint: https://auth.example.com/oauth2/token
scopes:
  - openid
`

	err := os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	config, err := LoadConfig(configFile)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	// Legacy profile field should be set
	if config.Profile != "fapi-ro" {
		t.Errorf("Legacy profile field = %s, want fapi-ro", config.Profile)
	}
}

func TestLoadConfig_EnvironmentVariables(t *testing.T) {
	// Note: Current implementation doesn't support env var substitution
	// This test shows the expected behavior when implemented
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	configContent := `
profiles:
  - oauth2-pkce
client_id: test-client-id
redirect_uri: https://example.com/callback
authorization_endpoint: https://auth.example.com/oauth2/authorize
token_endpoint: https://auth.example.com/oauth2/token
scopes:
  - openid
`

	err := os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	config, err := LoadConfig(configFile)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if config.ClientID != "test-client-id" {
		t.Errorf("ClientID = %s, want test-client-id", config.ClientID)
	}
}

func TestLoadConfig_mTLSConfig(t *testing.T) {
	// Create temporary certificate files
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "client.crt")
	keyFile := filepath.Join(tmpDir, "client.key")

	// Write dummy cert and key content
	certContent := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAK7l7NKwTBKbMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv
Y2FsaG9zdDAeFw0yNDA3MjMwMDAwMDBaFw0yNTA3MjMwMDAwMDBaMBQxEjAQBgNV
BAMMCWxvY2FsaG9zdDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7/test/cert/
content/here
-----END CERTIFICATE-----`

	keyContent := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7/test/key/
content/here
-----END PRIVATE KEY-----`

	err := os.WriteFile(certFile, []byte(certContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test cert: %v", err)
	}

	err = os.WriteFile(keyFile, []byte(keyContent), 0600)
	if err != nil {
		t.Fatalf("Failed to write test key: %v", err)
	}

	configFile := filepath.Join(tmpDir, "config.yaml")
	configContent := `
profiles:
  - oauth2-pkce
  - mtls
client_id: test-client
redirect_uri: https://example.com/callback
authorization_endpoint: https://auth.example.com/oauth2/authorize
token_endpoint: https://auth.example.com/oauth2/token
scopes:
  - openid
mtls:
  cert: ` + certFile + `
  key: ` + keyFile + `
`

	err = os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	config, err := LoadConfig(configFile)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if config.MTLS.Cert != certFile {
		t.Errorf("MTLS.Cert = %s, want %s", config.MTLS.Cert, certFile)
	}

	if config.MTLS.Key != keyFile {
		t.Errorf("MTLS.Key = %s, want %s", config.MTLS.Key, keyFile)
	}
}

func TestLoadConfig_PrivateKeyJWT(t *testing.T) {
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "signing.pem")

	keyContent := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7/test/signing/
key/content/here
-----END PRIVATE KEY-----`

	err := os.WriteFile(keyFile, []byte(keyContent), 0600)
	if err != nil {
		t.Fatalf("Failed to write test key: %v", err)
	}

	configFile := filepath.Join(tmpDir, "config.yaml")
	configContent := `
profiles:
  - oauth2-pkce
  - jar
client_id: test-client
redirect_uri: https://example.com/callback
authorization_endpoint: https://auth.example.com/oauth2/authorize
token_endpoint: https://auth.example.com/oauth2/token
scopes:
  - openid
private_key_jwt:
  kid: test-key-1
  key: ` + keyFile + `
`

	err = os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	config, err := LoadConfig(configFile)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if config.PrivateKeyJWT.Kid != "test-key-1" {
		t.Errorf("PrivateKeyJWT.Kid = %s, want test-key-1", config.PrivateKeyJWT.Kid)
	}

	if config.PrivateKeyJWT.Key != keyFile {
		t.Errorf("PrivateKeyJWT.Key = %s, want %s", config.PrivateKeyJWT.Key, keyFile)
	}
}

func TestLoadConfig_ValidationErrors(t *testing.T) {
	tests := []struct {
		name      string
		config    string
		wantError string
	}{
		{
			name: "missing client_id",
			config: `
profiles:
  - oauth2-pkce
redirect_uri: https://example.com/callback
authorization_endpoint: https://auth.example.com/oauth2/authorize
token_endpoint: https://auth.example.com/oauth2/token
scopes:
  - openid
`,
			wantError: "client_id is required",
		},
		{
			name: "missing token endpoint",
			config: `
profiles:
  - oauth2-pkce
client_id: test-client
authorization_endpoint: https://auth.example.com/oauth2/authorize
scopes:
  - openid
`,
			wantError: "token_endpoint is required",
		},
		{
			name: "invalid authorization endpoint",
			config: `
profiles:
  - oauth2-pkce
client_id: test-client
redirect_uri: https://example.com/callback
authorization_endpoint: not-a-url
token_endpoint: https://auth.example.com/oauth2/token
scopes:
  - openid
`,
			wantError: "invalid authorization_endpoint URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configFile := filepath.Join(tmpDir, "config.yaml")

			err := os.WriteFile(configFile, []byte(tt.config), 0644)
			if err != nil {
				t.Fatalf("Failed to write test config: %v", err)
			}

			config, err := LoadConfig(configFile)
			if err != nil {
				t.Errorf("LoadConfig() error = %v", err)
				return
			}

			// Test validation separately
			err = config.Validate()
			if err == nil {
				t.Errorf("Config.Validate() expected error containing %q, got nil", tt.wantError)
				return
			}

			if !strings.Contains(err.Error(), tt.wantError) {
				t.Errorf("Config.Validate() error = %v, want error containing %q", err, tt.wantError)
			}
		})
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	_, err := LoadConfig("nonexistent-config.yaml")
	if err == nil {
		t.Error("LoadConfig() expected error for nonexistent file, got nil")
	}
}

func TestConfig_Validate(t *testing.T) {
	validConfig := &Config{
		Profiles:              []string{"oauth2-pkce"},
		ClientID:              "test-client",
		AuthorizationEndpoint: "https://auth.example.com/oauth2/authorize",
		TokenEndpoint:         "https://auth.example.com/oauth2/token",
	}

	err := validConfig.Validate()
	if err != nil {
		t.Errorf("Valid config validation failed: %v", err)
	}

	// Test missing client_id
	invalidConfig := *validConfig
	invalidConfig.ClientID = ""

	err = invalidConfig.Validate()
	if err == nil {
		t.Error("Expected validation error for missing client_id, got nil")
	}
}
