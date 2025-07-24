package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestGeneratePKCECommand(t *testing.T) {
	// Create temporary directory
	tmpDir := t.TempDir()

	// Test basic PKCE generation
	cmd := &cobra.Command{}
	args := []string{}

	// Set global variables for testing
	genOutputDir = tmpDir
	genKeyID = ""
	genShowDetails = false

	// Capture output by redirecting stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	runGeneratePKCE(cmd, args)

	w.Close()
	os.Stdout = oldStdout

	output := make([]byte, 1024)
	n, _ := r.Read(output)
	outputStr := string(output[:n])

	// Check output contains expected elements
	if !strings.Contains(outputStr, "Code Verifier:") {
		t.Error("Output should contain 'Code Verifier:'")
	}

	if !strings.Contains(outputStr, "Code Challenge:") {
		t.Error("Output should contain 'Code Challenge:'")
	}

	if !strings.Contains(outputStr, "Challenge Method: S256") {
		t.Error("Output should contain 'Challenge Method: S256'")
	}
}

func TestGeneratePKCECommand_WithSave(t *testing.T) {
	tmpDir := t.TempDir()

	cmd := &cobra.Command{}
	args := []string{}

	genOutputDir = tmpDir
	genKeyID = "test-pkce"
	genOverwrite = true
	genShowDetails = false

	runGeneratePKCE(cmd, args)

	// Check files were created
	verifierFile := filepath.Join(tmpDir, "test-pkce_verifier.txt")
	challengeFile := filepath.Join(tmpDir, "test-pkce_challenge.txt")

	if _, err := os.Stat(verifierFile); os.IsNotExist(err) {
		t.Errorf("Verifier file should exist: %s", verifierFile)
	}

	if _, err := os.Stat(challengeFile); os.IsNotExist(err) {
		t.Errorf("Challenge file should exist: %s", challengeFile)
	}

	// Read and validate content
	verifierContent, err := os.ReadFile(verifierFile)
	if err != nil {
		t.Fatalf("Failed to read verifier file: %v", err)
	}

	challengeContent, err := os.ReadFile(challengeFile)
	if err != nil {
		t.Fatalf("Failed to read challenge file: %v", err)
	}

	if len(verifierContent) == 0 {
		t.Error("Verifier file should not be empty")
	}

	if len(challengeContent) == 0 {
		t.Error("Challenge file should not be empty")
	}
}

func TestGenerateKeyCommand_RSA(t *testing.T) {
	tmpDir := t.TempDir()

	cmd := &cobra.Command{}
	args := []string{}

	genOutputDir = tmpDir
	genKeyID = "test-rsa-key"
	genKeyType = "rsa"
	genKeySize = 2048
	genOverwrite = true

	runGenerateKey(cmd, args)

	// Check files were created
	privateKeyFile := filepath.Join(tmpDir, "test-rsa-key-private.pem")
	publicKeyFile := filepath.Join(tmpDir, "test-rsa-key-public.pem")

	if _, err := os.Stat(privateKeyFile); os.IsNotExist(err) {
		t.Errorf("Private key file should exist: %s", privateKeyFile)
	}

	if _, err := os.Stat(publicKeyFile); os.IsNotExist(err) {
		t.Errorf("Public key file should exist: %s", publicKeyFile)
	}

	// Validate private key format
	privateKeyContent, err := os.ReadFile(privateKeyFile)
	if err != nil {
		t.Fatalf("Failed to read private key file: %v", err)
	}

	block, _ := pem.Decode(privateKeyContent)
	if block == nil {
		t.Error("Private key should be valid PEM")
	}

	if block.Type != "RSA PRIVATE KEY" {
		t.Errorf("Private key type = %s, want RSA PRIVATE KEY", block.Type)
	}

	// Validate public key format
	publicKeyContent, err := os.ReadFile(publicKeyFile)
	if err != nil {
		t.Fatalf("Failed to read public key file: %v", err)
	}

	block, _ = pem.Decode(publicKeyContent)
	if block == nil {
		t.Error("Public key should be valid PEM")
	}

	if block.Type != "PUBLIC KEY" {
		t.Errorf("Public key type = %s, want PUBLIC KEY", block.Type)
	}
}

func TestGenerateKeyCommand_ECDSA(t *testing.T) {
	tmpDir := t.TempDir()

	cmd := &cobra.Command{}
	args := []string{}

	genOutputDir = tmpDir
	genKeyID = "test-ecdsa-key"
	genKeyType = "ecdsa"
	genCurve = "P-256"
	genOverwrite = true

	runGenerateKey(cmd, args)

	// Check files were created
	privateKeyFile := filepath.Join(tmpDir, "test-ecdsa-key-private.pem")
	publicKeyFile := filepath.Join(tmpDir, "test-ecdsa-key-public.pem")

	if _, err := os.Stat(privateKeyFile); os.IsNotExist(err) {
		t.Errorf("Private key file should exist: %s", privateKeyFile)
	}

	if _, err := os.Stat(publicKeyFile); os.IsNotExist(err) {
		t.Errorf("Public key file should exist: %s", publicKeyFile)
	}

	// Validate private key format
	privateKeyContent, err := os.ReadFile(privateKeyFile)
	if err != nil {
		t.Fatalf("Failed to read private key file: %v", err)
	}

	block, _ := pem.Decode(privateKeyContent)
	if block == nil {
		t.Error("Private key should be valid PEM")
	}

	if block.Type != "EC PRIVATE KEY" {
		t.Errorf("Private key type = %s, want EC PRIVATE KEY", block.Type)
	}
}

func TestGenerateCertCommand(t *testing.T) {
	tmpDir := t.TempDir()

	cmd := &cobra.Command{}
	args := []string{}

	genOutputDir = tmpDir
	genKeyID = "test-cert"
	genKeyType = "rsa"
	genKeySize = 2048
	genCertSubject = "CN=test.example.com"
	genCertDays = 365
	genCertDNS = []string{"test.example.com", "localhost"}
	genCertIPs = []string{"127.0.0.1"}
	genOverwrite = true

	runGenerateCert(cmd, args)

	// Check files were created
	certFile := filepath.Join(tmpDir, "test-cert.crt")
	keyFile := filepath.Join(tmpDir, "test-cert.key")

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		t.Errorf("Certificate file should exist: %s", certFile)
	}

	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		t.Errorf("Key file should exist: %s", keyFile)
	}

	// Validate certificate format and content
	certContent, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("Failed to read certificate file: %v", err)
	}

	block, _ := pem.Decode(certContent)
	if block == nil {
		t.Error("Certificate should be valid PEM")
	}

	if block.Type != "CERTIFICATE" {
		t.Errorf("Certificate type = %s, want CERTIFICATE", block.Type)
	}

	// Parse and validate certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	if cert.Subject.CommonName != "test.example.com" {
		t.Errorf("Certificate CN = %s, want test.example.com", cert.Subject.CommonName)
	}

	// Check DNS names in SAN
	expectedDNS := []string{"test.example.com", "localhost"}
	if len(cert.DNSNames) != len(expectedDNS) {
		t.Errorf("DNS names length = %d, want %d", len(cert.DNSNames), len(expectedDNS))
	}

	for i, expected := range expectedDNS {
		if i < len(cert.DNSNames) && cert.DNSNames[i] != expected {
			t.Errorf("DNS name[%d] = %s, want %s", i, cert.DNSNames[i], expected)
		}
	}

	// Check IP addresses in SAN
	if len(cert.IPAddresses) != 1 {
		t.Errorf("IP addresses length = %d, want 1", len(cert.IPAddresses))
	}

	if len(cert.IPAddresses) > 0 && cert.IPAddresses[0].String() != "127.0.0.1" {
		t.Errorf("IP address = %s, want 127.0.0.1", cert.IPAddresses[0].String())
	}
}

func TestSaveToFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	content := "test content"

	// Test successful save
	err := saveToFile(testFile, content, false)
	if err != nil {
		t.Errorf("saveToFile() error = %v", err)
	}

	// Verify content
	readContent, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}

	if string(readContent) != content {
		t.Errorf("File content = %s, want %s", string(readContent), content)
	}

	// Test overwrite protection
	err = saveToFile(testFile, "new content", false)
	if err == nil {
		t.Error("Expected error for existing file without overwrite, got nil")
	}

	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("Expected 'already exists' error, got: %v", err)
	}

	// Test overwrite allowed
	newContent := "new content"
	err = saveToFile(testFile, newContent, true)
	if err != nil {
		t.Errorf("saveToFile() with overwrite error = %v", err)
	}

	readContent, err = os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}

	if string(readContent) != newContent {
		t.Errorf("File content after overwrite = %s, want %s", string(readContent), newContent)
	}
}

func TestParseSubject(t *testing.T) {
	tests := []struct {
		name        string
		subject     string
		wantCN      string
		wantOrg     []string
		wantCountry []string
	}{
		{
			name:    "Simple CN",
			subject: "CN=test.example.com",
			wantCN:  "test.example.com",
		},
		{
			name:    "CN with Organization",
			subject: "CN=test.example.com,O=Test Org",
			wantCN:  "test.example.com",
			wantOrg: []string{"Test Org"},
		},
		{
			name:        "Full subject",
			subject:     "CN=test.example.com,O=Test Org,C=US",
			wantCN:      "test.example.com",
			wantOrg:     []string{"Test Org"},
			wantCountry: []string{"US"},
		},
		{
			name:    "Spaces in subject",
			subject: "CN = test.example.com , O = Test Org",
			wantCN:  "test.example.com",
			wantOrg: []string{"Test Org"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subject, err := parseSubject(tt.subject)
			if err != nil {
				t.Errorf("parseSubject() error = %v", err)
				return
			}

			if subject.CommonName != tt.wantCN {
				t.Errorf("CommonName = %s, want %s", subject.CommonName, tt.wantCN)
			}

			if tt.wantOrg != nil {
				if len(subject.Organization) != len(tt.wantOrg) {
					t.Errorf("Organization length = %d, want %d", len(subject.Organization), len(tt.wantOrg))
				} else {
					for i, org := range tt.wantOrg {
						if subject.Organization[i] != org {
							t.Errorf("Organization[%d] = %s, want %s", i, subject.Organization[i], org)
						}
					}
				}
			}

			if tt.wantCountry != nil {
				if len(subject.Country) != len(tt.wantCountry) {
					t.Errorf("Country length = %d, want %d", len(subject.Country), len(tt.wantCountry))
				} else {
					for i, country := range tt.wantCountry {
						if subject.Country[i] != country {
							t.Errorf("Country[%d] = %s, want %s", i, subject.Country[i], country)
						}
					}
				}
			}
		})
	}
}

func TestParseIP(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"Valid IPv4", "192.168.1.1", true},
		{"Valid IPv6", "2001:db8::1", true},
		{"Localhost IPv4", "127.0.0.1", true},
		{"Localhost IPv6", "::1", true},
		{"Invalid IP", "not-an-ip", false},
		{"Empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := parseIP(tt.ip)
			got := ip != nil

			if got != tt.want {
				t.Errorf("parseIP(%s) valid = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}
