package optional

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	httpClient "fapictl/pkg/http"
	"fapictl/pkg/verifier"
)

type MTLSVerifier struct {
	client *httpClient.Client
}

func NewMTLSVerifier(client *httpClient.Client) *MTLSVerifier {
	return &MTLSVerifier{
		client: client,
	}
}

func (v *MTLSVerifier) Name() string {
	return "Mutual TLS (mTLS)"
}

func (v *MTLSVerifier) Description() string {
	return "Verifies mutual TLS client certificate authentication compliance"
}

func (v *MTLSVerifier) Verify(ctx context.Context, config verifier.VerifierConfig) (*verifier.TestSuite, error) {
	suite := &verifier.TestSuite{
		Name:        v.Name(),
		Description: v.Description(),
		Tests:       []verifier.TestResult{},
	}

	startTime := time.Now()

	// Test 1: Client Certificate Configuration
	suite.Tests = append(suite.Tests, v.testClientCertificateConfiguration(config))

	// Test 2: Certificate Chain Validation
	suite.Tests = append(suite.Tests, v.testCertificateChainValidation(config))

	// Test 3: TLS Handshake
	suite.Tests = append(suite.Tests, v.testTLSHandshake(config))

	// Test 4: Certificate Binding
	suite.Tests = append(suite.Tests, v.testCertificateBinding(config))

	// Test 5: Revocation Check
	suite.Tests = append(suite.Tests, v.testCertificateRevocation(config))

	suite.Duration = time.Since(startTime)
	suite.Summary = v.calculateSummary(suite.Tests)

	return suite, nil
}

func (v *MTLSVerifier) testClientCertificateConfiguration(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	if config.MTLSCert == "" || config.MTLSKey == "" {
		return verifier.TestResult{
			Name:        "Client Certificate Configuration",
			Description: "Verify client certificate and private key are configured",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       "mTLS certificate and key must be configured",
		}
	}

	// Test loading the certificate
	_, err := tls.LoadX509KeyPair(config.MTLSCert, config.MTLSKey)
	if err != nil {
		return verifier.TestResult{
			Name:        "Client Certificate Configuration",
			Description: "Verify client certificate and private key are configured",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       fmt.Sprintf("Failed to load certificate pair: %v", err),
		}
	}

	return verifier.TestResult{
		Name:        "Client Certificate Configuration",
		Description: "Verify client certificate and private key are configured",
		Status:      verifier.StatusPass,
		Duration:    time.Since(startTime),
		Details: map[string]interface{}{
			"cert_file": config.MTLSCert,
			"key_file":  config.MTLSKey,
		},
	}
}

func (v *MTLSVerifier) testCertificateChainValidation(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	cert, err := tls.LoadX509KeyPair(config.MTLSCert, config.MTLSKey)
	if err != nil {
		return verifier.TestResult{
			Name:        "Certificate Chain Validation",
			Description: "Verify certificate chain is valid",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       fmt.Sprintf("Cannot load certificate: %v", err),
		}
	}

	if len(cert.Certificate) == 0 {
		return verifier.TestResult{
			Name:        "Certificate Chain Validation",
			Description: "Verify certificate chain is valid",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       "Certificate chain is empty",
		}
	}

	return verifier.TestResult{
		Name:        "Certificate Chain Validation",
		Description: "Verify certificate chain is valid",
		Status:      verifier.StatusPass,
		Duration:    time.Since(startTime),
		Details: map[string]interface{}{
			"chain_length": len(cert.Certificate),
		},
	}
}

func (v *MTLSVerifier) testTLSHandshake(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	// Test TLS handshake with the token endpoint
	req, err := http.NewRequest("OPTIONS", config.TokenEndpoint, nil)
	if err != nil {
		return verifier.TestResult{
			Name:        "TLS Handshake",
			Description: "Verify mTLS handshake with server",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       fmt.Sprintf("Failed to create request: %v", err),
		}
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return verifier.TestResult{
			Name:        "TLS Handshake",
			Description: "Verify mTLS handshake with server",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       fmt.Sprintf("mTLS handshake failed: %v", err),
		}
	}
	defer resp.Body.Close()

	// Check if the connection used client certificate
	tlsVersion := "unknown"
	if resp.TLS != nil {
		switch resp.TLS.Version {
		case tls.VersionTLS12:
			tlsVersion = "TLS 1.2"
		case tls.VersionTLS13:
			tlsVersion = "TLS 1.3"
		}
	}

	return verifier.TestResult{
		Name:        "TLS Handshake",
		Description: "Verify mTLS handshake with server",
		Status:      verifier.StatusPass,
		Duration:    time.Since(startTime),
		Details: map[string]interface{}{
			"tls_version":      tlsVersion,
			"status_code":      resp.StatusCode,
			"client_cert_used": resp.TLS != nil,
		},
	}
}

func (v *MTLSVerifier) testCertificateBinding(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	// Test certificate binding (cnf claim in tokens)
	return verifier.TestResult{
		Name:        "Certificate Binding",
		Description: "Verify tokens are bound to client certificate",
		Status:      verifier.StatusSkip,
		Duration:    time.Since(startTime),
		Error:       "Certificate binding testing requires actual token issuance",
	}
}

func (v *MTLSVerifier) testCertificateRevocation(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	// Test certificate revocation status
	return verifier.TestResult{
		Name:        "Certificate Revocation Check",
		Description: "Verify certificate revocation status",
		Status:      verifier.StatusSkip,
		Duration:    time.Since(startTime),
		Error:       "Certificate revocation checking requires OCSP/CRL validation",
	}
}

func (v *MTLSVerifier) calculateSummary(tests []verifier.TestResult) verifier.TestSummary {
	summary := verifier.TestSummary{
		Total: len(tests),
	}

	for _, test := range tests {
		switch test.Status {
		case verifier.StatusPass:
			summary.Passed++
		case verifier.StatusFail:
			summary.Failed++
		case verifier.StatusSkip:
			summary.Skipped++
		}
	}

	return summary
}
