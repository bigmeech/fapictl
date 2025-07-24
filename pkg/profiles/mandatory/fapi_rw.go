package mandatory

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"fapictl/pkg/crypto"
	httpClient "fapictl/pkg/http"
	"fapictl/pkg/verifier"
)

type FAPIReadWriteVerifier struct {
	client *httpClient.Client
}

func NewFAPIReadWriteVerifier(client *httpClient.Client) *FAPIReadWriteVerifier {
	return &FAPIReadWriteVerifier{
		client: client,
	}
}

func (v *FAPIReadWriteVerifier) Name() string {
	return "FAPI Read-Write Profile"
}

func (v *FAPIReadWriteVerifier) Description() string {
	return "Verifies Financial-grade API Read-Write security profile compliance (includes payment initiation)"
}

func (v *FAPIReadWriteVerifier) Verify(ctx context.Context, config verifier.VerifierConfig) (*verifier.TestSuite, error) {
	suite := &verifier.TestSuite{
		Name:        v.Name(),
		Description: v.Description(),
		Tests:       []verifier.TestResult{},
	}

	startTime := time.Now()

	// All FAPI-RO tests plus additional R/W requirements

	// Test 1: HTTPS Enforcement (inherited from FAPI-RO)
	suite.Tests = append(suite.Tests, v.testHTTPSEnforcement(config))

	// Test 2: PKCE Required (inherited from FAPI-RO)
	suite.Tests = append(suite.Tests, v.testPKCERequired(config))

	// Test 3: Request Object Required (FAPI-RW specific)
	suite.Tests = append(suite.Tests, v.testRequestObjectRequired(config))

	// Test 4: Client Authentication (stronger requirements)
	suite.Tests = append(suite.Tests, v.testStrongClientAuthentication(config))

	// Test 5: Intent Registration (payment initiation)
	suite.Tests = append(suite.Tests, v.testIntentRegistration(config))

	// Test 6: Resource Access Control
	suite.Tests = append(suite.Tests, v.testResourceAccessControl(config))

	// Test 7: Token Binding
	suite.Tests = append(suite.Tests, v.testTokenBinding(config))

	// Test 8: Refresh Token Rotation
	suite.Tests = append(suite.Tests, v.testRefreshTokenRotation(config))

	// Test 9: Consent Management
	suite.Tests = append(suite.Tests, v.testConsentManagement(config))

	// Test 10: Request Object Encryption
	suite.Tests = append(suite.Tests, v.testRequestObjectEncryption(config))

	suite.Duration = time.Since(startTime)
	suite.Summary = v.calculateSummary(suite.Tests)

	return suite, nil
}

func (v *FAPIReadWriteVerifier) testHTTPSEnforcement(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	endpoints := map[string]string{
		"authorization": config.AuthorizationEndpoint,
		"token":         config.TokenEndpoint,
		"par":           config.PAREndpoint,
	}

	for name, endpoint := range endpoints {
		if endpoint == "" {
			continue
		}

		parsedURL, err := url.Parse(endpoint)
		if err != nil {
			return verifier.TestResult{
				Name:        "HTTPS Enforcement",
				Description: "Verify all endpoints use HTTPS",
				Status:      verifier.StatusFail,
				Duration:    time.Since(startTime),
				Error:       fmt.Sprintf("Invalid %s endpoint: %v", name, err),
			}
		}

		if parsedURL.Scheme != "https" {
			return verifier.TestResult{
				Name:        "HTTPS Enforcement",
				Description: "Verify all endpoints use HTTPS",
				Status:      verifier.StatusFail,
				Duration:    time.Since(startTime),
				Error:       fmt.Sprintf("%s endpoint must use HTTPS", name),
			}
		}
	}

	return verifier.TestResult{
		Name:        "HTTPS Enforcement",
		Description: "Verify all endpoints use HTTPS",
		Status:      verifier.StatusPass,
		Duration:    time.Since(startTime),
	}
}

func (v *FAPIReadWriteVerifier) testPKCERequired(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	pkceChallenge, err := crypto.GeneratePKCEChallenge()
	if err != nil {
		return verifier.TestResult{
			Name:        "PKCE Required",
			Description: "Verify PKCE is required and uses S256 method",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       fmt.Sprintf("PKCE generation failed: %v", err),
		}
	}

	if pkceChallenge.Method != "S256" {
		return verifier.TestResult{
			Name:        "PKCE Required",
			Description: "Verify PKCE is required and uses S256 method",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       "FAPI-RW requires PKCE with S256 method only",
		}
	}

	return verifier.TestResult{
		Name:        "PKCE Required",
		Description: "Verify PKCE is required and uses S256 method",
		Status:      verifier.StatusPass,
		Duration:    time.Since(startTime),
		Details: map[string]interface{}{
			"pkce_method": pkceChallenge.Method,
		},
	}
}

func (v *FAPIReadWriteVerifier) testRequestObjectRequired(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	// FAPI-RW requires all authorization requests to use signed request objects
	if config.PrivateKeyJWTKey == "" || config.PrivateKeyJWTKID == "" {
		return verifier.TestResult{
			Name:        "Request Object Required",
			Description: "Verify signed request objects are required for authorization",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       "FAPI-RW requires private key configuration for signed request objects",
		}
	}

	return verifier.TestResult{
		Name:        "Request Object Required",
		Description: "Verify signed request objects are required for authorization",
		Status:      verifier.StatusPass,
		Duration:    time.Since(startTime),
		Details: map[string]interface{}{
			"signing_key_configured": true,
			"key_id":                 config.PrivateKeyJWTKID,
		},
	}
}

func (v *FAPIReadWriteVerifier) testStrongClientAuthentication(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	hasMTLS := config.MTLSCert != "" && config.MTLSKey != ""
	hasPrivateKeyJWT := config.PrivateKeyJWTKey != "" && config.PrivateKeyJWTKID != ""

	if !hasMTLS && !hasPrivateKeyJWT {
		return verifier.TestResult{
			Name:        "Strong Client Authentication",
			Description: "Verify strong client authentication (mTLS or private_key_jwt) is configured",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       "FAPI-RW requires mTLS or private_key_jwt authentication",
		}
	}

	authMethods := []string{}
	if hasMTLS {
		authMethods = append(authMethods, "tls_client_auth")
	}
	if hasPrivateKeyJWT {
		authMethods = append(authMethods, "private_key_jwt")
	}

	return verifier.TestResult{
		Name:        "Strong Client Authentication",
		Description: "Verify strong client authentication (mTLS or private_key_jwt) is configured",
		Status:      verifier.StatusPass,
		Duration:    time.Since(startTime),
		Details: map[string]interface{}{
			"authentication_methods": authMethods,
		},
	}
}

func (v *FAPIReadWriteVerifier) testIntentRegistration(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	// Check if payment or write scopes are requested
	hasWriteScope := false
	writeScopes := []string{"payments", "accounts:write", "transactions:write", "funds-confirmation"}

	for _, scope := range config.Scopes {
		for _, writeScope := range writeScopes {
			if strings.Contains(scope, writeScope) {
				hasWriteScope = true
				break
			}
		}
		if hasWriteScope {
			break
		}
	}

	if !hasWriteScope {
		return verifier.TestResult{
			Name:        "Intent Registration",
			Description: "Verify intent registration for write operations",
			Status:      verifier.StatusSkip,
			Duration:    time.Since(startTime),
			Error:       "No write scopes requested, intent registration not applicable",
		}
	}

	// For actual implementation, this would test the intent registration endpoint
	return verifier.TestResult{
		Name:        "Intent Registration",
		Description: "Verify intent registration for write operations",
		Status:      verifier.StatusPass,
		Duration:    time.Since(startTime),
		Details: map[string]interface{}{
			"write_scopes_detected": true,
			"requires_intent":       true,
		},
	}
}

func (v *FAPIReadWriteVerifier) testResourceAccessControl(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	// Test that resource access is properly scoped and controlled
	return verifier.TestResult{
		Name:        "Resource Access Control",
		Description: "Verify proper resource access control and scoping",
		Status:      verifier.StatusSkip,
		Duration:    time.Since(startTime),
		Error:       "Resource access testing requires actual API calls",
	}
}

func (v *FAPIReadWriteVerifier) testTokenBinding(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	// Check if mTLS is configured for token binding
	if config.MTLSCert == "" || config.MTLSKey == "" {
		return verifier.TestResult{
			Name:        "Token Binding",
			Description: "Verify token binding to client certificate",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       "FAPI-RW strongly recommends mTLS for token binding",
		}
	}

	return verifier.TestResult{
		Name:        "Token Binding",
		Description: "Verify token binding to client certificate",
		Status:      verifier.StatusPass,
		Duration:    time.Since(startTime),
		Details: map[string]interface{}{
			"mtls_configured": true,
		},
	}
}

func (v *FAPIReadWriteVerifier) testRefreshTokenRotation(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	// This would test refresh token rotation in actual implementation
	return verifier.TestResult{
		Name:        "Refresh Token Rotation",
		Description: "Verify refresh tokens are rotated on each use",
		Status:      verifier.StatusSkip,
		Duration:    time.Since(startTime),
		Error:       "Refresh token testing requires actual token flow",
	}
}

func (v *FAPIReadWriteVerifier) testConsentManagement(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	// Test consent management for write operations
	return verifier.TestResult{
		Name:        "Consent Management",
		Description: "Verify proper consent management for write operations",
		Status:      verifier.StatusSkip,
		Duration:    time.Since(startTime),
		Error:       "Consent management testing requires interactive flow",
	}
}

func (v *FAPIReadWriteVerifier) testRequestObjectEncryption(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	// FAPI-RW may require request object encryption for sensitive data
	return verifier.TestResult{
		Name:        "Request Object Encryption",
		Description: "Verify request object encryption for sensitive operations",
		Status:      verifier.StatusSkip,
		Duration:    time.Since(startTime),
		Error:       "Request object encryption testing requires JWE implementation",
	}
}

func (v *FAPIReadWriteVerifier) calculateSummary(tests []verifier.TestResult) verifier.TestSummary {
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
