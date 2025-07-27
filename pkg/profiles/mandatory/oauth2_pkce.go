package mandatory

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"fapictl/pkg/crypto"
	httpClient "fapictl/pkg/http"
	"fapictl/pkg/verifier"
)

type AuthCodePKCEVerifier struct {
	client *httpClient.Client
}

func NewAuthCodePKCEVerifier(client *httpClient.Client) *AuthCodePKCEVerifier {
	return &AuthCodePKCEVerifier{
		client: client,
	}
}

func (v *AuthCodePKCEVerifier) Name() string {
	return "OAuth2 Authorization Code + PKCE"
}

func (v *AuthCodePKCEVerifier) Description() string {
	return "Verifies OAuth 2.0 Authorization Code flow with PKCE (RFC 7636) compliance"
}

func (v *AuthCodePKCEVerifier) Verify(ctx context.Context, config verifier.VerifierConfig) (*verifier.TestSuite, error) {
	suite := &verifier.TestSuite{
		Name:        v.Name(),
		Description: v.Description(),
		Tests:       []verifier.TestResult{},
	}

	startTime := time.Now()

	// Test 1: PKCE Challenge Generation
	suite.Tests = append(suite.Tests, v.testPKCEGeneration())

	// Test 2: Authorization Endpoint Discovery
	suite.Tests = append(suite.Tests, v.testAuthorizationEndpoint(config))

	// Test 3: Token Endpoint Discovery
	suite.Tests = append(suite.Tests, v.testTokenEndpoint(config))

	// Test 4: Authorization Request with PKCE
	pkceChallenge, authTest := v.testAuthorizationRequest(config)
	suite.Tests = append(suite.Tests, authTest)

	// Test 5: Token Exchange (simulated)
	if authTest.Status == verifier.StatusPass && pkceChallenge != nil {
		suite.Tests = append(suite.Tests, v.testTokenExchange(config, pkceChallenge))
	} else {
		suite.Tests = append(suite.Tests, verifier.TestResult{
			Name:        "Token Exchange",
			Description: "OAuth2 token exchange with PKCE verification",
			Status:      verifier.StatusSkip,
			Error:       "Skipped due to failed authorization request",
		})
	}

	suite.Duration = time.Since(startTime)
	suite.Summary = calculateSummary(suite.Tests)

	return suite, nil
}

func (v *AuthCodePKCEVerifier) testPKCEGeneration() verifier.TestResult {
	startTime := time.Now()

	challenge, err := crypto.GeneratePKCEChallenge()
	if err != nil {
		return verifier.TestResult{
			Name:        "PKCE Challenge Generation",
			Description: "Generate PKCE code verifier and challenge",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       fmt.Sprintf("Failed to generate PKCE challenge: %v", err),
		}
	}

	// Verify the challenge is valid
	if !crypto.VerifyPKCEChallenge(challenge.Verifier, challenge.Challenge) {
		return verifier.TestResult{
			Name:        "PKCE Challenge Generation",
			Description: "Generate PKCE code verifier and challenge",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       "Generated PKCE challenge verification failed",
		}
	}

	return verifier.TestResult{
		Name:        "PKCE Challenge Generation",
		Description: "Generate PKCE code verifier and challenge",
		Status:      verifier.StatusPass,
		Duration:    time.Since(startTime),
		Details: map[string]interface{}{
			"challenge_method": challenge.Method,
			"verifier_length":  len(challenge.Verifier),
			"challenge_length": len(challenge.Challenge),
		},
	}
}

func (v *AuthCodePKCEVerifier) testAuthorizationEndpoint(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	if config.AuthorizationEndpoint == "" {
		return verifier.TestResult{
			Name:        "Authorization Endpoint Discovery",
			Description: "Verify authorization endpoint is configured",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       "Authorization endpoint not configured",
		}
	}

	// Parse URL to verify it's valid
	_, err := url.Parse(config.AuthorizationEndpoint)
	if err != nil {
		return verifier.TestResult{
			Name:        "Authorization Endpoint Discovery",
			Description: "Verify authorization endpoint is configured",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       fmt.Sprintf("Invalid authorization endpoint URL: %v", err),
		}
	}

	return verifier.TestResult{
		Name:        "Authorization Endpoint Discovery",
		Description: "Verify authorization endpoint is configured",
		Status:      verifier.StatusPass,
		Duration:    time.Since(startTime),
		Details: map[string]interface{}{
			"endpoint": config.AuthorizationEndpoint,
		},
	}
}

func (v *AuthCodePKCEVerifier) testTokenEndpoint(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	if config.TokenEndpoint == "" {
		return verifier.TestResult{
			Name:        "Token Endpoint Discovery",
			Description: "Verify token endpoint is configured",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       "Token endpoint not configured",
		}
	}

	// Test if token endpoint is reachable (OPTIONS request)
	req, err := http.NewRequest("OPTIONS", config.TokenEndpoint, nil)
	if err != nil {
		return verifier.TestResult{
			Name:        "Token Endpoint Discovery",
			Description: "Verify token endpoint is configured",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       fmt.Sprintf("Failed to create request: %v", err),
		}
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return verifier.TestResult{
			Name:        "Token Endpoint Discovery",
			Description: "Verify token endpoint is configured",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       fmt.Sprintf("Token endpoint unreachable: %v", err),
		}
	}
	defer resp.Body.Close()

	// Validate HTTP status code - server errors indicate service unavailability
	if resp.StatusCode >= 500 {
		return verifier.TestResult{
			Name:        "Token Endpoint Discovery",
			Description: "Verify token endpoint is configured",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       fmt.Sprintf("Token endpoint server error: %d %s", resp.StatusCode, resp.Status),
			Details: map[string]interface{}{
				"endpoint":    config.TokenEndpoint,
				"status_code": resp.StatusCode,
			},
		}
	}

	// 4xx errors other than 405 (Method Not Allowed) indicate configuration issues
	if resp.StatusCode >= 400 && resp.StatusCode != 405 {
		return verifier.TestResult{
			Name:        "Token Endpoint Discovery",
			Description: "Verify token endpoint is configured",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       fmt.Sprintf("Token endpoint client error: %d %s", resp.StatusCode, resp.Status),
			Details: map[string]interface{}{
				"endpoint":    config.TokenEndpoint,
				"status_code": resp.StatusCode,
			},
		}
	}

	return verifier.TestResult{
		Name:        "Token Endpoint Discovery",
		Description: "Verify token endpoint is configured",
		Status:      verifier.StatusPass,
		Duration:    time.Since(startTime),
		Details: map[string]interface{}{
			"endpoint":    config.TokenEndpoint,
			"status_code": resp.StatusCode,
		},
	}
}

func (v *AuthCodePKCEVerifier) testAuthorizationRequest(config verifier.VerifierConfig) (*crypto.PKCEChallenge, verifier.TestResult) {
	startTime := time.Now()

	// Generate PKCE challenge
	pkceChallenge, err := crypto.GeneratePKCEChallenge()
	if err != nil {
		return nil, verifier.TestResult{
			Name:        "Authorization Request",
			Description: "Construct OAuth2 authorization request with PKCE",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       fmt.Sprintf("PKCE generation failed: %v", err),
		}
	}

	// Build authorization URL
	authURL, err := v.buildAuthorizationURL(config, pkceChallenge)
	if err != nil {
		return nil, verifier.TestResult{
			Name:        "Authorization Request",
			Description: "Construct OAuth2 authorization request with PKCE",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       fmt.Sprintf("Failed to build authorization URL: %v", err),
		}
	}

	return pkceChallenge, verifier.TestResult{
		Name:        "Authorization Request",
		Description: "Construct OAuth2 authorization request with PKCE",
		Status:      verifier.StatusPass,
		Duration:    time.Since(startTime),
		Details: map[string]interface{}{
			"authorization_url": authURL,
			"pkce_method":       pkceChallenge.Method,
			"scopes":            config.Scopes,
		},
	}
}

func (v *AuthCodePKCEVerifier) testTokenExchange(config verifier.VerifierConfig, pkceChallenge *crypto.PKCEChallenge) verifier.TestResult {
	startTime := time.Now()

	// Simulate token exchange request structure
	tokenData := map[string]interface{}{
		"grant_type":    "authorization_code",
		"code":          "simulated_auth_code",
		"redirect_uri":  config.RedirectURI,
		"client_id":     config.ClientID,
		"code_verifier": pkceChallenge.Verifier,
	}

	// Test token endpoint with invalid code (should fail gracefully)
	resp, err := v.testTokenEndpointRequest(config, tokenData)
	if err != nil {
		return verifier.TestResult{
			Name:        "Token Exchange",
			Description: "OAuth2 token exchange with PKCE verification",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       fmt.Sprintf("Token request failed: %v", err),
		}
	}

	// Server errors (5xx) indicate service unavailability - should fail
	if resp.StatusCode >= 500 {
		return verifier.TestResult{
			Name:        "Token Exchange",
			Description: "OAuth2 token exchange with PKCE verification",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       fmt.Sprintf("Token endpoint server error: %d", resp.StatusCode),
			Details: map[string]interface{}{
				"status_code": resp.StatusCode,
				"pkce_sent":   true,
			},
		}
	}

	// We expect 4xx errors with invalid_grant since we're using a fake code
	// But the server should properly handle the PKCE parameters (not return 5xx)
	return verifier.TestResult{
		Name:        "Token Exchange",
		Description: "OAuth2 token exchange with PKCE verification",
		Status:      verifier.StatusPass,
		Duration:    time.Since(startTime),
		Details: map[string]interface{}{
			"status_code": resp.StatusCode,
			"pkce_sent":   true,
			"note":        "4xx errors expected for invalid authorization codes",
		},
	}
}

func (v *AuthCodePKCEVerifier) buildAuthorizationURL(config verifier.VerifierConfig, pkce *crypto.PKCEChallenge) (string, error) {
	baseURL, err := url.Parse(config.AuthorizationEndpoint)
	if err != nil {
		return "", err
	}

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", config.ClientID)
	params.Set("redirect_uri", config.RedirectURI)
	params.Set("scope", strings.Join(config.Scopes, " "))
	params.Set("code_challenge", pkce.Challenge)
	params.Set("code_challenge_method", pkce.Method)
	params.Set("state", "test_state_value")

	baseURL.RawQuery = params.Encode()
	return baseURL.String(), nil
}

func (v *AuthCodePKCEVerifier) testTokenEndpointRequest(config verifier.VerifierConfig, data map[string]interface{}) (*http.Response, error) {
	values := url.Values{}
	for k, v := range data {
		values.Set(k, fmt.Sprintf("%v", v))
	}

	req, err := http.NewRequest("POST", config.TokenEndpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	return v.client.Do(req)
}

func calculateSummary(tests []verifier.TestResult) verifier.TestSummary {
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
