package optional

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"fapictl/pkg/crypto"
	httpClient "fapictl/pkg/http"
	"fapictl/pkg/verifier"
)

type PARVerifier struct {
	client *httpClient.Client
}

func NewPARVerifier(client *httpClient.Client) *PARVerifier {
	return &PARVerifier{
		client: client,
	}
}

func (v *PARVerifier) Name() string {
	return "Pushed Authorization Requests (PAR)"
}

func (v *PARVerifier) Description() string {
	return "Verifies Pushed Authorization Request (RFC 9126) compliance"
}

func (v *PARVerifier) Verify(ctx context.Context, config verifier.VerifierConfig) (*verifier.TestSuite, error) {
	suite := &verifier.TestSuite{
		Name:        v.Name(),
		Description: v.Description(),
		Tests:       []verifier.TestResult{},
	}

	startTime := time.Now()

	// Test 1: PAR Endpoint Configuration
	suite.Tests = append(suite.Tests, v.testPAREndpointConfiguration(config))

	// Test 2: PAR Request Format
	suite.Tests = append(suite.Tests, v.testPARRequestFormat(config))

	// Test 3: PAR Response Validation
	suite.Tests = append(suite.Tests, v.testPARResponseValidation(config))

	// Test 4: Request URI Usage
	suite.Tests = append(suite.Tests, v.testRequestURIUsage(config))

	// Test 5: PAR Security Requirements
	suite.Tests = append(suite.Tests, v.testPARSecurityRequirements(config))

	suite.Duration = time.Since(startTime)
	suite.Summary = v.calculateSummary(suite.Tests)

	return suite, nil
}

func (v *PARVerifier) testPAREndpointConfiguration(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	if config.PAREndpoint == "" {
		return verifier.TestResult{
			Name:        "PAR Endpoint Configuration",
			Description: "Verify PAR endpoint is configured",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       "PAR endpoint not configured",
		}
	}

	// Validate URL format
	parsedURL, err := url.Parse(config.PAREndpoint)
	if err != nil {
		return verifier.TestResult{
			Name:        "PAR Endpoint Configuration",
			Description: "Verify PAR endpoint is configured",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       fmt.Sprintf("Invalid PAR endpoint URL: %v", err),
		}
	}

	if parsedURL.Scheme != "https" {
		return verifier.TestResult{
			Name:        "PAR Endpoint Configuration",
			Description: "Verify PAR endpoint is configured",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       "PAR endpoint must use HTTPS",
		}
	}

	return verifier.TestResult{
		Name:        "PAR Endpoint Configuration",
		Description: "Verify PAR endpoint is configured",
		Status:      verifier.StatusPass,
		Duration:    time.Since(startTime),
		Details: map[string]interface{}{
			"par_endpoint": config.PAREndpoint,
			"scheme":       parsedURL.Scheme,
		},
	}
}

func (v *PARVerifier) testPARRequestFormat(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	if config.PAREndpoint == "" {
		return verifier.TestResult{
			Name:        "PAR Request Format",
			Description: "Verify PAR request format compliance",
			Status:      verifier.StatusSkip,
			Duration:    time.Since(startTime),
			Error:       "PAR endpoint not configured",
		}
	}

	// Generate PKCE challenge for the request
	pkceChallenge, err := crypto.GeneratePKCEChallenge()
	if err != nil {
		return verifier.TestResult{
			Name:        "PAR Request Format",
			Description: "Verify PAR request format compliance",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       fmt.Sprintf("PKCE generation failed: %v", err),
		}
	}

	// Build PAR request parameters
	parParams := v.buildPARParams(config, pkceChallenge)

	// Test if we can construct a valid PAR request
	req, err := v.createPARRequest(config, parParams)
	if err != nil {
		return verifier.TestResult{
			Name:        "PAR Request Format",
			Description: "Verify PAR request format compliance",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       fmt.Sprintf("Failed to create PAR request: %v", err),
		}
	}

	return verifier.TestResult{
		Name:        "PAR Request Format",
		Description: "Verify PAR request format compliance",
		Status:      verifier.StatusPass,
		Duration:    time.Since(startTime),
		Details: map[string]interface{}{
			"request_method":      req.Method,
			"content_type":        req.Header.Get("Content-Type"),
			"parameters_included": len(parParams),
		},
	}
}

func (v *PARVerifier) testPARResponseValidation(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	if config.PAREndpoint == "" {
		return verifier.TestResult{
			Name:        "PAR Response Validation",
			Description: "Verify PAR response format and content",
			Status:      verifier.StatusSkip,
			Duration:    time.Since(startTime),
			Error:       "PAR endpoint not configured",
		}
	}

	// Generate test PAR request
	pkceChallenge, _ := crypto.GeneratePKCEChallenge()
	parParams := v.buildPARParams(config, pkceChallenge)
	req, err := v.createPARRequest(config, parParams)
	if err != nil {
		return verifier.TestResult{
			Name:        "PAR Response Validation",
			Description: "Verify PAR response format and content",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       fmt.Sprintf("Failed to create PAR request: %v", err),
		}
	}

	// Send PAR request
	resp, err := v.client.Do(req)
	if err != nil {
		return verifier.TestResult{
			Name:        "PAR Response Validation",
			Description: "Verify PAR response format and content",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       fmt.Sprintf("PAR request failed: %v", err),
		}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return verifier.TestResult{
			Name:        "PAR Response Validation",
			Description: "Verify PAR response format and content",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       fmt.Sprintf("Failed to read PAR response: %v", err),
		}
	}

	// Parse response
	var parResponse map[string]interface{}
	if err := json.Unmarshal(body, &parResponse); err != nil {
		return verifier.TestResult{
			Name:        "PAR Response Validation",
			Description: "Verify PAR response format and content",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       fmt.Sprintf("Invalid JSON in PAR response: %v", err),
		}
	}

	// Check for required fields
	if resp.StatusCode == http.StatusCreated {
		requestURI, hasRequestURI := parResponse["request_uri"]
		expiresIn, hasExpiresIn := parResponse["expires_in"]

		if !hasRequestURI {
			return verifier.TestResult{
				Name:        "PAR Response Validation",
				Description: "Verify PAR response format and content",
				Status:      verifier.StatusFail,
				Duration:    time.Since(startTime),
				Error:       "PAR response missing request_uri",
			}
		}

		if !hasExpiresIn {
			return verifier.TestResult{
				Name:        "PAR Response Validation",
				Description: "Verify PAR response format and content",
				Status:      verifier.StatusFail,
				Duration:    time.Since(startTime),
				Error:       "PAR response missing expires_in",
			}
		}

		return verifier.TestResult{
			Name:        "PAR Response Validation",
			Description: "Verify PAR response format and content",
			Status:      verifier.StatusPass,
			Duration:    time.Since(startTime),
			Details: map[string]interface{}{
				"status_code": resp.StatusCode,
				"request_uri": requestURI,
				"expires_in":  expiresIn,
			},
		}
	}

	// Handle error responses
	return verifier.TestResult{
		Name:        "PAR Response Validation",
		Description: "Verify PAR response format and content",
		Status:      verifier.StatusFail,
		Duration:    time.Since(startTime),
		Error:       fmt.Sprintf("PAR request failed with status %d: %s", resp.StatusCode, string(body)),
	}
}

func (v *PARVerifier) testRequestURIUsage(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	// Test that request_uri can be used in authorization requests
	return verifier.TestResult{
		Name:        "Request URI Usage",
		Description: "Verify request_uri can be used in authorization requests",
		Status:      verifier.StatusSkip,
		Duration:    time.Since(startTime),
		Error:       "Request URI usage testing requires full authorization flow",
	}
}

func (v *PARVerifier) testPARSecurityRequirements(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	// Check security requirements for PAR
	securityIssues := []string{}

	// Check client authentication
	if config.MTLSCert == "" && config.PrivateKeyJWTKey == "" {
		securityIssues = append(securityIssues, "PAR should use strong client authentication")
	}

	// Check HTTPS
	if config.PAREndpoint != "" {
		if parsedURL, err := url.Parse(config.PAREndpoint); err == nil {
			if parsedURL.Scheme != "https" {
				securityIssues = append(securityIssues, "PAR endpoint must use HTTPS")
			}
		}
	}

	if len(securityIssues) > 0 {
		return verifier.TestResult{
			Name:        "PAR Security Requirements",
			Description: "Verify PAR security requirements are met",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       strings.Join(securityIssues, "; "),
		}
	}

	return verifier.TestResult{
		Name:        "PAR Security Requirements",
		Description: "Verify PAR security requirements are met",
		Status:      verifier.StatusPass,
		Duration:    time.Since(startTime),
	}
}

func (v *PARVerifier) buildPARParams(config verifier.VerifierConfig, pkce *crypto.PKCEChallenge) map[string]string {
	params := map[string]string{
		"response_type":         "code",
		"client_id":             config.ClientID,
		"redirect_uri":          config.RedirectURI,
		"scope":                 strings.Join(config.Scopes, " "),
		"code_challenge":        pkce.Challenge,
		"code_challenge_method": pkce.Method,
		"state":                 "test_state_par",
	}

	// Add nonce for OIDC
	for _, scope := range config.Scopes {
		if scope == "openid" {
			params["nonce"] = "test_nonce_par"
			break
		}
	}

	return params
}

func (v *PARVerifier) createPARRequest(config verifier.VerifierConfig, params map[string]string) (*http.Request, error) {
	// Convert params to form data
	formData := url.Values{}
	for key, value := range params {
		formData.Set(key, value)
	}

	req, err := http.NewRequest("POST", config.PAREndpoint, bytes.NewBufferString(formData.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	return req, nil
}

func (v *PARVerifier) calculateSummary(tests []verifier.TestResult) verifier.TestSummary {
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
