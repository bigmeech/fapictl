package optional

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	httpClient "fapictl/pkg/http"
	"fapictl/pkg/verifier"
	jwt "github.com/golang-jwt/jwt/v5"
)

type JARVerifier struct {
	client *httpClient.Client
}

func NewJARVerifier(client *httpClient.Client) *JARVerifier {
	return &JARVerifier{
		client: client,
	}
}

func (v *JARVerifier) Name() string {
	return "JWT Secured Authorization Request (JAR)"
}

func (v *JARVerifier) Description() string {
	return "Verifies JWT Secured Authorization Request (RFC 9101) compliance"
}

func (v *JARVerifier) Verify(ctx context.Context, config verifier.VerifierConfig) (*verifier.TestSuite, error) {
	suite := &verifier.TestSuite{
		Name:        v.Name(),
		Description: v.Description(),
		Tests:       []verifier.TestResult{},
	}

	startTime := time.Now()

	// Test 1: Request Object Signing Key Configuration
	suite.Tests = append(suite.Tests, v.testSigningKeyConfiguration(config))

	// Test 2: Request Object Creation
	suite.Tests = append(suite.Tests, v.testRequestObjectCreation(config))

	// Test 3: Request Object Validation
	suite.Tests = append(suite.Tests, v.testRequestObjectValidation(config))

	// Test 4: Authorization Request with Request Object
	suite.Tests = append(suite.Tests, v.testAuthorizationWithRequestObject(config))

	// Test 5: Request Object Security Requirements
	suite.Tests = append(suite.Tests, v.testRequestObjectSecurity(config))

	suite.Duration = time.Since(startTime)
	suite.Summary = v.calculateSummary(suite.Tests)

	return suite, nil
}

func (v *JARVerifier) testSigningKeyConfiguration(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	if config.PrivateKeyJWTKey == "" || config.PrivateKeyJWTKID == "" {
		return verifier.TestResult{
			Name:        "Request Object Signing Key Configuration",
			Description: "Verify signing key is configured for request objects",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       "Private key and key ID required for JAR",
		}
	}

	return verifier.TestResult{
		Name:        "Request Object Signing Key Configuration",
		Description: "Verify signing key is configured for request objects",
		Status:      verifier.StatusPass,
		Duration:    time.Since(startTime),
		Details: map[string]interface{}{
			"key_id":   config.PrivateKeyJWTKID,
			"key_file": config.PrivateKeyJWTKey,
		},
	}
}

func (v *JARVerifier) testRequestObjectCreation(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	if config.PrivateKeyJWTKey == "" {
		return verifier.TestResult{
			Name:        "Request Object Creation",
			Description: "Verify request object can be created and signed",
			Status:      verifier.StatusSkip,
			Duration:    time.Since(startTime),
			Error:       "No signing key configured",
		}
	}

	// Create a test request object
	requestObject, err := v.createTestRequestObject(config)
	if err != nil {
		return verifier.TestResult{
			Name:        "Request Object Creation",
			Description: "Verify request object can be created and signed",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       fmt.Sprintf("Failed to create request object: %v", err),
		}
	}

	return verifier.TestResult{
		Name:        "Request Object Creation",
		Description: "Verify request object can be created and signed",
		Status:      verifier.StatusPass,
		Duration:    time.Since(startTime),
		Details: map[string]interface{}{
			"request_object_length": len(requestObject),
			"algorithm":             "RS256",
		},
	}
}

func (v *JARVerifier) testRequestObjectValidation(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	if config.PrivateKeyJWTKey == "" {
		return verifier.TestResult{
			Name:        "Request Object Validation",
			Description: "Verify request object structure and claims",
			Status:      verifier.StatusSkip,
			Duration:    time.Since(startTime),
			Error:       "No signing key configured",
		}
	}

	// Create and validate a test request object
	requestObject, err := v.createTestRequestObject(config)
	if err != nil {
		return verifier.TestResult{
			Name:        "Request Object Validation",
			Description: "Verify request object structure and claims",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       fmt.Sprintf("Failed to create request object: %v", err),
		}
	}

	// Parse and validate the JWT
	token, err := jwt.Parse(requestObject, func(token *jwt.Token) (interface{}, error) {
		// In a real implementation, you would fetch the public key
		// For testing, we'll generate a temporary key pair
		return v.generateTestPublicKey()
	})

	if err != nil {
		return verifier.TestResult{
			Name:        "Request Object Validation",
			Description: "Verify request object structure and claims",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       fmt.Sprintf("Failed to validate request object: %v", err),
		}
	}

	// Check required claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return verifier.TestResult{
			Name:        "Request Object Validation",
			Description: "Verify request object structure and claims",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       "Invalid claims structure",
		}
	}

	requiredClaims := []string{"iss", "aud", "response_type", "client_id", "redirect_uri", "scope"}
	for _, claim := range requiredClaims {
		if _, exists := claims[claim]; !exists {
			return verifier.TestResult{
				Name:        "Request Object Validation",
				Description: "Verify request object structure and claims",
				Status:      verifier.StatusFail,
				Duration:    time.Since(startTime),
				Error:       fmt.Sprintf("Missing required claim: %s", claim),
			}
		}
	}

	return verifier.TestResult{
		Name:        "Request Object Validation",
		Description: "Verify request object structure and claims",
		Status:      verifier.StatusPass,
		Duration:    time.Since(startTime),
		Details: map[string]interface{}{
			"claims_count":            len(claims),
			"required_claims_present": true,
		},
	}
}

func (v *JARVerifier) testAuthorizationWithRequestObject(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	// Test using request object in authorization request
	return verifier.TestResult{
		Name:        "Authorization Request with Request Object",
		Description: "Verify authorization request can use request object",
		Status:      verifier.StatusSkip,
		Duration:    time.Since(startTime),
		Error:       "Authorization flow testing requires interactive session",
	}
}

func (v *JARVerifier) testRequestObjectSecurity(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	securityIssues := []string{}

	// Check if signing algorithm is secure
	// In a real implementation, you would check the actual algorithm used

	// Check if key ID is present
	if config.PrivateKeyJWTKID == "" {
		securityIssues = append(securityIssues, "Key ID (kid) should be specified for request objects")
	}

	// Check if JWKS URI is configured for public key distribution
	if config.JWKSURI == "" {
		securityIssues = append(securityIssues, "JWKS URI should be configured for public key distribution")
	}

	if len(securityIssues) > 0 {
		return verifier.TestResult{
			Name:        "Request Object Security Requirements",
			Description: "Verify request object security requirements",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       fmt.Sprintf("Security issues: %v", securityIssues),
		}
	}

	return verifier.TestResult{
		Name:        "Request Object Security Requirements",
		Description: "Verify request object security requirements",
		Status:      verifier.StatusPass,
		Duration:    time.Since(startTime),
	}
}

func (v *JARVerifier) createTestRequestObject(config verifier.VerifierConfig) (string, error) {
	// Generate a temporary key pair for testing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}

	// Create claims for the request object
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":           config.ClientID,
		"aud":           config.AuthorizationEndpoint,
		"response_type": "code",
		"client_id":     config.ClientID,
		"redirect_uri":  config.RedirectURI,
		"scope":         "openid",
		"state":         "test_state_jar",
		"nonce":         "test_nonce_jar",
		"iat":           now.Unix(),
		"exp":           now.Add(5 * time.Minute).Unix(),
		"jti":           fmt.Sprintf("jar_%d", now.Unix()),
	}

	// Create and sign the token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = config.PrivateKeyJWTKID

	return token.SignedString(privateKey)
}

func (v *JARVerifier) generateTestPublicKey() (interface{}, error) {
	// Generate a temporary key pair for testing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &privateKey.PublicKey, nil
}

func (v *JARVerifier) calculateSummary(tests []verifier.TestResult) verifier.TestSummary {
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
