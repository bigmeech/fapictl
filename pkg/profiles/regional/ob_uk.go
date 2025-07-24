package regional

import (
	"context"
	"strings"
	"time"

	httpClient "fapictl/pkg/http"
	"fapictl/pkg/verifier"
)

type OBUKVerifier struct {
	client *httpClient.Client
}

func NewOBUKVerifier(client *httpClient.Client) *OBUKVerifier {
	return &OBUKVerifier{
		client: client,
	}
}

func (v *OBUKVerifier) Name() string {
	return "UK Open Banking"
}

func (v *OBUKVerifier) Description() string {
	return "Verifies UK Open Banking Implementation Entity (OBIE) security profile compliance"
}

func (v *OBUKVerifier) Verify(ctx context.Context, config verifier.VerifierConfig) (*verifier.TestSuite, error) {
	suite := &verifier.TestSuite{
		Name:        v.Name(),
		Description: v.Description(),
		Tests:       []verifier.TestResult{},
	}

	startTime := time.Now()

	// Test 1: UK Open Banking Scopes
	suite.Tests = append(suite.Tests, v.testOBUKScopes(config))

	// Test 2: Intent-based Authorization
	suite.Tests = append(suite.Tests, v.testIntentBasedAuthorization(config))

	// Test 3: Strong Customer Authentication (SCA)
	suite.Tests = append(suite.Tests, v.testStrongCustomerAuthentication(config))

	// Test 4: Account Request Permissions
	suite.Tests = append(suite.Tests, v.testAccountRequestPermissions(config))

	// Test 5: Payment Initiation Security
	suite.Tests = append(suite.Tests, v.testPaymentInitiationSecurity(config))

	// Test 6: Directory Certificate Validation
	suite.Tests = append(suite.Tests, v.testDirectoryCertificateValidation(config))

	// Test 7: Customer Authentication Methods
	suite.Tests = append(suite.Tests, v.testCustomerAuthenticationMethods(config))

	// Test 8: Data Cluster Permissions
	suite.Tests = append(suite.Tests, v.testDataClusterPermissions(config))

	suite.Duration = time.Since(startTime)
	suite.Summary = v.calculateSummary(suite.Tests)

	return suite, nil
}

func (v *OBUKVerifier) testOBUKScopes(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	// Check for UK Open Banking specific scopes
	obukScopes := []string{"accounts", "payments", "fundsconfirmations"}
	hasOBUKScope := false

	for _, scope := range config.Scopes {
		for _, obukScope := range obukScopes {
			if strings.Contains(strings.ToLower(scope), obukScope) {
				hasOBUKScope = true
				break
			}
		}
		if hasOBUKScope {
			break
		}
	}

	if !hasOBUKScope {
		return verifier.TestResult{
			Name:        "UK Open Banking Scopes",
			Description: "Verify UK Open Banking specific scopes are requested",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       "No UK Open Banking scopes (accounts, payments, fundsconfirmations) found",
		}
	}

	return verifier.TestResult{
		Name:        "UK Open Banking Scopes",
		Description: "Verify UK Open Banking specific scopes are requested",
		Status:      verifier.StatusPass,
		Duration:    time.Since(startTime),
		Details: map[string]interface{}{
			"requested_scopes": config.Scopes,
		},
	}
}

func (v *OBUKVerifier) testIntentBasedAuthorization(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	// UK Open Banking requires intent-based authorization for payments and account access
	hasPaymentScope := false
	hasAccountScope := false

	for _, scope := range config.Scopes {
		if strings.Contains(strings.ToLower(scope), "payment") {
			hasPaymentScope = true
		}
		if strings.Contains(strings.ToLower(scope), "account") {
			hasAccountScope = true
		}
	}

	if hasPaymentScope || hasAccountScope {
		// Intent registration should be tested, but this requires API integration
		return verifier.TestResult{
			Name:        "Intent-based Authorization",
			Description: "Verify intent registration for account/payment access",
			Status:      verifier.StatusSkip,
			Duration:    time.Since(startTime),
			Error:       "Intent registration testing requires API integration",
		}
	}

	return verifier.TestResult{
		Name:        "Intent-based Authorization",
		Description: "Verify intent registration for account/payment access",
		Status:      verifier.StatusSkip,
		Duration:    time.Since(startTime),
		Error:       "No account or payment scopes requested",
	}
}

func (v *OBUKVerifier) testStrongCustomerAuthentication(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	// SCA requirements under PSD2
	return verifier.TestResult{
		Name:        "Strong Customer Authentication (SCA)",
		Description: "Verify PSD2 Strong Customer Authentication compliance",
		Status:      verifier.StatusSkip,
		Duration:    time.Since(startTime),
		Error:       "SCA testing requires customer authentication flow",
	}
}

func (v *OBUKVerifier) testAccountRequestPermissions(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	// Check account access permissions structure
	hasAccountScope := false
	for _, scope := range config.Scopes {
		if strings.Contains(strings.ToLower(scope), "account") {
			hasAccountScope = true
			break
		}
	}

	if !hasAccountScope {
		return verifier.TestResult{
			Name:        "Account Request Permissions",
			Description: "Verify account request permissions structure",
			Status:      verifier.StatusSkip,
			Duration:    time.Since(startTime),
			Error:       "No account scopes requested",
		}
	}

	return verifier.TestResult{
		Name:        "Account Request Permissions",
		Description: "Verify account request permissions structure",
		Status:      verifier.StatusSkip,
		Duration:    time.Since(startTime),
		Error:       "Account permissions testing requires API integration",
	}
}

func (v *OBUKVerifier) testPaymentInitiationSecurity(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	// Check payment initiation security requirements
	hasPaymentScope := false
	for _, scope := range config.Scopes {
		if strings.Contains(strings.ToLower(scope), "payment") {
			hasPaymentScope = true
			break
		}
	}

	if !hasPaymentScope {
		return verifier.TestResult{
			Name:        "Payment Initiation Security",
			Description: "Verify payment initiation security requirements",
			Status:      verifier.StatusSkip,
			Duration:    time.Since(startTime),
			Error:       "No payment scopes requested",
		}
	}

	// Check security requirements for payments
	securityIssues := []string{}

	if config.MTLSCert == "" && config.PrivateKeyJWTKey == "" {
		securityIssues = append(securityIssues, "Strong client authentication required for payments")
	}

	if len(securityIssues) > 0 {
		return verifier.TestResult{
			Name:        "Payment Initiation Security",
			Description: "Verify payment initiation security requirements",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       strings.Join(securityIssues, "; "),
		}
	}

	return verifier.TestResult{
		Name:        "Payment Initiation Security",
		Description: "Verify payment initiation security requirements",
		Status:      verifier.StatusPass,
		Duration:    time.Since(startTime),
	}
}

func (v *OBUKVerifier) testDirectoryCertificateValidation(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	// UK Open Banking requires certificates from the OBIE Directory
	if config.MTLSCert == "" {
		return verifier.TestResult{
			Name:        "Directory Certificate Validation",
			Description: "Verify certificate is from OBIE Directory",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       "UK Open Banking requires OBIE Directory certificates",
		}
	}

	return verifier.TestResult{
		Name:        "Directory Certificate Validation",
		Description: "Verify certificate is from OBIE Directory",
		Status:      verifier.StatusSkip,
		Duration:    time.Since(startTime),
		Error:       "Directory certificate validation requires certificate parsing",
	}
}

func (v *OBUKVerifier) testCustomerAuthenticationMethods(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	// Test customer authentication methods compliance
	return verifier.TestResult{
		Name:        "Customer Authentication Methods",
		Description: "Verify customer authentication methods compliance",
		Status:      verifier.StatusSkip,
		Duration:    time.Since(startTime),
		Error:       "Customer authentication testing requires bank integration",
	}
}

func (v *OBUKVerifier) testDataClusterPermissions(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	// Test UK Open Banking data cluster permissions
	return verifier.TestResult{
		Name:        "Data Cluster Permissions",
		Description: "Verify data cluster permissions are properly structured",
		Status:      verifier.StatusSkip,
		Duration:    time.Since(startTime),
		Error:       "Data cluster testing requires permission structure analysis",
	}
}

func (v *OBUKVerifier) calculateSummary(tests []verifier.TestResult) verifier.TestSummary {
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
