package regional

import (
	"context"
	"strings"
	"time"

	httpClient "fapictl/pkg/http"
	"fapictl/pkg/verifier"
)

type OpenFinanceBRVerifier struct {
	client *httpClient.Client
}

func NewOpenFinanceBRVerifier(client *httpClient.Client) *OpenFinanceBRVerifier {
	return &OpenFinanceBRVerifier{
		client: client,
	}
}

func (v *OpenFinanceBRVerifier) Name() string {
	return "Brazil Open Finance"
}

func (v *OpenFinanceBRVerifier) Description() string {
	return "Verifies Brazil Open Finance (Sistema Financeiro Aberto) security profile compliance"
}

func (v *OpenFinanceBRVerifier) Verify(ctx context.Context, config verifier.VerifierConfig) (*verifier.TestSuite, error) {
	suite := &verifier.TestSuite{
		Name:        v.Name(),
		Description: v.Description(),
		Tests:       []verifier.TestResult{},
	}

	startTime := time.Now()

	// Test 1: Brazil Open Finance Scopes
	suite.Tests = append(suite.Tests, v.testBrazilOpenFinanceScopes(config))

	// Test 2: CPF/CNPJ Authorization
	suite.Tests = append(suite.Tests, v.testCPFCNPJAuthorization(config))

	// Test 3: Consent Management (Brazilian Requirements)
	suite.Tests = append(suite.Tests, v.testBrazilianConsentManagement(config))

	// Test 4: Directory Certificate (Brazil)
	suite.Tests = append(suite.Tests, v.testBrazilDirectoryCertificate(config))

	// Test 5: PIX Integration Requirements
	suite.Tests = append(suite.Tests, v.testPIXIntegrationRequirements(config))

	// Test 6: LGPD Compliance
	suite.Tests = append(suite.Tests, v.testLGPDCompliance(config))

	// Test 7: Dynamic Client Registration
	suite.Tests = append(suite.Tests, v.testDynamicClientRegistration(config))

	// Test 8: Operational Risk Requirements
	suite.Tests = append(suite.Tests, v.testOperationalRiskRequirements(config))

	suite.Duration = time.Since(startTime)
	suite.Summary = v.calculateSummary(suite.Tests)

	return suite, nil
}

func (v *OpenFinanceBRVerifier) testBrazilOpenFinanceScopes(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	// Check for Brazil Open Finance specific scopes
	brazilScopes := []string{
		"accounts", "credit-cards-accounts", "loans", "financings",
		"unarranged-accounts-overdraft", "invoice-financings",
		"payments", "consents", "resources", "customers",
	}

	hasBrazilScope := false
	foundScopes := []string{}

	for _, scope := range config.Scopes {
		for _, brazilScope := range brazilScopes {
			if strings.Contains(strings.ToLower(scope), brazilScope) {
				hasBrazilScope = true
				foundScopes = append(foundScopes, scope)
			}
		}
	}

	if !hasBrazilScope {
		return verifier.TestResult{
			Name:        "Brazil Open Finance Scopes",
			Description: "Verify Brazil Open Finance specific scopes are requested",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       "No Brazil Open Finance scopes found",
		}
	}

	return verifier.TestResult{
		Name:        "Brazil Open Finance Scopes",
		Description: "Verify Brazil Open Finance specific scopes are requested",
		Status:      verifier.StatusPass,
		Duration:    time.Since(startTime),
		Details: map[string]interface{}{
			"brazil_scopes_found": foundScopes,
			"total_scopes":        len(config.Scopes),
		},
	}
}

func (v *OpenFinanceBRVerifier) testCPFCNPJAuthorization(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	// Brazil Open Finance requires CPF/CNPJ identification
	return verifier.TestResult{
		Name:        "CPF/CNPJ Authorization",
		Description: "Verify CPF/CNPJ identification in authorization flow",
		Status:      verifier.StatusSkip,
		Duration:    time.Since(startTime),
		Error:       "CPF/CNPJ validation requires customer identification flow",
	}
}

func (v *OpenFinanceBRVerifier) testBrazilianConsentManagement(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	// Brazilian consent management has specific requirements
	return verifier.TestResult{
		Name:        "Brazilian Consent Management",
		Description: "Verify Brazilian consent management requirements",
		Status:      verifier.StatusSkip,
		Duration:    time.Since(startTime),
		Error:       "Consent management testing requires API integration",
	}
}

func (v *OpenFinanceBRVerifier) testBrazilDirectoryCertificate(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	// Check for directory certificate from Brazilian authorities
	if config.MTLSCert == "" {
		return verifier.TestResult{
			Name:        "Brazil Directory Certificate",
			Description: "Verify certificate is from Brazilian directory authority",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       "Brazil Open Finance requires certificates from authorized directory",
		}
	}

	return verifier.TestResult{
		Name:        "Brazil Directory Certificate",
		Description: "Verify certificate is from Brazilian directory authority",
		Status:      verifier.StatusSkip,
		Duration:    time.Since(startTime),
		Error:       "Directory certificate validation requires certificate parsing",
	}
}

func (v *OpenFinanceBRVerifier) testPIXIntegrationRequirements(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	// Check for PIX payment integration requirements
	hasPaymentScope := false
	for _, scope := range config.Scopes {
		if strings.Contains(strings.ToLower(scope), "payment") {
			hasPaymentScope = true
			break
		}
	}

	if !hasPaymentScope {
		return verifier.TestResult{
			Name:        "PIX Integration Requirements",
			Description: "Verify PIX instant payment integration requirements",
			Status:      verifier.StatusSkip,
			Duration:    time.Since(startTime),
			Error:       "No payment scopes requested",
		}
	}

	return verifier.TestResult{
		Name:        "PIX Integration Requirements",
		Description: "Verify PIX instant payment integration requirements",
		Status:      verifier.StatusSkip,
		Duration:    time.Since(startTime),
		Error:       "PIX integration testing requires payment API integration",
	}
}

func (v *OpenFinanceBRVerifier) testLGPDCompliance(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	// LGPD (Lei Geral de Proteção de Dados) compliance requirements
	return verifier.TestResult{
		Name:        "LGPD Compliance",
		Description: "Verify LGPD (Brazilian data protection law) compliance",
		Status:      verifier.StatusSkip,
		Duration:    time.Since(startTime),
		Error:       "LGPD compliance testing requires data handling analysis",
	}
}

func (v *OpenFinanceBRVerifier) testDynamicClientRegistration(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	// Test dynamic client registration capabilities
	return verifier.TestResult{
		Name:        "Dynamic Client Registration",
		Description: "Verify dynamic client registration compliance",
		Status:      verifier.StatusSkip,
		Duration:    time.Since(startTime),
		Error:       "Dynamic client registration testing requires DCR endpoint",
	}
}

func (v *OpenFinanceBRVerifier) testOperationalRiskRequirements(config verifier.VerifierConfig) verifier.TestResult {
	startTime := time.Now()

	// Brazilian operational risk management requirements
	securityIssues := []string{}

	// Check for strong authentication
	if config.MTLSCert == "" && config.PrivateKeyJWTKey == "" {
		securityIssues = append(securityIssues, "Strong client authentication required for operational risk management")
	}

	// Check HTTPS enforcement
	endpoints := []string{config.AuthorizationEndpoint, config.TokenEndpoint}
	for _, endpoint := range endpoints {
		if endpoint != "" && !strings.HasPrefix(endpoint, "https://") {
			securityIssues = append(securityIssues, "All endpoints must use HTTPS for operational risk compliance")
			break
		}
	}

	if len(securityIssues) > 0 {
		return verifier.TestResult{
			Name:        "Operational Risk Requirements",
			Description: "Verify operational risk management requirements",
			Status:      verifier.StatusFail,
			Duration:    time.Since(startTime),
			Error:       strings.Join(securityIssues, "; "),
		}
	}

	return verifier.TestResult{
		Name:        "Operational Risk Requirements",
		Description: "Verify operational risk management requirements",
		Status:      verifier.StatusPass,
		Duration:    time.Since(startTime),
		Details: map[string]interface{}{
			"strong_auth_configured": config.MTLSCert != "" || config.PrivateKeyJWTKey != "",
			"https_enforced":         true,
		},
	}
}

func (v *OpenFinanceBRVerifier) calculateSummary(tests []verifier.TestResult) verifier.TestSummary {
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
