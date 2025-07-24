package profiles

import (
	"context"

	httpClient "fapictl/pkg/http"
	"fapictl/pkg/profiles/mandatory"
	"fapictl/pkg/profiles/optional"
	"fapictl/pkg/profiles/regional"
	"fapictl/pkg/verifier"
)

func init() {
	// Register mandatory profiles
	registerMandatoryProfiles()

	// Register optional profiles
	registerOptionalProfiles()

	// Register regional profiles
	registerRegionalProfiles()
}

func registerMandatoryProfiles() {
	// OAuth2 Authorization Code with PKCE (baseline)
	DefaultRegistry.Register(&ProfileInfo{
		ID:          "oauth2-pkce",
		Name:        "OAuth2 Authorization Code + PKCE",
		Description: "OAuth 2.0 Authorization Code flow with PKCE (RFC 7636)",
		Type:        Mandatory,
		Factory: func(client *httpClient.Client) verifier.Verifier {
			return mandatory.NewAuthCodePKCEVerifier(client)
		},
	})

	// FAPI Read-Only Profile
	DefaultRegistry.Register(&ProfileInfo{
		ID:           "fapi-ro",
		Name:         "FAPI Read-Only Profile",
		Description:  "Financial-grade API Read-Only security profile",
		Type:         Mandatory,
		Dependencies: []string{"oauth2-pkce"},
		Factory: func(client *httpClient.Client) verifier.Verifier {
			return mandatory.NewFAPIReadOnlyVerifier(client)
		},
	})

	// FAPI Read-Write Profile
	DefaultRegistry.Register(&ProfileInfo{
		ID:           "fapi-rw",
		Name:         "FAPI Read-Write Profile",
		Description:  "Financial-grade API Read-Write security profile (includes payment initiation)",
		Type:         Mandatory,
		Dependencies: []string{"oauth2-pkce", "fapi-ro"},
		Factory: func(client *httpClient.Client) verifier.Verifier {
			return mandatory.NewFAPIReadWriteVerifier(client)
		},
	})
}

func registerOptionalProfiles() {
	// Client-Initiated Backchannel Authentication (CIBA)
	DefaultRegistry.Register(&ProfileInfo{
		ID:          "ciba",
		Name:        "Client-Initiated Backchannel Authentication",
		Description: "CIBA flow for decoupled authentication scenarios",
		Type:        Optional,
		Factory: func(client *httpClient.Client) verifier.Verifier {
			// TODO: Implement CIBAVerifier
			return &NoOpVerifier{name: "CIBA", description: "CIBA verifier not yet implemented"}
		},
	})

	// Demonstration of Proof-of-Possession (DPoP)
	DefaultRegistry.Register(&ProfileInfo{
		ID:          "dpop",
		Name:        "Demonstration of Proof-of-Possession",
		Description: "DPoP token binding mechanism",
		Type:        Optional,
		Factory: func(client *httpClient.Client) verifier.Verifier {
			// TODO: Implement DPoPVerifier
			return &NoOpVerifier{name: "DPoP", description: "DPoP verifier not yet implemented"}
		},
	})

	// Mutual TLS
	DefaultRegistry.Register(&ProfileInfo{
		ID:          "mtls",
		Name:        "Mutual TLS",
		Description: "Mutual TLS client certificate authentication",
		Type:        Optional,
		Factory: func(client *httpClient.Client) verifier.Verifier {
			return optional.NewMTLSVerifier(client)
		},
	})

	// JWT Secured Authorization Request (JAR)
	DefaultRegistry.Register(&ProfileInfo{
		ID:          "jar",
		Name:        "JWT Secured Authorization Request",
		Description: "JAR for securing authorization request parameters",
		Type:        Optional,
		Factory: func(client *httpClient.Client) verifier.Verifier {
			return optional.NewJARVerifier(client)
		},
	})

	// JWT Secured Authorization Response Mode (JARM)
	DefaultRegistry.Register(&ProfileInfo{
		ID:          "jarm",
		Name:        "JWT Secured Authorization Response Mode",
		Description: "JARM for securing authorization response parameters",
		Type:        Optional,
		Factory: func(client *httpClient.Client) verifier.Verifier {
			// TODO: Implement JARMVerifier
			return &NoOpVerifier{name: "JARM", description: "JARM verifier not yet implemented"}
		},
	})

	// Pushed Authorization Requests (PAR)
	DefaultRegistry.Register(&ProfileInfo{
		ID:          "par",
		Name:        "Pushed Authorization Requests",
		Description: "PAR for pre-registering authorization request parameters",
		Type:        Optional,
		Factory: func(client *httpClient.Client) verifier.Verifier {
			return optional.NewPARVerifier(client)
		},
	})
}

func registerRegionalProfiles() {
	// UK Open Banking
	DefaultRegistry.Register(&ProfileInfo{
		ID:           "ob-uk",
		Name:         "UK Open Banking",
		Description:  "UK Open Banking Implementation Entity (OBIE) security profile",
		Type:         Regional,
		Dependencies: []string{"fapi-rw", "mtls", "jar"},
		Factory: func(client *httpClient.Client) verifier.Verifier {
			return regional.NewOBUKVerifier(client)
		},
	})

	// Brazil Open Finance
	DefaultRegistry.Register(&ProfileInfo{
		ID:           "open-finance-br",
		Name:         "Brazil Open Finance",
		Description:  "Brazil Open Finance (Sistema Financeiro Aberto) security profile",
		Type:         Regional,
		Dependencies: []string{"fapi-rw", "mtls", "jar"},
		Factory: func(client *httpClient.Client) verifier.Verifier {
			return regional.NewOpenFinanceBRVerifier(client)
		},
	})

	// Berlin Group NextGenPSD2
	DefaultRegistry.Register(&ProfileInfo{
		ID:           "berlin-group",
		Name:         "Berlin Group NextGenPSD2",
		Description:  "Berlin Group NextGenPSD2 XS2A Framework",
		Type:         Regional,
		Dependencies: []string{"fapi-ro"},
		Factory: func(client *httpClient.Client) verifier.Verifier {
			// TODO: Implement BerlinGroupVerifier
			return &NoOpVerifier{name: "Berlin Group", description: "Berlin Group verifier not yet implemented"}
		},
	})

	// Australian CDR
	DefaultRegistry.Register(&ProfileInfo{
		ID:           "cdr-au",
		Name:         "Australian Consumer Data Right",
		Description:  "Australian CDR security profile",
		Type:         Regional,
		Dependencies: []string{"fapi-rw", "mtls", "jar"},
		Factory: func(client *httpClient.Client) verifier.Verifier {
			// TODO: Implement CDRAUVerifier
			return &NoOpVerifier{name: "Australian CDR", description: "Australian CDR verifier not yet implemented"}
		},
	})

	// Nigerian Open Banking
	DefaultRegistry.Register(&ProfileInfo{
		ID:           "open-banking-ng",
		Name:         "Nigerian Open Banking",
		Description:  "Nigerian Open Banking security profile",
		Type:         Regional,
		Dependencies: []string{"fapi-ro"},
		Factory: func(client *httpClient.Client) verifier.Verifier {
			// TODO: Implement NigerianOBVerifier
			return &NoOpVerifier{name: "Nigerian Open Banking", description: "Nigerian Open Banking verifier not yet implemented"}
		},
	})
}

// NoOpVerifier is a placeholder for unimplemented verifiers
type NoOpVerifier struct {
	name        string
	description string
}

func (v *NoOpVerifier) Name() string {
	return v.name
}

func (v *NoOpVerifier) Description() string {
	return v.description
}

func (v *NoOpVerifier) Verify(ctx context.Context, config verifier.VerifierConfig) (*verifier.TestSuite, error) {
	return &verifier.TestSuite{
		Name:        v.name,
		Description: v.description,
		Tests: []verifier.TestResult{
			{
				Name:        "Implementation Status",
				Description: "Check if verifier is implemented",
				Status:      verifier.StatusSkip,
				Error:       "This verifier is not yet implemented",
			},
		},
		Summary: verifier.TestSummary{
			Total:   1,
			Skipped: 1,
		},
	}, nil
}
