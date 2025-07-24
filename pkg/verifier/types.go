package verifier

import (
	"context"
	"time"
)

type TestResult struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Status      TestStatus    `json:"status"`
	Duration    time.Duration `json:"duration"`
	Error       string        `json:"error,omitempty"`
	Details     interface{}   `json:"details,omitempty"`
}

type TestStatus string

const (
	StatusPass TestStatus = "PASS"
	StatusFail TestStatus = "FAIL"
	StatusSkip TestStatus = "SKIP"
)

type TestSuite struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Tests       []TestResult  `json:"tests"`
	Duration    time.Duration `json:"duration"`
	Summary     TestSummary   `json:"summary"`
}

type TestSummary struct {
	Total   int `json:"total"`
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Skipped int `json:"skipped"`
}

type Verifier interface {
	Name() string
	Description() string
	Verify(ctx context.Context, config VerifierConfig) (*TestSuite, error)
}

type VerifierConfig struct {
	ClientID              string            `json:"client_id"`
	ClientSecret          string            `json:"client_secret,omitempty"`
	RedirectURI           string            `json:"redirect_uri"`
	AuthorizationEndpoint string            `json:"authorization_endpoint"`
	TokenEndpoint         string            `json:"token_endpoint"`
	PAREndpoint           string            `json:"par_endpoint,omitempty"`
	IntrospectionEndpoint string            `json:"introspection_endpoint,omitempty"`
	JWKSURI               string            `json:"jwks_uri,omitempty"`
	OIDCConfig            string            `json:"oidc_config,omitempty"`
	Scopes                []string          `json:"scopes"`
	MTLSCert              string            `json:"mtls_cert,omitempty"`
	MTLSKey               string            `json:"mtls_key,omitempty"`
	PrivateKeyJWTKey      string            `json:"private_key_jwt_key,omitempty"`
	PrivateKeyJWTKID      string            `json:"private_key_jwt_kid,omitempty"`
	AdditionalParams      map[string]string `json:"additional_params,omitempty"`
}

type TestRunner struct {
	verifiers []Verifier
	config    VerifierConfig
}

func NewTestRunner(config VerifierConfig) *TestRunner {
	return &TestRunner{
		config: config,
	}
}

func (tr *TestRunner) AddVerifier(v Verifier) {
	tr.verifiers = append(tr.verifiers, v)
}

func (tr *TestRunner) RunAll(ctx context.Context) ([]*TestSuite, error) {
	var results []*TestSuite

	for _, verifier := range tr.verifiers {
		suite, err := verifier.Verify(ctx, tr.config)
		if err != nil {
			return nil, err
		}
		results = append(results, suite)
	}

	return results, nil
}
