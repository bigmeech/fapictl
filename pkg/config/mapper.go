package config

import "fapictl/pkg/verifier"

// ToVerifierConfig converts a Config to a VerifierConfig for use with verifiers
func (c *Config) ToVerifierConfig() verifier.VerifierConfig {
	return verifier.VerifierConfig{
		ClientID:              c.ClientID,
		RedirectURI:           c.RedirectURI,
		AuthorizationEndpoint: c.AuthorizationEndpoint,
		TokenEndpoint:         c.TokenEndpoint,
		PAREndpoint:           c.PAREndpoint,
		IntrospectionEndpoint: c.IntrospectionEndpoint,
		JWKSURI:               c.JWKSURI,
		OIDCConfig:            c.OIDCConfig,
		Scopes:                c.Scopes,
		MTLSCert:              c.MTLS.Cert,
		MTLSKey:               c.MTLS.Key,
		PrivateKeyJWTKey:      c.PrivateKeyJWT.Key,
		PrivateKeyJWTKID:      c.PrivateKeyJWT.Kid,
		AdditionalParams:      make(map[string]string),
	}
}

// GetProfilesOrLegacy returns the profiles array or converts legacy profile field
func (c *Config) GetProfilesOrLegacy() []string {
	if len(c.Profiles) > 0 {
		return c.Profiles
	}

	if c.Profile != "" {
		return []string{c.Profile}
	}

	return []string{}
}
