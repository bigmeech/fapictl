package config

import (
	"fmt"
	"net/url"
	"os"

	yaml "gopkg.in/yaml.v3"
)

type Config struct {
	Profile               string              `yaml:"profile"`  // Legacy single profile
	Profiles              []string            `yaml:"profiles"` // New multiple profiles support
	ClientID              string              `yaml:"client_id"`
	RedirectURI           string              `yaml:"redirect_uri"`
	AuthorizationEndpoint string              `yaml:"authorization_endpoint"`
	TokenEndpoint         string              `yaml:"token_endpoint"`
	PAREndpoint           string              `yaml:"par_endpoint"`
	IntrospectionEndpoint string              `yaml:"introspection_endpoint"`
	JWKSURI               string              `yaml:"jwks_uri"`
	OIDCConfig            string              `yaml:"oidc_config"`
	MTLS                  MTLSConfig          `yaml:"mtls"`
	PrivateKeyJWT         PrivateKeyJWTConfig `yaml:"private_key_jwt"`
	Scopes                []string            `yaml:"scopes"`
}

type MTLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

type PrivateKeyJWTConfig struct {
	Kid string `yaml:"kid"`
	Key string `yaml:"key"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

func (c *Config) Validate() error {
	if c.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}
	if c.AuthorizationEndpoint == "" {
		return fmt.Errorf("authorization_endpoint is required")
	}
	if c.TokenEndpoint == "" {
		return fmt.Errorf("token_endpoint is required")
	}

	// Validate URL format for endpoints
	if c.AuthorizationEndpoint != "" {
		u, err := url.Parse(c.AuthorizationEndpoint)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("invalid authorization_endpoint URL")
		}
	}
	if c.TokenEndpoint != "" {
		u, err := url.Parse(c.TokenEndpoint)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("invalid token_endpoint URL")
		}
	}

	return nil
}
