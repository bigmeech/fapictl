# config/ Package

The config package provides configuration file parsing, validation, and management for fapictl. It supports both legacy single-profile and modern multi-profile configurations.

## Purpose

- Parse YAML configuration files containing OAuth2/OIDC server details
- Validate configuration completeness and correctness
- Support both legacy single-profile and new multi-profile configurations
- Provide type-safe access to configuration values

## Key Components

### `Config` struct
The main configuration structure that maps to the YAML file format:

```go
type Config struct {
    Profile               string   // Legacy single profile
    Profiles              []string // New multiple profiles support
    ClientID              string   // OAuth2 client identifier
    RedirectURI           string   // OAuth2 redirect URI
    AuthorizationEndpoint string   // OAuth2 authorization endpoint
    TokenEndpoint         string   // OAuth2 token endpoint
    PAREndpoint           string   // Pushed Authorization Request endpoint
    IntrospectionEndpoint string   // Token introspection endpoint
    JWKSURI               string   // JSON Web Key Set URI
    OIDCConfig            string   // OpenID Connect discovery endpoint
    MTLS                  MTLSConfig // Mutual TLS configuration
    PrivateKeyJWT         PrivateKeyJWTConfig // Private key JWT config
    Scopes                []string // OAuth2 scopes to request
}
```

### `MTLSConfig` struct
Configuration for mutual TLS client authentication:

```go
type MTLSConfig struct {
    Cert string // Path to client certificate file
    Key  string // Path to client private key file
}
```

### `PrivateKeyJWTConfig` struct
Configuration for private_key_jwt client authentication:

```go
type PrivateKeyJWTConfig struct {
    Kid string // Key identifier (kid claim)
    Key string // Path to private key file
}
```

## Functions

### `LoadConfig(path string) (*Config, error)`
Loads and parses a YAML configuration file from the specified path.

**Parameters:**
- `path`: Absolute path to the YAML configuration file

**Returns:**
- `*Config`: Parsed configuration struct
- `error`: Any parsing or file access errors

**Example:**
```go
cfg, err := config.LoadConfig("/path/to/fapictl.yaml")
if err != nil {
    log.Fatal("Failed to load config:", err)
}
```

### `(*Config) Validate() error`
Validates that required configuration fields are present and properly formatted.

**Validation Rules:**
- `client_id` must be non-empty
- `authorization_endpoint` must be non-empty
- `token_endpoint` must be non-empty
- URLs must be valid and use HTTPS (recommended for production)

**Example:**
```go
if err := cfg.Validate(); err != nil {
    log.Fatal("Invalid configuration:", err)
}
```

## Configuration File Format

### Modern Multi-Profile Configuration
```yaml
# Multiple profiles (recommended)
profiles:
  - oauth2-pkce      # OAuth2 baseline
  - fapi-ro          # FAPI Read-Only
  - mtls             # Mutual TLS
  - jar              # JWT Authorization Request

client_id: "your-client-id"
redirect_uri: "https://your-app.com/callback"

authorization_endpoint: "https://authserver.com/oauth2/authorize"
token_endpoint: "https://authserver.com/oauth2/token"
par_endpoint: "https://authserver.com/oauth2/par"
introspection_endpoint: "https://authserver.com/oauth2/introspect"
jwks_uri: "https://authserver.com/.well-known/jwks.json"
oidc_config: "https://authserver.com/.well-known/openid-configuration"

# Optional: Mutual TLS configuration
mtls:
  cert: "./certs/client.crt"
  key: "./certs/client.key"

# Optional: Private Key JWT configuration
private_key_jwt:
  kid: "key1"
  key: "./keys/private.pem"

scopes:
  - openid
  - accounts
  - transactions
```

### Legacy Single-Profile Configuration
```yaml
# Single profile (legacy, still supported)
profile: fapi-ro

client_id: "your-client-id"
# ... rest of configuration
```

## Configuration Priority

The configuration loading follows this priority order:

1. **Command-line profiles flag**: `--profiles oauth2-pkce,fapi-ro,mtls`
2. **Command-line profile flag**: `--profile fapi-ro` 
3. **Config file profiles array**: `profiles: [oauth2-pkce, fapi-ro]`
4. **Config file legacy profile**: `profile: fapi-ro`
5. **Default**: `oauth2-pkce` (basic OAuth2 + PKCE)

## Security Considerations

### Recommended Practices
- Always use HTTPS endpoints in production
- Store certificates and private keys securely
- Use relative paths for certificate files within secure directory structures
- Validate certificate chains and expiry dates
- Rotate keys and certificates regularly

### Sensitive Data Handling
- Private keys and certificates are referenced by file paths, not embedded in config
- No secrets are logged or exposed in error messages
- Configuration validation checks for common security misconfigurations

## Error Handling

The package provides detailed error messages for common configuration issues:

- **File not found**: Clear path resolution errors
- **YAML parsing errors**: Line and column information for syntax issues
- **Validation errors**: Specific field names and requirements
- **URL format errors**: Validation of endpoint URLs

## Testing

Example test configuration for development/testing:

```yaml
profiles:
  - oauth2-pkce
  - fapi-ro

client_id: "test-client"
redirect_uri: "https://localhost:8080/callback"
authorization_endpoint: "https://demo.authserver.com/oauth2/authorize"
token_endpoint: "https://demo.authserver.com/oauth2/token"

scopes:
  - openid
  - profile
```

## Integration

The config package is typically used by:

1. **CLI commands** to load user-specified configuration files
2. **Profile verifiers** to access endpoint URLs and authentication details
3. **Test runners** to configure HTTP clients and validation parameters

```go
// Typical usage pattern
cfg, err := config.LoadConfig(configFile)
if err != nil {
    return fmt.Errorf("config loading failed: %w", err)
}

if err := cfg.Validate(); err != nil {
    return fmt.Errorf("config validation failed: %w", err)
}

// Use cfg.AuthorizationEndpoint, cfg.ClientID, etc.
```