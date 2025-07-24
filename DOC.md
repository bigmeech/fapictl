# fapictl Configuration Documentation

This document provides comprehensive documentation for all configuration values supported by fapictl, including their purposes, requirements, validation rules, and usage examples.

## Table of Contents

1. [Configuration File Format](#configuration-file-format)
2. [Core Configuration](#core-configuration)
3. [Profile Configuration](#profile-configuration)
4. [OAuth2/OIDC Endpoints](#oauth2oidc-endpoints)
5. [Client Authentication](#client-authentication)
6. [Scope Configuration](#scope-configuration)
7. [Regional-Specific Configuration](#regional-specific-configuration)
8. [Validation Rules](#validation-rules)
9. [Configuration Examples](#configuration-examples)
10. [Environment Variable Support](#environment-variable-support)
11. [Security Best Practices](#security-best-practices)
12. [Troubleshooting](#troubleshooting)

## Configuration File Format

fapictl uses YAML configuration files. The configuration file must be valid YAML and contain the required fields for your testing scenario.

### Basic Structure
```yaml
# Profile selection (choose one approach)
profile: "profile-name"              # Legacy single profile
profiles: ["profile1", "profile2"]   # Modern multi-profile approach

# Client identification
client_id: "your-client-identifier"
client_secret: "optional-client-secret"
redirect_uri: "https://your-app.com/callback"

# OAuth2/OIDC endpoints
authorization_endpoint: "https://authserver.com/oauth2/authorize"
token_endpoint: "https://authserver.com/oauth2/token"
# ... additional configuration
```

## Core Configuration

### `client_id` (Required)
**Type**: String  
**Purpose**: OAuth2 client identifier registered with the authorization server  
**Validation**: Must be non-empty string  
**Example**: `"my-fapi-client-2024"`  

```yaml
client_id: "banking-app-client-id"
```

**Notes**:
- This is your registered client identifier from the authorization server
- Must match exactly what was registered (case-sensitive)
- Used in all OAuth2 flows for client identification

### `client_secret` (Optional)
**Type**: String  
**Purpose**: OAuth2 client secret for confidential clients  
**Validation**: Optional, but required for some client authentication methods  
**Security**: Should be kept secure and not committed to version control  

```yaml
client_secret: "${CLIENT_SECRET}"  # Use environment variable
```

**Notes**:
- Only required for confidential clients using `client_secret_basic` or `client_secret_post`
- Not used when using mTLS or private_key_jwt authentication
- Should be stored securely (environment variables, secrets management)

### `redirect_uri` (Required)
**Type**: String  
**Purpose**: OAuth2 redirect URI where authorization responses are sent  
**Validation**: Must be a valid HTTPS URL (HTTP allowed for localhost testing)  
**Example**: `"https://myapp.example.com/oauth/callback"`  

```yaml
redirect_uri: "https://banking-app.com/auth/callback"
```

**Notes**:
- Must exactly match a URI registered with the authorization server
- HTTPS is required for production (FAPI requirement)
- Localhost HTTP URIs allowed for development/testing
- Can include port numbers and paths

## Profile Configuration

### `profile` (Legacy, Optional)
**Type**: String  
**Purpose**: Single profile to test (legacy configuration)  
**Valid Values**: Any registered profile ID  
**Deprecated**: Use `profiles` array instead  

```yaml
profile: "fapi-ro"
```

### `profiles` (Recommended)
**Type**: Array of Strings  
**Purpose**: Multiple profiles to test in a single run  
**Valid Values**: Array of registered profile IDs  
**Dependency Resolution**: Automatically resolves and validates dependencies  

```yaml
profiles:
  - "oauth2-pkce"      # OAuth2 baseline
  - "fapi-ro"          # FAPI Read-Only
  - "mtls"             # Mutual TLS
  - "jar"              # JWT Authorization Request
```

**Available Profile IDs**:

#### Mandatory Profiles
- `oauth2-pkce`: OAuth2 Authorization Code + PKCE
- `fapi-ro`: FAPI Read-Only Profile  
- `fapi-rw`: FAPI Read-Write Profile

#### Optional Profiles
- `mtls`: Mutual TLS Authentication
- `jar`: JWT Secured Authorization Request
- `par`: Pushed Authorization Requests
- `ciba`: Client-Initiated Backchannel Authentication (placeholder)
- `dpop`: Demonstration of Proof-of-Possession (placeholder)
- `jarm`: JWT Secured Authorization Response Mode (placeholder)

#### Regional Profiles
- `ob-uk`: UK Open Banking
- `open-finance-br`: Brazil Open Finance
- `berlin-group`: Berlin Group NextGenPSD2 (placeholder)
- `cdr-au`: Australian Consumer Data Right (placeholder)
- `open-banking-ng`: Nigerian Open Banking (placeholder)

## OAuth2/OIDC Endpoints

### `authorization_endpoint` (Required)
**Type**: String (URL)  
**Purpose**: OAuth2 authorization endpoint URL  
**Validation**: Must be valid HTTPS URL  
**FAPI Requirement**: HTTPS mandatory  

```yaml
authorization_endpoint: "https://bank.example.com/oauth2/authorize"
```

### `token_endpoint` (Required)
**Type**: String (URL)  
**Purpose**: OAuth2 token endpoint URL  
**Validation**: Must be valid HTTPS URL  
**FAPI Requirement**: HTTPS mandatory  

```yaml
token_endpoint: "https://bank.example.com/oauth2/token"
```

### `par_endpoint` (Optional)
**Type**: String (URL)  
**Purpose**: Pushed Authorization Request endpoint URL  
**Validation**: Must be valid HTTPS URL if provided  
**Required For**: PAR profile testing  

```yaml
par_endpoint: "https://bank.example.com/oauth2/par"
```

### `introspection_endpoint` (Optional)
**Type**: String (URL)  
**Purpose**: OAuth2 token introspection endpoint URL  
**Validation**: Must be valid HTTPS URL if provided  
**Used For**: Token validation testing  

```yaml
introspection_endpoint: "https://bank.example.com/oauth2/introspect"
```

### `jwks_uri` (Optional)
**Type**: String (URL)  
**Purpose**: JSON Web Key Set endpoint URL  
**Validation**: Must be valid HTTPS URL if provided  
**Required For**: JWT signature verification, JAR profile  

```yaml
jwks_uri: "https://bank.example.com/.well-known/jwks.json"
```

### `oidc_config` (Optional)
**Type**: String (URL)  
**Purpose**: OpenID Connect discovery document URL  
**Validation**: Must be valid HTTPS URL if provided  
**Used For**: Automatic endpoint discovery, metadata validation  

```yaml
oidc_config: "https://bank.example.com/.well-known/openid-configuration"
```

## Client Authentication

fapictl supports multiple client authentication methods as required by FAPI specifications.

### Mutual TLS (mTLS)

#### `mtls.cert` (Optional)
**Type**: String (File Path)  
**Purpose**: Path to client certificate file for mTLS authentication  
**Format**: PEM-encoded X.509 certificate  
**Required For**: mTLS profile, FAPI-RW strong authentication  

#### `mtls.key` (Optional)
**Type**: String (File Path)  
**Purpose**: Path to client private key file for mTLS authentication  
**Format**: PEM-encoded private key (RSA, ECDSA, or Ed25519)  
**Security**: Must be kept secure with appropriate file permissions (600)  

```yaml
mtls:
  cert: "./certs/client.crt"
  key: "./certs/client.key"
```

**File Format Example (client.crt)**:
```
-----BEGIN CERTIFICATE-----
MIIEBjCCAu6gAwIBAgIUXYZ123...
-----END CERTIFICATE-----
```

**Security Requirements**:
- Certificate must be issued by a trusted CA recognized by the authorization server
- Private key must be kept secure (file permissions 600 or better)
- Certificate should not be expired or revoked
- For regional profiles, certificate may need to be from specific directory (e.g., OBIE Directory for UK)

### Private Key JWT

#### `private_key_jwt.kid` (Optional)
**Type**: String  
**Purpose**: Key identifier for private key JWT client authentication  
**Validation**: Must match the `kid` in the corresponding JWK  
**Required For**: JAR profile, private_key_jwt authentication  

#### `private_key_jwt.key` (Optional)
**Type**: String (File Path)  
**Purpose**: Path to private key file for JWT signing  
**Format**: PEM-encoded private key (RSA, ECDSA, or Ed25519)  
**Key Size**: RSA 2048+ bits recommended, ECDSA P-256+ recommended  

```yaml
private_key_jwt:
  kid: "my-signing-key-2024"
  key: "./keys/jwt-signing.pem"
```

**Key Generation Example**:
```bash
# Generate RSA key pair
openssl genrsa -out jwt-signing.pem 2048
openssl rsa -in jwt-signing.pem -pubout -out jwt-public.pem

# Generate ECDSA key pair (P-256)
openssl ecparam -genkey -name prime256v1 -noout -out jwt-signing.pem
openssl ec -in jwt-signing.pem -pubout -out jwt-public.pem
```

## Scope Configuration

### `scopes` (Required)
**Type**: Array of Strings  
**Purpose**: OAuth2 scopes to request during authorization  
**Validation**: Must be non-empty array  
**Profile-Dependent**: Different profiles may require specific scopes  

#### Standard OAuth2/OIDC Scopes
```yaml
scopes:
  - "openid"           # OpenID Connect identity
  - "profile"          # Profile information
  - "email"            # Email address
  - "offline_access"   # Refresh token
```

#### FAPI/Banking Scopes
```yaml
scopes:
  - "openid"
  - "accounts"         # Account information
  - "transactions"     # Transaction data
  - "payments"         # Payment initiation
```

#### UK Open Banking Scopes
```yaml
scopes:
  - "openid"
  - "accounts"         # Account information
  - "payments"         # Payment initiation  
  - "fundsconfirmations"  # Confirmation of funds
```

#### Brazil Open Finance Scopes
```yaml
scopes:
  - "openid"
  - "accounts"
  - "credit-cards-accounts"
  - "loans"
  - "financings"
  - "unarranged-accounts-overdraft"
  - "invoice-financings"
  - "payments"
  - "consents"
```

**Scope Validation by Profile**:
- **oauth2-pkce**: Any valid OAuth2 scopes
- **fapi-ro**: Typically read-only scopes (`accounts`, `transactions`)
- **fapi-rw**: May include write scopes (`payments`)
- **ob-uk**: Must include OBIE-specific scopes
- **open-finance-br**: Must include Brazilian Open Finance scopes

## Regional-Specific Configuration

### UK Open Banking Configuration
```yaml
profiles:
  - "oauth2-pkce"
  - "fapi-ro"
  - "fapi-rw"
  - "mtls"
  - "jar"
  - "ob-uk"

# OBIE-specific scopes
scopes:
  - "openid"
  - "accounts"
  - "payments"
  - "fundsconfirmations"

# OBIE Directory certificate required
mtls:
  cert: "./certs/obie-directory.crt"
  key: "./certs/obie-directory.key"

# Request object signing required for OBIE
private_key_jwt:
  kid: "obie-signing-key"
  key: "./keys/obie-signing.pem"

# OBIE endpoints
authorization_endpoint: "https://ob19-auth1-ui.o3bank.co.uk/oauth2/authorize"
token_endpoint: "https://ob19-auth1-ui.o3bank.co.uk/oauth2/token"
```

### Brazil Open Finance Configuration
```yaml
profiles:
  - "oauth2-pkce"
  - "fapi-ro"
  - "fapi-rw"
  - "mtls"
  - "jar"
  - "open-finance-br"

# Brazilian Open Finance scopes
scopes:
  - "openid"
  - "accounts"
  - "credit-cards-accounts"
  - "loans"
  - "payments"
  - "consents"

# Brazilian directory certificate
mtls:
  cert: "./certs/brazil-directory.crt"
  key: "./certs/brazil-directory.key"

# Request object signing
private_key_jwt:
  kid: "brazil-signing-key"
  key: "./keys/brazil-signing.pem"
```

## Validation Rules

### URL Validation
- All endpoint URLs must use HTTPS scheme (HTTP allowed only for localhost)
- URLs must be well-formed and parseable
- Hosts must be resolvable (if network tests are enabled)

### Certificate Validation
- Certificate files must exist and be readable
- Certificate and key must form a valid pair
- Certificates must be in PEM format
- Private keys must be in PEM format and match the certificate

### Profile Dependency Validation
- All profile dependencies must be satisfied
- No conflicting profiles can be selected simultaneously
- Profile IDs must exist in the registry

### Scope Validation
- Scopes array must not be empty
- Scope strings must be valid (no spaces, special characters as per OAuth2 spec)
- Profile-specific scope requirements are validated

## Configuration Examples

### Minimal Configuration (OAuth2 + PKCE Only)
```yaml
profiles:
  - "oauth2-pkce"

client_id: "test-client"
redirect_uri: "https://example.com/callback"
authorization_endpoint: "https://auth.example.com/oauth2/authorize"
token_endpoint: "https://auth.example.com/oauth2/token"

scopes:
  - "openid"
  - "profile"
```

### FAPI Read-Only Configuration
```yaml
profiles:
  - "oauth2-pkce"
  - "fapi-ro"

client_id: "fapi-ro-client"
redirect_uri: "https://app.example.com/callback"

authorization_endpoint: "https://bank.example.com/oauth2/authorize"
token_endpoint: "https://bank.example.com/oauth2/token"
oidc_config: "https://bank.example.com/.well-known/openid-configuration"
jwks_uri: "https://bank.example.com/.well-known/jwks.json"

scopes:
  - "openid"
  - "accounts"
  - "transactions"

# Optional: Strong client authentication
mtls:
  cert: "./certs/fapi-client.crt"
  key: "./certs/fapi-client.key"
```

### FAPI Read-Write Configuration
```yaml
profiles:
  - "oauth2-pkce"
  - "fapi-ro"
  - "fapi-rw"
  - "mtls"
  - "jar"

client_id: "fapi-rw-client"
redirect_uri: "https://app.example.com/callback"

authorization_endpoint: "https://bank.example.com/oauth2/authorize"
token_endpoint: "https://bank.example.com/oauth2/token"
par_endpoint: "https://bank.example.com/oauth2/par"
oidc_config: "https://bank.example.com/.well-known/openid-configuration"
jwks_uri: "https://bank.example.com/.well-known/jwks.json"

scopes:
  - "openid"
  - "accounts"
  - "payments"

# Strong client authentication (required for FAPI-RW)
mtls:
  cert: "./certs/fapi-rw-client.crt"
  key: "./certs/fapi-rw-client.key"

# Request object signing (required for FAPI-RW)
private_key_jwt:
  kid: "fapi-rw-signing-2024"
  key: "./keys/fapi-rw-signing.pem"
```

### Comprehensive Testing Configuration
```yaml
profiles:
  - "oauth2-pkce"
  - "fapi-ro"
  - "fapi-rw"
  - "mtls"
  - "jar"
  - "par"

client_id: "comprehensive-test-client"
redirect_uri: "https://testapp.example.com/callback"

# All relevant endpoints
authorization_endpoint: "https://bank.example.com/oauth2/authorize"
token_endpoint: "https://bank.example.com/oauth2/token"
par_endpoint: "https://bank.example.com/oauth2/par"
introspection_endpoint: "https://bank.example.com/oauth2/introspect"
jwks_uri: "https://bank.example.com/.well-known/jwks.json"
oidc_config: "https://bank.example.com/.well-known/openid-configuration"

scopes:
  - "openid"
  - "profile"
  - "accounts"
  - "transactions"
  - "payments"

# Full authentication setup
mtls:
  cert: "./certs/test-client.crt"
  key: "./certs/test-client.key"

private_key_jwt:
  kid: "test-signing-key-2024"
  key: "./keys/test-signing.pem"
```

## Environment Variable Support

fapictl supports environment variable substitution in configuration files using `${VARIABLE_NAME}` syntax.

### Example with Environment Variables
```yaml
profiles:
  - "oauth2-pkce"
  - "fapi-ro"

client_id: "${OAUTH2_CLIENT_ID}"
client_secret: "${OAUTH2_CLIENT_SECRET}"
redirect_uri: "${OAUTH2_REDIRECT_URI}"

authorization_endpoint: "${AUTH_SERVER_BASE_URL}/oauth2/authorize"
token_endpoint: "${AUTH_SERVER_BASE_URL}/oauth2/token"

scopes:
  - "openid"
  - "accounts"

mtls:
  cert: "${CERT_PATH}/client.crt"
  key: "${CERT_PATH}/client.key"
```

### Setting Environment Variables
```bash
export OAUTH2_CLIENT_ID="my-client-id"
export OAUTH2_CLIENT_SECRET="my-client-secret"
export OAUTH2_REDIRECT_URI="https://myapp.com/callback"
export AUTH_SERVER_BASE_URL="https://auth.bank.com"
export CERT_PATH="/secure/certs"

fapictl test --config config.yaml
```

### Docker Environment Variables
```yaml
# docker-compose.yml
services:
  fapictl:
    image: fapictl:latest
    environment:
      - OAUTH2_CLIENT_ID=my-client-id
      - OAUTH2_CLIENT_SECRET=my-client-secret
      - AUTH_SERVER_BASE_URL=https://auth.bank.com
    volumes:
      - ./config.yaml:/config.yaml
      - ./certs:/certs:ro
```

## Security Best Practices

### Credential Management
1. **Never commit secrets to version control**
   ```yaml
   # BAD - secret in config file
   client_secret: "super-secret-value"
   
   # GOOD - use environment variable
   client_secret: "${CLIENT_SECRET}"
   ```

2. **Use secure file permissions for private keys**
   ```bash
   chmod 600 /path/to/private.key
   chown app:app /path/to/private.key
   ```

3. **Store certificates and keys securely**
   ```bash
   # Create secure directory structure
   mkdir -p /secure/certs /secure/keys
   chmod 750 /secure/certs /secure/keys
   
   # Set proper ownership
   chown -R app:app /secure/
   ```

### Network Security
1. **Always use HTTPS in production**
   ```yaml
   # All endpoints must use HTTPS
   authorization_endpoint: "https://auth.bank.com/oauth2/authorize"
   token_endpoint: "https://auth.bank.com/oauth2/token"
   ```

2. **Validate TLS certificates**
   - Ensure server certificates are valid and trusted
   - Check certificate expiry dates
   - Verify certificate chains

3. **Use strong TLS configuration**
   - TLS 1.2 minimum (TLS 1.3 preferred)
   - Strong cipher suites only
   - Proper certificate validation

### Configuration Security
1. **Validate all configuration values**
   ```bash
   # Test configuration before use
   fapictl test --config config.yaml --dry-run
   ```

2. **Use configuration templates for different environments**
   ```
   config/
   ├── template.yaml          # Template with environment variables
   ├── development.yaml       # Development-specific values
   ├── staging.yaml          # Staging-specific values
   └── production.yaml       # Production-specific values
   ```

3. **Implement configuration validation in CI/CD**
   ```yaml
   # GitHub Actions example
   - name: Validate Configuration
     run: |
       fapictl test --config config/production.yaml --validate-only
   ```

## Troubleshooting

### Common Configuration Errors

#### Invalid URL Format
```
Error: Invalid authorization endpoint URL: parse "http://invalid-url": invalid character " " in host name
```
**Solution**: Ensure URLs are properly formatted and use HTTPS.

#### Missing Required Fields
```
Error: Invalid config: client_id is required
```
**Solution**: Ensure all required fields are present and non-empty.

#### Certificate Loading Errors
```
Error: Failed to load config: tls: failed to find certificate PEM data in certificate input
```
**Solution**: Verify certificate file format and path.

#### Profile Dependency Errors
```
Error: Profile resolution failed: profile fapi-rw requires dependency oauth2-pkce
```
**Solution**: Include all required dependencies in the profiles list.

#### Scope Configuration Issues
```
Error: No UK Open Banking scopes (accounts, payments, fundsconfirmations) found
```
**Solution**: Configure appropriate scopes for the selected profiles.

### Validation Commands

#### Validate Configuration Only
```bash
fapictl test --config config.yaml --validate-only
```

#### Test Specific Profiles
```bash
fapictl test --config config.yaml --profiles oauth2-pkce,fapi-ro
```

#### Generate Detailed Error Reports
```bash
fapictl test --config config.yaml --report json > error-report.json
```

#### Check Profile Dependencies
```bash
fapictl profiles --details
fapictl profiles --type mandatory
```

### Debug Configuration Issues

#### Enable Verbose Logging
```bash
export FAPICTL_LOG_LEVEL=debug
fapictl test --config config.yaml
```

#### Validate Individual Components
```bash
# Test just certificate loading
fapictl test --config config.yaml --profiles mtls

# Test just endpoint connectivity  
fapictl test --config config.yaml --profiles oauth2-pkce

# Test profile dependencies
fapictl test --config config.yaml --profiles fapi-rw --validate-only
```

#### Configuration File Syntax Check
```bash
# Validate YAML syntax
yamllint config.yaml

# Check for environment variable substitution
envsubst < config.yaml | yamllint -
```

This comprehensive documentation covers all configuration aspects of fapictl, providing developers and operators with the information needed to properly configure and troubleshoot the tool for various FAPI compliance testing scenarios.