# FAPI Profile Usage Guide

This document provides comprehensive usage instructions for each FAPI compliance profile available in fapictl.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Mandatory Profiles](#mandatory-profiles)
3. [Optional Profiles](#optional-profiles)
4. [Regional Profiles](#regional-profiles)
5. [Profile Combinations](#profile-combinations)
6. [Configuration Examples](#configuration-examples)
7. [Troubleshooting](#troubleshooting)

## Quick Start

View all available profiles:
```bash
fapictl profiles
```

Use the interactive wizard to configure profiles:
```bash
fapictl wizard
```

Run tests with specific profiles:
```bash
fapictl test --config your-config.yaml --profiles oauth2-pkce,fapi-ro
```

---

## Mandatory Profiles

These profiles implement core FAPI requirements and are typically required for any FAPI-compliant system.

### 🔐 oauth2-pkce - OAuth 2.0 Authorization Code + PKCE

**Purpose**: Implements the baseline OAuth 2.0 Authorization Code flow with PKCE (Proof Key for Code Exchange) as required by FAPI.

**Standards**: RFC 6749, RFC 7636

**When to use**: 
- Required for all FAPI implementations
- Base requirement for secure authorization flows
- Public and confidential clients

**Configuration**:
```yaml
profiles:
  - oauth2-pkce
client_id: "my-oauth-client"
redirect_uri: "https://myapp.com/callback"
authorization_endpoint: "https://auth.provider.com/oauth2/authorize"
token_endpoint: "https://auth.provider.com/oauth2/token"
scopes:
  - openid
  - profile
```

**What it tests**:
- ✅ PKCE challenge generation (S256 method only)
- ✅ Authorization request construction
- ✅ State parameter validation
- ✅ Authorization code exchange
- ✅ Access token validation
- ✅ Error handling for invalid requests

**CLI Usage**:
```bash
# Basic OAuth2 + PKCE test
fapictl test --profiles oauth2-pkce --config config.yaml

# Generate PKCE challenge for manual testing
fapictl generate pkce --save

# Verbose output to see all HTTP requests
fapictl test --profiles oauth2-pkce --verbose
```

---

### 🛡️ fapi-ro - FAPI Read-Only Profile

**Purpose**: Implements FAPI 1.0 Read-Only profile for secure API access with read-only permissions.

**Standards**: FAPI 1.0 Read-Only Profile

**Dependencies**: `oauth2-pkce` (automatically included)

**When to use**:
- Account information services
- Read-only API access
- Minimum FAPI compliance for data access

**Configuration**:
```yaml
profiles:
  - fapi-ro  # oauth2-pkce automatically included
client_id: "fapi-ro-client"
redirect_uri: "https://myapp.com/callback"
authorization_endpoint: "https://fapi.provider.com/oauth2/authorize"
token_endpoint: "https://fapi.provider.com/oauth2/token"
jwks_uri: "https://fapi.provider.com/.well-known/jwks.json"
scopes:
  - openid
  - accounts
```

**What it tests**:
- ✅ All OAuth2+PKCE requirements
- ✅ HTTPS enforcement (TLS 1.2+ required)
- ✅ Authorization server metadata discovery
- ✅ Strong client authentication requirements
- ✅ JWT access token validation (if used)
- ✅ Token lifetime restrictions
- ✅ OIDC compliance (nonce, state parameters)
- ✅ Security headers validation

**CLI Usage**:
```bash
# FAPI Read-Only compliance test
fapictl test --profiles fapi-ro

# Test with specific TLS version
fapictl test --profiles fapi-ro --min-tls-version 1.2

# Check authorization server metadata
fapictl test --profiles fapi-ro --check-metadata
```

---

### 🏦 fapi-rw - FAPI Read-Write Profile

**Purpose**: Implements FAPI 1.0 Read-Write profile for high-risk operations like payments and account modifications.

**Standards**: FAPI 1.0 Read-Write Profile

**Dependencies**: `oauth2-pkce`, `fapi-ro` (automatically included)

**When to use**:
- Payment initiation services
- Account modification operations
- High-value transactions
- Full FAPI compliance requirements

**Configuration**:
```yaml
profiles:
  - fapi-rw  # Dependencies auto-included
client_id: "fapi-rw-client"
redirect_uri: "https://myapp.com/callback"
authorization_endpoint: "https://fapi.provider.com/oauth2/authenticate"
token_endpoint: "https://fapi.provider.com/oauth2/token"
par_endpoint: "https://fapi.provider.com/oauth2/par"
jwks_uri: "https://fapi.provider.com/.well-known/jwks.json"
scopes:
  - openid
  - accounts
  - payments
```

**What it tests**:
- ✅ All FAPI-RO requirements
- ✅ Request object requirements (signed JWT)
- ✅ Enhanced client authentication
- ✅ Consent and intent validation
- ✅ Token binding to certificates
- ✅ Refresh token rotation
- ✅ PAR (Pushed Authorization Request) support
- ✅ JARM (JWT Authorization Response Mode)
- ✅ Request object encryption (if configured)

**CLI Usage**:
```bash
# Full FAPI Read-Write compliance
fapictl test --profiles fapi-rw

# Test with consent/intent flow
fapictl test --profiles fapi-rw --consent-required

# Validate refresh token behavior
fapictl test --profiles fapi-rw --test-refresh-tokens
```

---

## Optional Profiles

These profiles add specific security or functional capabilities to your FAPI implementation.

### 🔒 mtls - Mutual TLS Authentication

**Purpose**: Implements client certificate-based authentication using mutual TLS.

**Standards**: RFC 8705 - OAuth 2.0 Mutual-TLS Client Authentication

**Dependencies**: None (can be used with any profile)

**When to use**:
- Strong client authentication required
- Certificate-based security model
- B2B integrations
- Regulatory requirements for client certificates

**Configuration**:
```yaml
profiles:
  - oauth2-pkce
  - mtls
client_id: "mtls-client"
# ... other OAuth config ...
mtls:
  cert: "./certs/client.crt"
  key: "./certs/client.key"
```

**What it tests**:
- ✅ Client certificate configuration
- ✅ Certificate chain validation
- ✅ TLS handshake with client cert
- ✅ Certificate binding validation
- ✅ Certificate revocation checking (OCSP/CRL)
- ✅ Certificate subject validation
- ✅ Key usage restrictions

**CLI Usage**:
```bash
# Test mTLS authentication
fapictl test --profiles oauth2-pkce,mtls

# Generate test certificates
fapictl generate cert --subject "CN=test-client" --output-dir ./certs

# Validate existing certificate
fapictl validate cert --cert ./certs/client.crt --key ./certs/client.key
```

**Certificate Requirements**:
- X.509 certificates with proper key usage
- Valid certificate chain to trusted CA
- Private key must match certificate
- Certificate must not be expired or revoked

---

### 📝 jar - JWT Secured Authorization Request

**Purpose**: Implements request objects as signed JWTs for enhanced security.

**Standards**: RFC 9101 - JWT Secured Authorization Request (JAR)

**Dependencies**: None

**When to use**:
- Enhanced authorization request security
- Protection against parameter tampering
- FAPI 1.0 Read-Write compliance
- High-security environments

**Configuration**:
```yaml
profiles:
  - oauth2-pkce
  - jar
client_id: "jar-client"
# ... other OAuth config ...
private_key_jwt:
  kid: "signing-key-1"
  key: "./keys/jwt-signing.pem"
```

**What it tests**:
- ✅ Request object creation and signing
- ✅ JWT structure and claims validation
- ✅ Signing key configuration
- ✅ Algorithm support (RS256, ES256, PS256)
- ✅ Request object parameter validation
- ✅ Integration with authorization endpoint
- ✅ Security requirements compliance

**CLI Usage**:
```bash
# Test JAR functionality
fapictl test --profiles oauth2-pkce,jar

# Generate JWT signing key
fapictl generate key --type rsa --size 2048 --output jwt-signing

# Create and validate request object
fapictl test --profiles jar --validate-request-object
```

**Key Requirements**:
- RSA (2048+ bits) or ECDSA (P-256+) keys
- Proper key ID (kid) configuration
- Private key in PEM format
- Algorithm must be RS256, ES256, or PS256

---

### 🚀 par - Pushed Authorization Requests

**Purpose**: Implements PAR for enhanced security by pre-registering authorization requests.

**Standards**: RFC 9126 - OAuth 2.0 Pushed Authorization Requests

**Dependencies**: None

**When to use**:
- Large authorization requests
- Enhanced security for request parameters
- Mobile applications with limited URL length
- FAPI 1.0 Advanced security profile

**Configuration**:
```yaml
profiles:
  - oauth2-pkce
  - par
client_id: "par-client"
# ... other OAuth config ...
par_endpoint: "https://auth.provider.com/oauth2/par"
```

**What it tests**:
- ✅ PAR endpoint configuration
- ✅ PAR request format validation
- ✅ PAR response validation (request_uri)
- ✅ Request URI usage in authorization
- ✅ PAR request expiration handling
- ✅ Security requirements validation
- ✅ Large request handling

**CLI Usage**:
```bash
# Test PAR functionality
fapictl test --profiles oauth2-pkce,par

# Test with large authorization requests
fapictl test --profiles par --large-request-test

# Validate PAR endpoint
fapictl validate endpoint --url https://auth.provider.com/oauth2/par
```

---

## Regional Profiles

These profiles implement region-specific regulatory requirements and standards.

### 🇬🇧 ob-uk - UK Open Banking

**Purpose**: Implements UK Open Banking standards for PSD2 compliance in the United Kingdom.

**Standards**: OBIE Read/Write API Specification, PSD2 RTS, FCA requirements

**Dependencies**: `fapi-rw`, `mtls`, `jar` (automatically included)

**When to use**:
- UK Open Banking compliance
- PSD2 implementation in UK
- UK financial services integration
- OBIE directory participation

**Configuration**:
```yaml
profiles:
  - ob-uk  # All dependencies auto-included
client_id: "uk-tpp-client"
redirect_uri: "https://tpp.com/callback"
authorization_endpoint: "https://ob.bank.com/oauth2/authorize"
token_endpoint: "https://ob.bank.com/oauth2/token"
par_endpoint: "https://ob.bank.com/oauth2/par"
jwks_uri: "https://ob.bank.com/.well-known/jwks.json"
mtls:
  cert: "./certs/obie-transport.crt"
  key: "./certs/obie-transport.key"
private_key_jwt:
  kid: "obie-signing-key"
  key: "./keys/obie-signing.pem"
scopes:
  - openid
  - accounts
  - payments
  - fundsconfirmations
```

**What it tests**:
- ✅ All FAPI-RW requirements
- ✅ OBIE-specific scopes and permissions
- ✅ Intent-based authorization (AIS/PIS/CBPII)
- ✅ Strong Customer Authentication (SCA)
- ✅ Account request permissions model
- ✅ Payment initiation security
- ✅ OBIE Directory certificate validation
- ✅ Customer authentication methods
- ✅ Data cluster permissions
- ✅ Consent dashboard requirements

**CLI Usage**:
```bash
# Full UK Open Banking compliance
fapictl test --profiles ob-uk

# Test specific Open Banking service
fapictl test --profiles ob-uk --service-type AIS  # Account Information
fapictl test --profiles ob-uk --service-type PIS  # Payment Initiation
fapictl test --profiles ob-uk --service-type CBPII # Confirmation of Funds

# Validate OBIE certificates
fapictl validate obie-cert --cert ./certs/obie-transport.crt
```

**UK-Specific Requirements**:
- OBIE Directory enrollment and certificates
- UK-specific consent model
- SCA-compliant authentication
- FCA regulatory compliance
- Open Banking Implementation Entity (OBIE) standards

---

### 🇧🇷 open-finance-br - Brazil Open Finance

**Purpose**: Implements Brazilian Open Finance (Sistema Financeiro Aberto) standards.

**Standards**: Sistema Financeiro Aberto (SFA), BCB Resolutions, LGPD

**Dependencies**: `fapi-rw`, `mtls`, `jar` (automatically included)

**When to use**:
- Brazilian Open Finance compliance
- BCB (Central Bank of Brazil) requirements
- Brazilian financial services integration
- PIX integration

**Configuration**:
```yaml
profiles:
  - open-finance-br  # All dependencies auto-included
client_id: "br-openfinance-client"
redirect_uri: "https://fintech.com/callback"
authorization_endpoint: "https://auth.banco.com.br/oauth2/authorize"
token_endpoint: "https://auth.banco.com.br/oauth2/token"
par_endpoint: "https://auth.banco.com.br/oauth2/par"
jwks_uri: "https://auth.banco.com.br/.well-known/jwks.json"
mtls:
  cert: "./certs/bcb-transport.crt"
  key: "./certs/bcb-transport.key"
private_key_jwt:
  kid: "bcb-signing-key"
  key: "./keys/bcb-signing.pem"
scopes:
  - openid
  - accounts
  - resources
  - payments
  - consents
```

**What it tests**:
- ✅ All FAPI-RW requirements
- ✅ Brazilian Open Finance scopes
- ✅ CPF/CNPJ authorization flows
- ✅ Brazilian consent management model
- ✅ BCB Directory certificate validation
- ✅ PIX integration requirements
- ✅ LGPD (Brazilian GDPR) compliance
- ✅ Dynamic client registration
- ✅ Operational risk requirements
- ✅ Brazilian regulatory standards

**CLI Usage**:
```bash
# Full Brazilian Open Finance compliance
fapictl test --profiles open-finance-br

# Test with CPF/CNPJ customer identification
fapictl test --profiles open-finance-br --customer-type CPF
fapictl test --profiles open-finance-br --customer-type CNPJ

# Validate BCB certificates
fapictl validate bcb-cert --cert ./certs/bcb-transport.crt

# Test PIX integration
fapictl test --profiles open-finance-br --pix-enabled
```

**Brazil-Specific Requirements**:
- BCB Directory enrollment and certificates
- CPF/CNPJ customer identification
- Brazilian consent model compliance
- LGPD data protection compliance
- PIX instant payment integration

---

## Profile Combinations

### Common Combinations

**Basic FAPI Compliance**:
```bash
fapictl test --profiles oauth2-pkce,fapi-ro,fapi-rw
```

**FAPI with Strong Authentication**:
```bash
fapictl test --profiles oauth2-pkce,fapi-ro,fapi-rw,mtls,jar
```

**UK Open Banking (Full)**:
```bash
fapictl test --profiles ob-uk  # Includes all dependencies
```

**Brazilian Open Finance (Full)**:
```bash
fapictl test --profiles open-finance-br  # Includes all dependencies
```

**Custom High-Security Setup**:
```bash
fapictl test --profiles oauth2-pkce,fapi-rw,mtls,jar,par
```

### Profile Dependency Chain

The system automatically resolves dependencies:

```
oauth2-pkce (base)
    ↓
fapi-ro (extends oauth2-pkce)
    ↓
fapi-rw (extends fapi-ro + oauth2-pkce)
    ↓
ob-uk (extends fapi-rw + mtls + jar)
    ↓
open-finance-br (extends fapi-rw + mtls + jar)
```

---

## Configuration Examples

### Minimal FAPI Setup

```yaml
profiles:
  - fapi-ro
client_id: "minimal-fapi-client"
redirect_uri: "https://app.example.com/callback"
authorization_endpoint: "https://auth.bank.com/oauth2/authorize"
token_endpoint: "https://auth.bank.com/oauth2/token"
scopes:
  - openid
  - accounts
```

### Production FAPI Setup with mTLS

```yaml
profiles:
  - fapi-rw
  - mtls
  - jar
  - par
client_id: "prod-fapi-client"
redirect_uri: "https://prod.myfintech.com/oauth/callback"
authorization_endpoint: "https://api.bank.com/oauth2/authorize"
token_endpoint: "https://api.bank.com/oauth2/token"
par_endpoint: "https://api.bank.com/oauth2/par"
jwks_uri: "https://api.bank.com/.well-known/jwks.json"
introspection_endpoint: "https://api.bank.com/oauth2/introspect"

# mTLS Configuration
mtls:
  cert: "/etc/ssl/certs/client.crt"
  key: "/etc/ssl/private/client.key"

# JWT Signing Configuration  
private_key_jwt:
  kid: "prod-signing-key-2024"
  key: "/etc/ssl/private/jwt-signing.pem"

# Scopes
scopes:
  - openid
  - accounts
  - payments
  - profile
```

### UK Open Banking Production Setup

```yaml
profiles:
  - ob-uk
client_id: "0015800001041REAAY"  # OBIE Client ID
redirect_uri: "https://tpp.example.com/redirect"
authorization_endpoint: "https://ob.santander.co.uk/oauth2/authorize"
token_endpoint: "https://ob.santander.co.uk/oauth2/token"
par_endpoint: "https://ob.santander.co.uk/oauth2/par"
jwks_uri: "https://ob.santander.co.uk/.well-known/jwks.json"

# OBIE Transport Certificate
mtls:
  cert: "/etc/obie/transport.pem"
  key: "/etc/obie/transport.key"

# OBIE Signing Certificate
private_key_jwt:
  kid: "rDEKRWJIgbWeLqJDU4NxZg"
  key: "/etc/obie/signing.key"

scopes:
  - openid
  - accounts
  - payments
  - fundsconfirmations
```

---

## Troubleshooting

### Common Issues

**1. Certificate Problems**
```bash
# Validate certificate and key match
fapictl validate cert --cert client.crt --key client.key

# Check certificate expiration
openssl x509 -in client.crt -text -noout | grep "Not After"

# Test certificate against endpoint
fapictl test --profiles mtls --cert-check-only
```

**2. JWT Signing Issues**
```bash
# Validate JWT signing key
fapictl validate key --key jwt-signing.pem --algorithm RS256

# Generate new signing key
fapictl generate key --type rsa --size 2048 --output new-signing-key

# Test JWT creation
fapictl test --profiles jar --jwt-test-only
```

**3. Profile Dependency Errors**
```bash
# View profile dependencies
fapictl profiles --details

# Test with automatic dependency resolution
fapictl test --profiles fapi-rw --resolve-deps

# Check for conflicts
fapictl profiles --check-conflicts oauth2-pkce,fapi-rw,custom-profile
```

**4. Endpoint Connectivity**
```bash
# Test endpoint reachability
fapictl validate endpoint --url https://auth.provider.com/oauth2/authorize

# Check TLS configuration
fapictl validate tls --url https://auth.provider.com --min-version 1.2

# Test with verbose HTTP logging
fapictl test --profiles oauth2-pkce --verbose --very-verbose
```

### Debug Mode

Enable comprehensive debugging:
```bash
# Maximum verbosity
fapictl test --profiles fapi-rw --verbose --very-verbose --debug

# Save debug logs
fapictl test --profiles ob-uk --debug --log-file debug.log

# Test individual components
fapictl test --profiles fapi-rw --component-test authorization
fapictl test --profiles fapi-rw --component-test token-exchange
```

### Getting Help

```bash
# View help for specific profile
fapictl help profiles ob-uk

# Get configuration examples
fapictl examples --profile fapi-rw

# Validate your configuration
fapictl validate config --config your-config.yaml

# Interactive troubleshooting
fapictl doctor --profile fapi-rw
```

---

## Best Practices

1. **Start Simple**: Begin with `oauth2-pkce` and `fapi-ro`, then add complexity
2. **Use the Wizard**: `fapictl wizard` guides you through proper configuration
3. **Validate Early**: Use `fapictl validate` commands before running tests
4. **Security First**: Always use `mtls` and `jar` for production deployments
5. **Regional Compliance**: Use regional profiles (`ob-uk`, `open-finance-br`) for regulatory compliance
6. **Certificate Management**: Keep certificates current and properly configured
7. **Testing Strategy**: Test profiles incrementally during development
8. **Documentation**: Document your profile selections and configuration choices

This documentation covers all available FAPI profiles and their usage patterns. For specific implementation questions, refer to the individual profile source code or use the built-in help system.