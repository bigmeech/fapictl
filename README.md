# fapictl: Financial-grade API (FAPI) Compliance Testing Tool

## Overview

**fapictl** is a command-line tool written in Go for testing and validating the compliance of OAuth 2.0 and OpenID Connect servers with the Financial-grade API (FAPI) security profiles. It helps security engineers, developers, and auditors ensure their systems conform to FAPI Read-Only (R/O), FAPI Read/Write (R/W), and related open banking profiles.

## Quick Start

### 1. Interactive Setup (Recommended)

The fastest way to get started is using the interactive wizard:

```bash
fapictl wizard
```

This will guide you through:
- Configuring your OAuth 2.0/FAPI setup
- Selecting appropriate compliance profiles  
- Generating required cryptographic materials
- Creating configuration files
- Running your first compliance tests

### 2. Manual Setup

**Step 1: Create a basic configuration file**
```bash
# Create fapictl-config.yaml
cat > fapictl-config.yaml << EOF
profiles:
  - oauth2-pkce
  - fapi-ro
client_id: "your-client-id"
redirect_uri: "https://your-app.com/callback"
authorization_endpoint: "https://auth.provider.com/oauth2/authorize"
token_endpoint: "https://auth.provider.com/oauth2/token"
scopes:
  - openid
  - accounts
EOF
```

**Step 2: Run your first test**
```bash
fapictl test --config fapictl-config.yaml
```

**Step 3: View available profiles**
```bash
fapictl profiles
```

**Step 4: Generate cryptographic materials (if needed)**
```bash
# Generate PKCE challenge
fapictl generate pkce

# Generate mTLS certificates
fapictl generate cert --subject "CN=my-client"

# Generate JWT signing keys
fapictl generate key --type rsa --size 2048
```

### 3. Profile-Specific Quick Start

**Basic FAPI Compliance:**
```bash
fapictl test --profiles oauth2-pkce,fapi-ro,fapi-rw
```

**UK Open Banking:**
```bash
fapictl test --profiles ob-uk  # Includes all dependencies
```

**Brazilian Open Finance:**
```bash
fapictl test --profiles open-finance-br  # Includes all dependencies
```

**High Security Setup:**
```bash
fapictl test --profiles oauth2-pkce,fapi-rw,mtls,jar,par
```

## Documentation

- **[Profile Usage Guide](PROFILE_USAGE.md)** - Comprehensive guide for each FAPI profile
- **[Configuration Examples](examples/)** - Ready-to-use configuration templates
- **Built-in Help**: `fapictl help [command]`
- **Profile Details**: `fapictl profiles --details`

---

## Features

* Validate FAPI R/O and R/W profiles
* Test JWS request objects, JARM, PAR, and PKCE
* Validate access and ID token claims and structure
* Replay protection via `jti`, `exp`, `nonce`
* Inspect token introspection and consent enforcement
* Check mutual TLS and `private_key_jwt` client authentication
* Export detailed audit reports (JSON, YAML, HTML)
* Modular profile plugin architecture for regional and optional extensions

---

## Installation

### Option 1: Build from Source
```bash
git clone https://github.com/bigmeech/fapictl.git
cd fapictl
go build -o fapictl .
```

### Option 2: Go Install (when published)
```bash
go install github.com/your-org/fapictl@latest
```

### Option 3: Download Binary (when available)
Download the latest binary from [GitHub Releases](https://github.com/your-org/fapictl/releases).

---

## Configuration

### Modern Profile-Based Configuration

fapictl uses a modern profile-based system. Here's a comprehensive example:

```yaml
# Multiple profiles (automatically resolves dependencies)
profiles:
  - oauth2-pkce
  - fapi-ro
  - fapi-rw
  - mtls
  - jar

# OAuth 2.0 Client Configuration
client_id: "my-fapi-client"
redirect_uri: "https://myapp.com/callback"

# OAuth 2.0 / OIDC Endpoints
authorization_endpoint: "https://bank.com/oauth2/authorize"
token_endpoint: "https://bank.com/oauth2/token"
par_endpoint: "https://bank.com/oauth2/par"
introspection_endpoint: "https://bank.com/oauth2/introspect"
jwks_uri: "https://bank.com/.well-known/jwks.json"

# Mutual TLS Configuration
mtls:
  cert: "./certs/client.crt"
  key: "./certs/client.key"

# JWT Request Object Signing
private_key_jwt:
  kid: "signing-key-1"
  key: "./keys/jwt-signing.pem"

# Requested Scopes
scopes:
  - openid
  - accounts
  - payments
```

### Legacy Single Profile Configuration (still supported)

```yaml
profile: fapi-rw  # Legacy single profile format
client_id: "legacy-client"
# ... rest of configuration
```

---

## Common Usage Examples

### Basic Testing
```bash
# Run tests with configuration file
fapictl test --config fapictl-config.yaml

# Test specific profiles
fapictl test --profiles oauth2-pkce,fapi-ro

# Run with verbose HTTP logging
fapictl test --config fapictl-config.yaml --verbose
```

### Profile Management
```bash
# List all available profiles
fapictl profiles

# View profile details and dependencies
fapictl profiles --details

# List profiles by type
fapictl profiles --type mandatory
fapictl profiles --type optional
fapictl profiles --type regional
```

### Cryptographic Material Generation
```bash
# Generate PKCE challenge
fapictl generate pkce --save --output-dir ./generated

# Generate RSA key pair for JWT signing
fapictl generate key --type rsa --size 2048 --output jwt-key

# Generate mTLS certificate
fapictl generate cert --subject "CN=my-client" --output-dir ./certs
```

### Validation and Debugging
```bash
# Validate configuration file
fapictl validate config --config fapictl-config.yaml

# Test endpoint connectivity
fapictl validate endpoint --url https://auth.provider.com/oauth2/authorize

# Debug mode with maximum verbosity
fapictl test --config fapictl-config.yaml --verbose --very-verbose
```

---

## Available Commands

### Core Commands

| Command | Purpose |
|---------|---------|
| `fapictl wizard` | Interactive setup wizard (recommended for new users) |
| `fapictl test` | Run FAPI compliance tests |
| `fapictl profiles` | List and manage compliance profiles |
| `fapictl generate` | Generate cryptographic materials |
| `fapictl validate` | Validate configurations and endpoints |

### Test Command Options

```bash
fapictl test [flags]
```

**Key Flags:**
- `--config FILE` - Path to YAML configuration file
- `--profiles LIST` - Comma-separated list of profiles to test
- `--verbose, -v` - Enable verbose HTTP request/response logging
- `--very-verbose, -vv` - Maximum verbosity (includes all HTTP details)
- `--output-dir DIR` - Directory for generated files and reports
- `--dry-run` - Show what would be tested without running tests

### Generate Command Options

```bash
fapictl generate [pkce|key|cert] [flags]
```

**Examples:**
- `fapictl generate pkce --save` - Generate PKCE challenge/verifier
- `fapictl generate key --type rsa --size 2048` - Generate RSA key pair
- `fapictl generate cert --subject "CN=client"` - Generate mTLS certificate

---

## Supported FAPI Profiles

fapictl supports a comprehensive set of FAPI compliance profiles organized by category:

### Mandatory Profiles (Core FAPI)
- `oauth2-pkce` - OAuth 2.0 Authorization Code + PKCE (baseline requirement)
- `fapi-ro` - FAPI 1.0 Read-Only Profile (account information access)
- `fapi-rw` - FAPI 1.0 Read-Write Profile (payments and high-risk operations)

### Optional Profiles (Security Extensions)
- `mtls` - Mutual TLS client authentication (RFC 8705)
- `jar` - JWT Secured Authorization Request (RFC 9101)
- `par` - Pushed Authorization Requests (RFC 9126)

### Regional Profiles (Regulatory Compliance)
- `ob-uk` - UK Open Banking (OBIE standards + PSD2 RTS)
- `open-finance-br` - Brazilian Open Finance (Sistema Financeiro Aberto)

### Profile Dependencies

The system automatically resolves profile dependencies:
- `fapi-ro` → requires `oauth2-pkce`
- `fapi-rw` → requires `oauth2-pkce` + `fapi-ro`
- `ob-uk` → requires `fapi-rw` + `mtls` + `jar`
- `open-finance-br` → requires `fapi-rw` + `mtls` + `jar`

**For detailed usage instructions for each profile, see [PROFILE_USAGE.md](PROFILE_USAGE.md)**

---

## Sample Output

### Test Results
```text
FAPI Compliance Test Results

OAuth2 + PKCE Profile:
  PASS PKCE Challenge Generation
  PASS Authorization Request Construction
  PASS State Parameter Validation
  PASS Authorization Code Exchange

FAPI Read-Only Profile:
  PASS HTTPS Enforcement
  PASS TLS 1.2+ Validation
  PASS Authorization Server Metadata
  PASS Strong Client Authentication

FAPI Read-Write Profile:
  PASS Request Object Signing
  PASS Enhanced Client Authentication
  PASS PAR Support
  FAIL Token Binding Validation
  
Mutual TLS Profile:
  PASS Client Certificate Configuration
  PASS Certificate Chain Validation

Summary: 9 passed, 1 failed (90% compliance)
Report saved to: fapi-compliance-report-2024-07-24.json
```

### Interactive Wizard Output
```text
FAPI Compliance Test Wizard

Step 1 of 6: Basic Configuration
Client ID: my-fapi-client
Redirect URI: https://myapp.com/callback
Scopes: openid, accounts, payments

Step 2 of 6: OAuth 2.0 Endpoints
Authorization Endpoint: https://auth.bank.com/oauth2/authorize
Token Endpoint: https://auth.bank.com/oauth2/token

Configuration wizard completed successfully!

Generated files:
  fapictl-config.yaml
  client-cert.pem
  client-key.pem
  jwt-signing-key.pem

Running FAPI compliance tests...
```
---

## Roadmap

* [ ] Full CIBA support with push/poll mode
* [ ] DPoP signature verification
* [ ] FAPI 2.0 and OpenID4VP support
* [ ] OBIE conformance mode
* [ ] Browser-based dashboard UI

---

## License

MIT

## Maintainers

* [Larry Eliemenye](https://github.com/bigmeech)

---

## Resources

* [OpenID FAPI Specs](https://openid.net/wg/fapi/)
* [OAuth 2.0 (RFC 6749)](https://tools.ietf.org/html/rfc6749)
* [OIDC Core Spec](https://openid.net/specs/openid-connect-core-1_0.html)
* [FAPI R/W Profile](https://openid.net/specs/openid-financial-api-part-2.html)
