# profiles/mandatory/ Directory

This directory contains the core FAPI compliance profiles that form the foundation of financial-grade API security testing. These profiles implement the essential security requirements defined by the OpenID Foundation's FAPI specifications.

## Purpose

Mandatory profiles represent the baseline security requirements that all FAPI-compliant implementations must satisfy. They build on each other in a logical dependency hierarchy, from basic OAuth2 flows to comprehensive financial-grade security.

## Profiles Overview

### Profile Hierarchy
```
oauth2-pkce (baseline)
    ↓
fapi-ro (read-only operations)
    ↓  
fapi-rw (write operations & payments)
```

## Implemented Profiles

### 1. OAuth2 Authorization Code + PKCE (`oauth2_pkce.go`)

**Profile ID**: `oauth2-pkce`  
**Dependencies**: None (baseline requirement)  
**Standards**: RFC 6749, RFC 7636

#### Purpose
Implements the foundation OAuth 2.0 Authorization Code flow with PKCE (Proof Key for Code Exchange) security extension. This serves as the baseline for all other profiles.

#### Key Tests
- **PKCE Challenge Generation**: Validates proper S256 challenge/verifier generation
- **Authorization Endpoint Discovery**: Verifies endpoint configuration and accessibility  
- **Token Endpoint Discovery**: Tests token endpoint reachability and configuration
- **Authorization Request Construction**: Builds proper authorization URLs with PKCE
- **Token Exchange Simulation**: Tests token exchange request structure

#### Security Requirements
- PKCE with S256 method (plain method rejected)
- Cryptographically secure random verifier generation
- Proper base64url encoding without padding
- Authorization code flow compliance

#### Implementation Details
```go
type AuthCodePKCEVerifier struct {
    client *httpClient.Client
}

func NewAuthCodePKCEVerifier(client *httpClient.Client) *AuthCodePKCEVerifier
func (v *AuthCodePKCEVerifier) Name() string
func (v *AuthCodePKCEVerifier) Description() string  
func (v *AuthCodePKCEVerifier) Verify(ctx context.Context, config verifier.VerifierConfig) (*verifier.TestSuite, error)
```

#### Sample Output
```
=== OAuth2 Authorization Code + PKCE ===
PKCE Challenge Generation                PASS
Authorization Endpoint Discovery         PASS
Token Endpoint Discovery                 PASS
Authorization Request                    PASS
Token Exchange                           PASS

Suite Summary: 5 total, 5 passed, 0 failed, 0 skipped
```

### 2. FAPI Read-Only Profile (`fapi_ro.go`)

**Profile ID**: `fapi-ro`  
**Dependencies**: `oauth2-pkce`  
**Standards**: FAPI 1.0 Read-Only Profile

#### Purpose
Implements FAPI Read-Only security profile for account information access. Adds security requirements beyond basic OAuth2 for financial-grade API protection.

#### Key Tests
- **HTTPS Enforcement**: Validates all endpoints use HTTPS
- **PKCE Required**: Confirms PKCE is mandatory (inherits from oauth2-pkce)
- **TLS Version Check**: Ensures TLS 1.2+ is enforced
- **Authorization Server Metadata**: Validates OIDC discovery document
- **JARM Support**: Tests JWT Secured Authorization Response Mode
- **State Parameter Required**: Confirms state parameter usage
- **Nonce Parameter for OIDC**: Validates nonce for OpenID Connect flows
- **Client Authentication**: Tests strong client authentication methods
- **Token Lifetime Validation**: Checks appropriate token lifetimes

#### Security Requirements
- HTTPS mandatory for all endpoints
- TLS 1.2+ enforcement
- Strong client authentication (mTLS or private_key_jwt)
- State parameter mandatory
- Nonce parameter for OIDC flows
- JARM for response security (where supported)

#### Implementation Details
```go
type FAPIReadOnlyVerifier struct {
    client *httpClient.Client
}

func NewFAPIReadOnlyVerifier(client *httpClient.Client) *FAPIReadOnlyVerifier
func (v *FAPIReadOnlyVerifier) Name() string
func (v *FAPIReadOnlyVerifier) Description() string
func (v *FAPIReadOnlyVerifier) Verify(ctx context.Context, config verifier.VerifierConfig) (*verifier.TestSuite, error)
```

#### Sample Output
```
=== FAPI Read-Only Profile ===
HTTPS Enforcement                        PASS
PKCE Required                            PASS
TLS Version Check                        PASS
Authorization Server Metadata            FAIL
  Error: Discovery endpoint returned status 403
State Parameter Required                 PASS
Nonce Parameter for OIDC                 PASS
Client Authentication                    FAIL
  Error: Neither mTLS nor private_key_jwt authentication configured

Suite Summary: 9 total, 5 passed, 2 failed, 2 skipped
```

### 3. FAPI Read-Write Profile (`fapi_rw.go`)

**Profile ID**: `fapi-rw`  
**Dependencies**: `oauth2-pkce`, `fapi-ro`  
**Standards**: FAPI 1.0 Read-Write Profile

#### Purpose
Implements FAPI Read-Write security profile for payment initiation and account modification operations. Adds the highest level of security requirements for write operations.

#### Key Tests
- **HTTPS Enforcement**: Inherited and enhanced from FAPI-RO
- **PKCE Required**: Confirms S256 method specifically required
- **Request Object Required**: Validates signed request objects are mandatory
- **Strong Client Authentication**: Enhanced requirements for write operations
- **Intent Registration**: Tests intent-based authorization for payments
- **Resource Access Control**: Validates proper scoping and permissions
- **Token Binding**: Tests certificate binding for access tokens
- **Refresh Token Rotation**: Validates refresh token rotation security
- **Consent Management**: Tests consent frameworks for write operations
- **Request Object Encryption**: Tests JWE encryption for sensitive data

#### Security Requirements
- All FAPI-RO requirements plus:
- Signed request objects mandatory (JAR)
- Enhanced client authentication
- Intent registration for write operations
- Token binding to client certificates
- Refresh token rotation
- Request object encryption for sensitive operations

#### Implementation Details
```go
type FAPIReadWriteVerifier struct {
    client *httpClient.Client
}

func NewFAPIReadWriteVerifier(client *httpClient.Client) *FAPIReadWriteVerifier
func (v *FAPIReadWriteVerifier) Name() string
func (v *FAPIReadWriteVerifier) Description() string
func (v *FAPIReadWriteVerifier) Verify(ctx context.Context, config verifier.VerifierConfig) (*verifier.TestSuite, error)
```

#### Sample Output
```
=== FAPI Read-Write Profile ===
HTTPS Enforcement                        PASS
PKCE Required                            PASS
Request Object Required                  FAIL
  Error: FAPI-RW requires private key configuration for signed request objects
Strong Client Authentication             FAIL
  Error: FAPI-RW requires mTLS or private_key_jwt authentication
Intent Registration                      SKIP
  Error: No write scopes requested, intent registration not applicable
Token Binding                            FAIL
  Error: FAPI-RW strongly recommends mTLS for token binding

Suite Summary: 10 total, 2 passed, 3 failed, 5 skipped
```

## Dependency Relationships

### Profile Dependencies
Each profile builds upon the previous level:

```go
// oauth2-pkce (no dependencies)
DefaultRegistry.Register(&ProfileInfo{
    ID:          "oauth2-pkce",
    Type:        Mandatory,
    Dependencies: nil, // Baseline profile
})

// fapi-ro depends on oauth2-pkce
DefaultRegistry.Register(&ProfileInfo{
    ID:          "fapi-ro", 
    Type:        Mandatory,
    Dependencies: []string{"oauth2-pkce"},
})

// fapi-rw depends on both oauth2-pkce and fapi-ro
DefaultRegistry.Register(&ProfileInfo{
    ID:          "fapi-rw",
    Type:        Mandatory, 
    Dependencies: []string{"oauth2-pkce", "fapi-ro"},
})
```

### Test Inheritance
- **fapi-ro** inherits all oauth2-pkce tests and adds FAPI-specific requirements
- **fapi-rw** includes all fapi-ro tests plus write operation security
- Tests may be enhanced or made more restrictive in higher profiles

## Configuration Requirements

### Basic OAuth2 Configuration
```yaml
profiles:
  - oauth2-pkce

client_id: "your-client-id"
redirect_uri: "https://your-app.com/callback" 
authorization_endpoint: "https://authserver.com/oauth2/authorize"
token_endpoint: "https://authserver.com/oauth2/token"
scopes:
  - openid
```

### FAPI Read-Only Configuration
```yaml
profiles:
  - oauth2-pkce
  - fapi-ro

# Basic config plus:
oidc_config: "https://authserver.com/.well-known/openid-configuration"
jwks_uri: "https://authserver.com/.well-known/jwks.json"

# Recommended: Strong client authentication
mtls:
  cert: "./certs/client.crt"
  key: "./certs/client.key"
```

### FAPI Read-Write Configuration  
```yaml
profiles:
  - oauth2-pkce
  - fapi-ro
  - fapi-rw

# Previous config plus:
private_key_jwt:
  kid: "key1"
  key: "./keys/private.pem"

scopes:
  - openid
  - accounts
  - payments  # Write scopes trigger additional tests
```

## Common Test Scenarios

### Successful OAuth2 + PKCE Flow
```bash
$ fapictl test --config config.yaml --profiles oauth2-pkce
# All tests should PASS for properly configured OAuth2 server
```

### FAPI Read-Only Validation
```bash  
$ fapictl test --config config.yaml --profiles oauth2-pkce,fapi-ro
# Tests FAPI security requirements
# May show FAIL for missing mTLS/private_key_jwt
```

### Full FAPI Read-Write Testing
```bash
$ fapictl test --config config.yaml --profiles oauth2-pkce,fapi-ro,fapi-rw
# Comprehensive FAPI compliance testing
# Requires full security configuration
```

## Error Patterns and Solutions

### Common Configuration Issues

#### Missing Client Authentication
```
Client Authentication                    FAIL
Error: Neither mTLS nor private_key_jwt authentication configured
```
**Solution**: Configure mTLS certificates or private key JWT in config file.

#### HTTP Endpoints
```
HTTPS Enforcement                        FAIL
Error: Authorization endpoint must use HTTPS
```  
**Solution**: Update endpoint URLs to use `https://` scheme.

#### Missing Request Object Signing (FAPI-RW)
```
Request Object Required                  FAIL
Error: FAPI-RW requires private key configuration for signed request objects
```
**Solution**: Configure `private_key_jwt` section with signing key.

#### Discovery Endpoint Issues
```
Authorization Server Metadata            FAIL
Error: Discovery endpoint returned status 403
```
**Solution**: Verify `oidc_config` URL is correct and accessible.

## Integration with Other Profiles

### Optional Profile Extensions
Mandatory profiles work with optional extensions:

```bash
# Add mTLS testing
fapictl test --profiles oauth2-pkce,fapi-ro,mtls

# Add request object testing  
fapictl test --profiles oauth2-pkce,fapi-ro,fapi-rw,jar

# Comprehensive testing
fapictl test --profiles oauth2-pkce,fapi-ro,fapi-rw,mtls,jar,par
```

### Regional Profile Requirements
Regional profiles typically require the full mandatory stack:

```bash
# UK Open Banking requires FAPI-RW + extensions
fapictl test --profiles oauth2-pkce,fapi-ro,fapi-rw,mtls,jar,ob-uk

# Brazil Open Finance similar requirements
fapictl test --profiles oauth2-pkce,fapi-ro,fapi-rw,mtls,jar,open-finance-br
```

## Development Guidelines

### Adding New Mandatory Profiles
When adding new mandatory profiles:

1. **Follow dependency hierarchy**: New profiles should build on existing ones
2. **Comprehensive testing**: Cover all security requirements thoroughly  
3. **Clear error messages**: Provide actionable feedback for failures
4. **Standard compliance**: Align with published FAPI specifications
5. **Backward compatibility**: Ensure existing profile combinations still work

### Test Implementation Standards
```go
func (v *ProfileVerifier) testSecurityRequirement(config verifier.VerifierConfig) verifier.TestResult {
    startTime := time.Now()
    
    // Clear test description
    testName := "Security Requirement Name"
    testDesc := "Validates specific security requirement per FAPI spec section X.Y"
    
    // Comprehensive validation logic
    if !securityRequirementMet {
        return verifier.TestResult{
            Name:        testName,
            Description: testDesc,
            Status:      verifier.StatusFail,
            Duration:    time.Since(startTime),
            Error:       "Specific reason for failure with remediation guidance",
            Details: map[string]interface{}{
                "expected": "what should be configured",
                "actual":   "what was found",
                "spec_ref": "FAPI section reference",
            },
        }
    }
    
    return verifier.TestResult{
        Name:        testName,
        Description: testDesc,
        Status:      verifier.StatusPass,
        Duration:    time.Since(startTime),
        Details: map[string]interface{}{
            "validated_requirement": "what was successfully verified",
        },
    }
}
```

This directory provides the foundation for all FAPI compliance testing, ensuring that implementations meet the essential security requirements for financial-grade API protection.