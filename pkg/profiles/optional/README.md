# profiles/optional/ Directory

This directory contains optional FAPI compliance profiles that provide specific security extensions and enhancements. These profiles can be combined with mandatory profiles to test additional features and compliance requirements beyond the core FAPI specifications.

## Purpose

Optional profiles implement specific security mechanisms and extensions that enhance FAPI security but are not universally required. They can be mixed and matched based on the specific security architecture and compliance requirements of the target system.

## Design Principles

- **Modular**: Each profile tests a specific security mechanism independently
- **Composable**: Can be combined with any mandatory profile
- **Standalone**: No dependencies on other optional profiles (unless explicitly declared)
- **Standards-based**: Aligned with published RFCs and security specifications

## Implemented Profiles

### 1. Mutual TLS Authentication (`mtls.go`)

**Profile ID**: `mtls`  
**Dependencies**: None  
**Standards**: RFC 8705 (OAuth 2.0 Mutual-TLS Client Authentication)

#### Purpose
Tests mutual TLS (mTLS) client certificate authentication, which provides strong cryptographic client identity verification using X.509 certificates.

#### Key Tests
- **Client Certificate Configuration**: Validates certificate and private key are properly configured
- **Certificate Chain Validation**: Checks certificate chain integrity and format
- **TLS Handshake**: Tests mTLS handshake with the authorization server
- **Certificate Binding**: Validates token binding to client certificates (cnf claim)
- **Certificate Revocation Check**: Tests certificate revocation status validation

#### Security Benefits
- **Strong Authentication**: Cryptographic proof of client identity
- **Token Binding**: Prevents token theft/replay attacks
- **Non-repudiation**: Cryptographic audit trail
- **PKI Integration**: Works with enterprise certificate authorities

#### Configuration Requirements
```yaml
mtls:
  cert: "./certs/client.crt"  # Client certificate
  key: "./certs/client.key"   # Private key
```

#### Sample Output
```
=== Mutual TLS (mTLS) ===
Client Certificate Configuration         PASS
Certificate Chain Validation             PASS
TLS Handshake                            PASS
Certificate Binding                      SKIP
  Error: Certificate binding testing requires actual token issuance
Certificate Revocation Check             SKIP
  Error: Certificate revocation checking requires OCSP/CRL validation

Suite Summary: 5 total, 3 passed, 0 failed, 2 skipped
```

### 2. JWT Secured Authorization Request (`jar.go`)

**Profile ID**: `jar`  
**Dependencies**: None  
**Standards**: RFC 9101 (JWT Secured Authorization Request)

#### Purpose
Tests JWT Secured Authorization Request (JAR) implementation, which protects authorization request parameters by packaging them in signed JWT request objects.

#### Key Tests
- **Request Object Signing Key Configuration**: Validates signing key and key ID setup
- **Request Object Creation**: Tests JWT request object generation and signing
- **Request Object Validation**: Validates JWT structure, claims, and signatures
- **Authorization Request with Request Object**: Tests using request objects in authorization flow
- **Request Object Security Requirements**: Validates security configuration and algorithms

#### Security Benefits
- **Parameter Integrity**: Prevents authorization request tampering
- **Confidentiality**: Can encrypt sensitive request parameters
- **Authentication**: Cryptographically authenticates request origin
- **Replay Protection**: Includes timestamps and unique identifiers

#### Configuration Requirements
```yaml
private_key_jwt:
  kid: "key1"                    # Key identifier
  key: "./keys/private.pem"      # Private signing key
jwks_uri: "https://example.com/.well-known/jwks.json"  # Public key distribution
```

#### Sample Output
```
=== JWT Secured Authorization Request (JAR) ===
Request Object Signing Key Configuration PASS
Request Object Creation                  PASS
Request Object Validation                PASS
Authorization Request with Request Object SKIP
  Error: Authorization flow testing requires interactive session
Request Object Security Requirements     PASS

Suite Summary: 5 total, 3 passed, 0 failed, 2 skipped
```

### 3. Pushed Authorization Requests (`par.go`)

**Profile ID**: `par`  
**Dependencies**: None  
**Standards**: RFC 9126 (Pushed Authorization Requests)

#### Purpose
Tests Pushed Authorization Request (PAR) implementation, which improves security by pre-registering authorization request parameters at a dedicated endpoint.

#### Key Tests
- **PAR Endpoint Configuration**: Validates PAR endpoint setup and accessibility
- **PAR Request Format**: Tests proper PAR request structure and encoding
- **PAR Response Validation**: Validates PAR response format and required fields
- **Request URI Usage**: Tests using request_uri in authorization requests
- **PAR Security Requirements**: Validates security configuration and client authentication

#### Security Benefits
- **Parameter Protection**: Authorization parameters not exposed in browser
- **Request Validation**: Server-side validation before authorization
- **Reduced Attack Surface**: Shorter authorization URLs
- **Client Authentication**: Strong authentication at PAR endpoint

#### Configuration Requirements
```yaml
par_endpoint: "https://authserver.com/oauth2/par"  # PAR endpoint
# Plus client authentication (mTLS or private_key_jwt)
```

#### Sample Output
```
=== Pushed Authorization Requests (PAR) ===
PAR Endpoint Configuration               PASS
PAR Request Format                       PASS
PAR Response Validation                  FAIL
  Error: PAR request failed with status 400: invalid_request
Request URI Usage                        SKIP
  Error: Request URI usage testing requires full authorization flow
PAR Security Requirements                PASS

Suite Summary: 5 total, 3 passed, 1 failed, 1 skipped
```

## Placeholder Profiles (Future Implementation)

### 4. Client-Initiated Backchannel Authentication (`ciba.go`)

**Profile ID**: `ciba`  
**Dependencies**: None  
**Standards**: OIDC CIBA Core 1.0  
**Status**: Placeholder implementation

#### Purpose
Will test CIBA (Client-Initiated Backchannel Authentication) for decoupled authentication scenarios where user authentication happens out-of-band.

#### Planned Tests
- Backchannel authentication endpoint discovery
- Authentication request format and validation
- Poll/ping/push notification modes
- User authentication and consent flow
- Token delivery and binding

### 5. Demonstration of Proof-of-Possession (`dpop.go`)

**Profile ID**: `dpop`  
**Dependencies**: None  
**Standards**: RFC 9449 (DPoP)  
**Status**: Placeholder implementation

#### Purpose
Will test DPoP (Demonstration of Proof-of-Possession) token binding mechanism that cryptographically binds access tokens to client keys.

#### Planned Tests
- DPoP key generation and management
- DPoP proof creation and validation
- Token endpoint DPoP usage
- Resource server DPoP validation
- Key rotation and renewal

### 6. JWT Secured Authorization Response Mode (`jarm.go`)

**Profile ID**: `jarm`  
**Dependencies**: None  
**Standards**: JARM (JWT Secured Authorization Response Mode)  
**Status**: Placeholder implementation

#### Purpose
Will test JARM implementation for securing authorization response parameters using signed and/or encrypted JWTs.

#### Planned Tests
- Response mode negotiation
- JWT response creation and validation
- Response encryption (JWE) support
- Error response handling
- Response replay protection

## Profile Combinations

### Common Usage Patterns

#### Basic FAPI + mTLS
```bash
fapictl test --profiles oauth2-pkce,fapi-ro,mtls
# Tests FAPI Read-Only with mutual TLS authentication
```

#### FAPI + Request Objects
```bash
fapictl test --profiles oauth2-pkce,fapi-ro,fapi-rw,jar
# Tests FAPI Read-Write with signed request objects
```

#### Full Optional Stack
```bash
fapictl test --profiles oauth2-pkce,fapi-ro,fapi-rw,mtls,jar,par
# Comprehensive testing with all implemented optional profiles
```

#### Regional Profile Support
```bash
fapictl test --profiles oauth2-pkce,fapi-ro,fapi-rw,mtls,jar,ob-uk
# UK Open Banking typically requires mTLS and JAR
```

## Implementation Guidelines

### Adding New Optional Profiles

#### Profile Structure Template
```go
package optional

import (
    "context"
    "time"
    
    httpClient "fapictl/pkg/http" 
    "fapictl/pkg/verifier"
)

type MyFeatureVerifier struct {
    client *httpClient.Client
}

func NewMyFeatureVerifier(client *httpClient.Client) *MyFeatureVerifier {
    return &MyFeatureVerifier{client: client}
}

func (v *MyFeatureVerifier) Name() string {
    return "My Feature Name"
}

func (v *MyFeatureVerifier) Description() string {
    return "Tests specific security feature per RFC XXXX"
}

func (v *MyFeatureVerifier) Verify(ctx context.Context, config verifier.VerifierConfig) (*verifier.TestSuite, error) {
    suite := &verifier.TestSuite{
        Name:        v.Name(),
        Description: v.Description(),
        Tests:       []verifier.TestResult{},
    }
    
    startTime := time.Now()
    
    // Implement tests
    suite.Tests = append(suite.Tests, v.testFeatureRequirement1(config))
    suite.Tests = append(suite.Tests, v.testFeatureRequirement2(config))
    
    suite.Duration = time.Since(startTime)
    suite.Summary = v.calculateSummary(suite.Tests)
    
    return suite, nil
}
```

#### Registration in init.go
```go
DefaultRegistry.Register(&ProfileInfo{
    ID:          "my-feature",
    Name:        "My Feature Name", 
    Description: "Tests specific security feature",
    Type:        Optional,
    Dependencies: []string{}, // Usually none for optional profiles
    Conflicts:   []string{}, // If conflicts with other profiles
    Factory: func(client *httpClient.Client) verifier.Verifier {
        return optional.NewMyFeatureVerifier(client)
    },
})
```

### Best Practices

#### Test Design
- **Feature-focused**: Each profile should test one specific security mechanism
- **Configuration-aware**: Handle cases where the feature is not configured
- **Error-specific**: Provide clear guidance on configuration requirements
- **Standard-compliant**: Align with published specifications

#### Error Handling
```go
func (v *MyVerifier) testFeature(config verifier.VerifierConfig) verifier.TestResult {
    startTime := time.Now()
    
    // Check if feature is configured
    if !v.isFeatureConfigured(config) {
        return verifier.TestResult{
            Name:        "Feature Configuration",
            Description: "Verify feature is properly configured",
            Status:      verifier.StatusFail,
            Duration:    time.Since(startTime),
            Error:       "Feature requires specific configuration parameters",
            Details: map[string]interface{}{
                "required_config": []string{"param1", "param2"},
                "documentation": "https://example.com/feature-config",
            },
        }
    }
    
    // Test feature functionality
    // ...
}
```

#### Skip Conditions
Use SKIP status appropriately:
- **Configuration dependent**: Feature not configured, test not applicable
- **Interactive required**: Test requires manual user interaction
- **External dependency**: Test requires external service integration
- **Implementation limitation**: Test capability not yet implemented

```go
return verifier.TestResult{
    Name:        "Advanced Feature Test",
    Description: "Tests advanced feature capability",
    Status:      verifier.StatusSkip,
    Duration:    time.Since(startTime),
    Error:       "Test requires interactive user authentication session",
}
```

## Testing Scenarios

### Development Testing
```bash
# Test individual optional profiles
fapictl test --profiles mtls
fapictl test --profiles jar  
fapictl test --profiles par

# Test combinations
fapictl test --profiles oauth2-pkce,mtls
fapictl test --profiles fapi-ro,jar,par
```

### Configuration Validation
```bash
# Test with minimal config (should show configuration errors)
fapictl test --profiles mtls

# Test with proper config (should pass)
fapictl test --config full-config.yaml --profiles mtls
```

### Integration Testing
```bash
# Test real-world combinations
fapictl test --profiles oauth2-pkce,fapi-ro,fapi-rw,mtls,jar,par
fapictl test --profiles fapi-rw,mtls,jar,ob-uk
```

## Troubleshooting

### Common Issues

#### mTLS Configuration Problems
```
Client Certificate Configuration         FAIL
Error: mTLS certificate and key must be configured
```
**Solution**: Ensure `mtls.cert` and `mtls.key` paths are correct and files exist.

#### JAR Signing Issues
```
Request Object Signing Key Configuration FAIL
Error: Private key and key ID required for JAR
```
**Solution**: Configure `private_key_jwt.key` and `private_key_jwt.kid` in config.

#### PAR Endpoint Issues
```
PAR Response Validation                  FAIL
Error: PAR request failed with status 400
```
**Solution**: Verify PAR endpoint URL and client authentication configuration.

### Configuration Dependencies

Some optional profiles work better with specific configurations:

#### mTLS + Token Binding
```yaml
mtls:
  cert: "./certs/client.crt"
  key: "./certs/client.key"
# Server should return cnf claim in tokens for full testing
```

#### JAR + FAPI-RW
```yaml
private_key_jwt:
  kid: "key1"
  key: "./keys/private.pem"
jwks_uri: "https://authserver.com/.well-known/jwks.json"
# FAPI-RW often requires JAR for request object signing
```

#### PAR + Strong Authentication
```yaml
par_endpoint: "https://authserver.com/oauth2/par"
# PAR endpoint typically requires client authentication
mtls:
  cert: "./certs/client.crt" 
  key: "./certs/client.key"
```

This directory enables comprehensive testing of optional FAPI security mechanisms, allowing implementers to validate specific security features based on their architectural choices and compliance requirements.