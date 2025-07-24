# crypto/ Package

The crypto package provides cryptographic utilities required for FAPI compliance testing, with a focus on PKCE (Proof Key for Code Exchange) implementation and related security mechanisms.

## Purpose

- Implement PKCE challenge/verifier generation per RFC 7636
- Provide cryptographic primitives for OAuth2 and FAPI security features
- Ensure secure random generation and proper encoding
- Support various cryptographic operations needed for compliance testing

## Key Components

### PKCE Implementation

PKCE (Proof Key for Code Exchange) is a security extension to OAuth 2.0 authorization code flow that provides protection against authorization code interception attacks.

#### `PKCEChallenge` struct
Represents a complete PKCE challenge/verifier pair:

```go
type PKCEChallenge struct {
    Verifier  string // Code verifier (random string)
    Challenge string // Code challenge (derived from verifier)
    Method    string // Challenge method ("S256" for SHA256)
}
```

## Functions

### `GeneratePKCEChallenge() (*PKCEChallenge, error)`
Generates a new PKCE challenge/verifier pair following RFC 7636 specifications.

**Implementation Details:**
- Generates 32 random bytes (256 bits) for the code verifier
- Uses `crypto/rand` for cryptographically secure randomness
- Encodes verifier with base64url (no padding) per RFC 7636
- Creates challenge using SHA256 hash of the verifier
- Always uses S256 method (required for FAPI compliance)

**Returns:**
- `*PKCEChallenge`: Complete challenge/verifier pair
- `error`: Any random generation or encoding errors

**Example:**
```go
challenge, err := crypto.GeneratePKCEChallenge()
if err != nil {
    log.Fatal("PKCE generation failed:", err)
}

fmt.Printf("Verifier: %s\n", challenge.Verifier)
fmt.Printf("Challenge: %s\n", challenge.Challenge) 
fmt.Printf("Method: %s\n", challenge.Method) // Always "S256"
```

### `VerifyPKCEChallenge(verifier, challenge string) bool`
Verifies that a given challenge was correctly derived from the verifier.

**Parameters:**
- `verifier`: The original code verifier string
- `challenge`: The code challenge to verify

**Returns:**
- `bool`: True if the challenge matches the verifier, false otherwise

**Example:**
```go
isValid := crypto.VerifyPKCEChallenge(challenge.Verifier, challenge.Challenge)
if !isValid {
    log.Fatal("PKCE challenge verification failed")
}
```

### Internal Functions

#### `generateCodeVerifier() (string, error)`
Internal function that generates a cryptographically secure code verifier.

**Implementation:**
- Generates 32 random bytes using `crypto/rand.Read()`
- Encodes bytes using base64url without padding
- Results in 43-character string (meets RFC 7636 requirements)

#### `generateCodeChallenge(verifier string) string`
Internal function that derives a code challenge from a verifier.

**Implementation:**
- Computes SHA256 hash of the verifier string
- Encodes hash using base64url without padding
- Results in 43-character challenge string

## PKCE Security Properties

### RFC 7636 Compliance
- **Verifier length**: 43-128 characters (we use 43 for consistency)
- **Character set**: Unreserved characters as defined in RFC 3986
- **Encoding**: Base64url without padding per RFC 4648
- **Challenge method**: S256 (SHA256) only (FAPI requirement)

### Security Benefits
- **Authorization code interception protection**: Even if code is intercepted, attacker cannot exchange it without the verifier
- **No client secret required**: Suitable for public clients (mobile apps, SPAs)
- **Cryptographically strong**: Uses SHA256 and secure random generation
- **Replay protection**: Each authorization request uses a unique verifier

## FAPI Compliance

### FAPI Requirements Met
- **S256 method mandatory**: Plain method is not supported (security requirement)
- **Secure random generation**: Uses `crypto/rand` for unpredictability
- **Proper encoding**: Base64url without padding per specifications
- **Challenge verification**: Supports server-side verification of challenges

### Integration with FAPI Profiles
The PKCE implementation is used by:
- **oauth2-pkce profile**: Basic OAuth2 + PKCE verification
- **fapi-ro profile**: FAPI Read-Only requires PKCE
- **fapi-rw profile**: FAPI Read-Write requires PKCE with S256 method
- **Regional profiles**: UK Open Banking, Brazil Open Finance, etc.

## Usage Patterns

### Authorization Request
```go
// Generate PKCE challenge for authorization request
challenge, err := crypto.GeneratePKCEChallenge()
if err != nil {
    return fmt.Errorf("PKCE generation failed: %w", err)
}

// Build authorization URL with PKCE parameters
authURL := buildAuthURL(baseURL, map[string]string{
    "code_challenge":        challenge.Challenge,
    "code_challenge_method": challenge.Method, // "S256"
    // ... other parameters
})
```

### Token Exchange
```go
// Use verifier in token exchange request
tokenRequest := map[string]string{
    "grant_type":    "authorization_code",
    "code":          authCode,
    "code_verifier": challenge.Verifier, // Proves client identity
    // ... other parameters
}
```

### Testing and Validation
```go
// Verify PKCE implementation correctness
func TestPKCECompliance(t *testing.T) {
    challenge, err := crypto.GeneratePKCEChallenge()
    require.NoError(t, err)
    
    // Verify properties
    assert.Equal(t, "S256", challenge.Method)
    assert.Len(t, challenge.Verifier, 43) // Base64url of 32 bytes
    assert.Len(t, challenge.Challenge, 43) // Base64url of SHA256 (32 bytes)
    
    // Verify challenge derivation
    assert.True(t, crypto.VerifyPKCEChallenge(challenge.Verifier, challenge.Challenge))
}
```

## Error Handling

### Possible Errors
- **Random generation failure**: `crypto/rand.Read()` fails (system entropy issues)
- **Encoding errors**: Base64 encoding failures (extremely rare)

### Error Recovery
```go
challenge, err := crypto.GeneratePKCEChallenge()
if err != nil {
    // Log error with context but don't expose details
    log.Printf("PKCE generation failed: %v", err)
    return fmt.Errorf("cryptographic operation failed")
}
```

## Security Considerations

### Best Practices
- Always use the generated verifier exactly once
- Store verifier securely on client side until token exchange
- Never transmit verifier over insecure channels
- Validate challenge/verifier pairs server-side

### Cryptographic Strength
- Uses `crypto/rand` for cryptographically secure randomness
- SHA256 provides 256-bit security level
- Base64url encoding prevents padding-related issues
- Timing-safe verification prevents side-channel attacks

## Testing Support

### Mock Generation for Tests
```go
// For deterministic testing, you might need predictable values
func GenerateTestPKCEChallenge(seed string) *PKCEChallenge {
    // Use seed to generate deterministic but valid PKCE pair
    // Only for testing - never use predictable values in production
}
```

### Compliance Testing
The package supports various compliance scenarios:
- FAPI profile requirements verification
- OAuth2 security best practices validation
- Regional standard compliance (UK Open Banking, etc.)

## Future Extensions

The crypto package is designed to be extensible for additional FAPI requirements:
- JWT signing and verification
- JWE encryption/decryption for request objects
- DPoP proof generation
- Certificate-bound access tokens
- Additional cryptographic primitives as needed

## Dependencies

- `crypto/rand`: Secure random number generation
- `crypto/sha256`: SHA256 hashing for challenges
- `encoding/base64`: Base64url encoding without padding

No external dependencies - uses only Go standard library for maximum security and reliability.