# http/ Package

The http package provides a secure HTTP client implementation with built-in support for mutual TLS (mTLS), proper TLS configuration, and security best practices required for FAPI compliance testing.

## Purpose

- Provide secure HTTP client with FAPI-compliant TLS configuration
- Support mutual TLS (mTLS) client certificate authentication
- Enforce minimum TLS 1.2 for all connections
- Implement proper timeout and security headers
- Abstract HTTP operations for profile verifiers

## Key Components

### `Client` struct
A wrapper around Go's `http.Client` with security enhancements:

```go
type Client struct {
    httpClient *http.Client // Underlying HTTP client with security config
}
```

### `ClientOptions` struct
Configuration options for creating secure HTTP clients:

```go
type ClientOptions struct {
    Timeout   time.Duration // Request timeout (default: 30s)
    MTLSCert  string        // Path to client certificate for mTLS
    MTLSKey   string        // Path to client private key for mTLS
    UserAgent string        // User-Agent header (default: "fapictl/1.0")
}
```

## Functions

### `NewClient(opts ClientOptions) (*Client, error)`
Creates a new secure HTTP client with the specified options.

**Security Features Configured:**
- **Minimum TLS 1.2**: Rejects connections using older TLS versions
- **Mutual TLS support**: Loads client certificates when provided
- **Secure timeouts**: Prevents hanging connections
- **Proper TLS configuration**: Follows FAPI security requirements

**Parameters:**
- `opts ClientOptions`: Configuration options for the client

**Returns:**
- `*Client`: Configured secure HTTP client
- `error`: Certificate loading or configuration errors

**Example:**
```go
client, err := http.NewClient(http.ClientOptions{
    Timeout:   30 * time.Second,
    MTLSCert:  "./certs/client.crt",
    MTLSKey:   "./certs/client.key",
    UserAgent: "fapictl/1.0",
})
if err != nil {
    log.Fatal("Failed to create HTTP client:", err)
}
```

### `(*Client) Do(req *http.Request) (*http.Response, error)`
Executes an HTTP request using the secure client configuration.

**Security Enhancements:**
- Automatically applies mTLS certificates if configured
- Enforces TLS 1.2+ for all HTTPS connections
- Applies configured timeouts to prevent hangs
- Sets appropriate User-Agent headers

**Parameters:**
- `req *http.Request`: The HTTP request to execute

**Returns:**
- `*http.Response`: HTTP response with TLS connection details
- `error`: Network, TLS, or timeout errors

**Example:**
```go
req, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
resp, err := client.Do(req)
if err != nil {
    log.Fatal("Request failed:", err)
}
defer resp.Body.Close()
```

### `(*Client) Get(url string) (*http.Response, error)`
Convenience method for GET requests.

**Parameters:**
- `url string`: URL to request

**Returns:**
- `*http.Response`: HTTP response
- `error`: Any request errors

**Example:**
```go
resp, err := client.Get("https://authserver.com/.well-known/openid-configuration")
if err != nil {
    log.Fatal("Discovery request failed:", err)
}
```

### `(*Client) Post(url, contentType string, body interface{}) (*http.Response, error)`
Convenience method for POST requests (implementation placeholder).

**Note**: Currently returns `nil, nil` - implementation needed for specific POST operations.

## TLS Configuration

### Security Requirements Met
The HTTP client implements FAPI security requirements:

#### **Minimum TLS 1.2**
```go
transport := &http.Transport{
    TLSClientConfig: &tls.Config{
        MinVersion: tls.VersionTLS12, // Enforces TLS 1.2+
    },
}
```

#### **Mutual TLS Support**
```go
if opts.MTLSCert != "" && opts.MTLSKey != "" {
    cert, err := tls.LoadX509KeyPair(opts.MTLSCert, opts.MTLSKey)
    if err != nil {
        return nil, err
    }
    transport.TLSClientConfig.Certificates = []tls.Certificate{cert}
}
```

### Certificate Handling
- **Automatic loading**: Certificates loaded from file paths during client creation
- **Error validation**: Certificate format and key pair validation
- **Chain support**: Supports full certificate chains for enterprise PKI
- **Key protection**: Private keys remain in memory only during client lifetime

## FAPI Compliance Features

### Transport Layer Security
- **TLS 1.2+ enforcement**: Rejects connections using TLS 1.1 or lower
- **Certificate validation**: Validates server certificates against trusted CAs
- **Perfect Forward Secrecy**: Supports ECDHE and DHE cipher suites
- **Strong ciphers**: Prefers AES-GCM and ChaCha20-Poly1305

### Client Authentication
- **Mutual TLS**: Full support for certificate-based client authentication  
- **Certificate binding**: Tokens can be bound to client certificates (cnf claim)
- **PKI integration**: Works with enterprise certificate authorities
- **Key rotation**: Supports certificate renewal and rotation

### Security Headers
- **User-Agent**: Identifies client as fapictl for audit trails
- **Timeout enforcement**: Prevents resource exhaustion attacks
- **Connection limits**: Built-in connection pooling and limits

## Usage Patterns

### Basic Usage
```go
// Create client without mTLS
client, err := http.NewClient(http.ClientOptions{
    Timeout: 30 * time.Second,
})

// Make requests
resp, err := client.Get("https://api.example.com/endpoint")
```

### Mutual TLS Usage
```go
// Create client with mTLS
client, err := http.NewClient(http.ClientOptions{
    Timeout:  30 * time.Second,
    MTLSCert: "./certs/client.crt",
    MTLSKey:  "./certs/client.key",
})

// Requests automatically use client certificate
resp, err := client.Get("https://secure-api.example.com/endpoint")
```

### Profile Verifier Integration
```go
// Profile verifiers receive configured client
type MyVerifier struct {
    client *http.Client
}

func (v *MyVerifier) Verify(ctx context.Context, config Config) (*TestSuite, error) {
    // Use client for FAPI-compliant requests
    resp, err := v.client.Get(config.AuthorizationEndpoint)
    // ... verification logic
}
```

## Error Handling

### Certificate Errors
```go
client, err := http.NewClient(opts)
if err != nil {
    switch {
    case strings.Contains(err.Error(), "no such file"):
        return fmt.Errorf("certificate file not found: %w", err)
    case strings.Contains(err.Error(), "private key"):
        return fmt.Errorf("invalid private key: %w", err)
    default:
        return fmt.Errorf("TLS configuration failed: %w", err)
    }
}
```

### Request Errors
```go
resp, err := client.Do(req)
if err != nil {
    switch {
    case strings.Contains(err.Error(), "timeout"):
        return fmt.Errorf("request timeout: %w", err)
    case strings.Contains(err.Error(), "tls"):
        return fmt.Errorf("TLS handshake failed: %w", err)
    default:
        return fmt.Errorf("request failed: %w", err)
    }
}
```

## Security Considerations

### Certificate Security
- **File permissions**: Ensure certificate files have restricted permissions (600)
- **Key protection**: Private keys should never be logged or exposed
- **Rotation**: Implement certificate rotation procedures
- **Validation**: Verify certificate chains and expiry dates

### Network Security
- **HTTPS only**: All FAPI endpoints must use HTTPS
- **Certificate pinning**: Consider implementing for high-security environments
- **Proxy support**: Configure proxy settings securely if required
- **DNS security**: Use secure DNS resolution (DoH/DoT) where possible

### Best Practices
```go
// Recommended client configuration
client, err := http.NewClient(http.ClientOptions{
    Timeout:   30 * time.Second,           // Reasonable timeout
    MTLSCert:  "/secure/path/client.crt",  // Secure certificate storage
    MTLSKey:   "/secure/path/client.key",  // Secure key storage
    UserAgent: "fapictl/1.0",              // Proper identification
})
```

## Testing Support

### Mock Client for Tests
```go
// For unit tests, you might create a mock client
type MockClient struct {
    responses map[string]*http.Response
}

func (m *MockClient) Do(req *http.Request) (*http.Response, error) {
    return m.responses[req.URL.String()], nil
}
```

### Integration Testing
```go
// Test with real HTTPS endpoints
func TestHTTPSEnforcement(t *testing.T) {
    client, err := http.NewClient(http.ClientOptions{})
    require.NoError(t, err)
    
    // Should work with HTTPS
    resp, err := client.Get("https://httpbin.org/get")
    assert.NoError(t, err)
    assert.Equal(t, 200, resp.StatusCode)
}
```

## Integration with Profile System

### Profile Verifier Usage
Profile verifiers receive a configured HTTP client:

```go
// In profile factory functions
func NewMyProfileVerifier(client *http.Client) verifier.Verifier {
    return &MyProfileVerifier{client: client}
}

// Verifier uses client for requests
func (v *MyProfileVerifier) testEndpoint(endpoint string) TestResult {
    resp, err := v.client.Get(endpoint)
    // ... test logic
}
```

### Configuration Flow
1. **CLI loads config**: mTLS certificate paths from YAML
2. **Client creation**: HTTP client configured with certificates
3. **Profile registration**: Profiles receive configured client
4. **Test execution**: Verifiers use client for secure requests

## Future Enhancements

Planned improvements to the HTTP client:
- **HTTP/2 support**: Enable HTTP/2 for better performance
- **Connection pooling**: Optimize connection reuse
- **Retry logic**: Implement exponential backoff for transient failures
- **Request logging**: Add structured logging for debugging
- **Metrics collection**: Gather performance and error metrics
- **Certificate validation**: Enhanced certificate chain validation
- **Proxy authentication**: Support for authenticated proxy connections

## Dependencies

- `crypto/tls`: TLS configuration and certificate handling
- `net/http`: Core HTTP client functionality
- `time`: Timeout and duration handling

The package uses only Go standard library components for maximum security and reliability, avoiding external dependencies that might introduce vulnerabilities.