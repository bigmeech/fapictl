# verifier/ Package

The verifier package provides the core testing framework for fapictl, including test execution, result aggregation, and multi-format reporting. It defines the interfaces and structures that enable the modular profile system.

## Purpose

- Define the `Verifier` interface that all profile implementations must satisfy
- Provide test result structures and status management
- Implement test execution orchestration via `TestRunner`
- Generate comprehensive reports in multiple formats (text, JSON, YAML, HTML)
- Support test suite aggregation and summary statistics

## Key Components

### Core Interfaces

#### `Verifier` Interface
The fundamental interface that all profile verifiers must implement:

```go
type Verifier interface {
    Name() string                                                    // Profile display name
    Description() string                                             // Profile description
    Verify(ctx context.Context, config VerifierConfig) (*TestSuite, error) // Run tests
}
```

### Data Structures

#### `TestResult` struct
Represents the result of a single test within a profile:

```go
type TestResult struct {
    Name        string        `json:"name"`        // Test name/identifier
    Description string        `json:"description"` // Test description
    Status      TestStatus    `json:"status"`      // PASS/FAIL/SKIP
    Duration    time.Duration `json:"duration"`    // Test execution time
    Error       string        `json:"error,omitempty"`    // Error message if failed
    Details     interface{}   `json:"details,omitempty"`  // Additional test details
}
```

#### `TestStatus` enum
Possible test outcomes:

```go
type TestStatus string

const (
    StatusPass TestStatus = "PASS" // Test passed successfully
    StatusFail TestStatus = "FAIL" // Test failed
    StatusSkip TestStatus = "SKIP" // Test was skipped (not applicable/requires manual verification)
)
```

#### `TestSuite` struct
Represents the complete test results for a single profile:

```go
type TestSuite struct {
    Name        string        `json:"name"`        // Profile name
    Description string        `json:"description"` // Profile description  
    Tests       []TestResult  `json:"tests"`       // Individual test results
    Duration    time.Duration `json:"duration"`    // Total suite execution time
    Summary     TestSummary   `json:"summary"`     // Aggregated statistics
}
```

#### `TestSummary` struct
Aggregated statistics for a test suite:

```go
type TestSummary struct {
    Total   int `json:"total"`   // Total number of tests
    Passed  int `json:"passed"`  // Number of passed tests
    Failed  int `json:"failed"`  // Number of failed tests
    Skipped int `json:"skipped"` // Number of skipped tests
}
```

#### `VerifierConfig` struct
Configuration passed to verifiers containing all necessary connection and authentication details:

```go
type VerifierConfig struct {
    ClientID                string            `json:"client_id"`
    ClientSecret            string            `json:"client_secret,omitempty"`  
    RedirectURI             string            `json:"redirect_uri"`
    AuthorizationEndpoint   string            `json:"authorization_endpoint"`
    TokenEndpoint           string            `json:"token_endpoint"`
    PAREndpoint             string            `json:"par_endpoint,omitempty"`
    IntrospectionEndpoint   string            `json:"introspection_endpoint,omitempty"`
    JWKSURI                 string            `json:"jwks_uri,omitempty"`
    OIDCConfig              string            `json:"oidc_config,omitempty"`
    Scopes                  []string          `json:"scopes"`
    MTLSCert                string            `json:"mtls_cert,omitempty"`
    MTLSKey                 string            `json:"mtls_key,omitempty"`
    PrivateKeyJWTKey        string            `json:"private_key_jwt_key,omitempty"`
    PrivateKeyJWTKID        string            `json:"private_key_jwt_kid,omitempty"`
    AdditionalParams        map[string]string `json:"additional_params,omitempty"`
}
```

### Test Execution

#### `TestRunner` struct
Orchestrates test execution across multiple verifiers:

```go
type TestRunner struct {
    verifiers []Verifier      // List of verifiers to execute
    config    VerifierConfig  // Configuration for all verifiers
}
```

### Reporting System

#### `Reporter` struct
Handles multi-format report generation:

```go
type Reporter struct {
    // Internal implementation for generating reports
}
```

## Functions

### TestRunner Functions

#### `NewTestRunner(config VerifierConfig) *TestRunner`
Creates a new test runner with the specified configuration.

**Parameters:**
- `config VerifierConfig`: Configuration that will be passed to all verifiers

**Returns:**
- `*TestRunner`: New test runner instance

**Example:**
```go
config := verifier.VerifierConfig{
    ClientID: "test-client",
    AuthorizationEndpoint: "https://auth.example.com/oauth2/authorize",
    TokenEndpoint: "https://auth.example.com/oauth2/token",
    // ... other configuration
}
runner := verifier.NewTestRunner(config)
```

#### `(*TestRunner) AddVerifier(v Verifier)`
Adds a verifier to the test execution list.

**Parameters:**
- `v Verifier`: The verifier implementation to add

**Example:**
```go
runner.AddVerifier(oauth2.NewAuthCodePKCEVerifier(httpClient))
runner.AddVerifier(fapi.NewFAPIReadOnlyVerifier(httpClient))
```

#### `(*TestRunner) RunAll(ctx context.Context) ([]*TestSuite, error)`
Executes all registered verifiers and returns their results.

**Parameters:**
- `ctx context.Context`: Context for timeout and cancellation control

**Returns:**
- `[]*TestSuite`: Test results from all verifiers
- `error`: Any execution errors

**Example:**
```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
defer cancel()

suites, err := runner.RunAll(ctx)
if err != nil {
    log.Fatal("Test execution failed:", err)
}
```

### Reporter Functions

#### `NewReporter() *Reporter`
Creates a new report generator.

**Returns:**
- `*Reporter`: New reporter instance

#### `(*Reporter) GenerateReport(suites []*TestSuite, format string, writer io.Writer) error`
Generates a report in the specified format.

**Parameters:**
- `suites []*TestSuite`: Test results to include in report
- `format string`: Output format ("text", "json", "yaml", "html")
- `writer io.Writer`: Output destination

**Returns:**
- `error`: Any generation or writing errors

**Example:**
```go
reporter := verifier.NewReporter()

// Generate text report to stdout
err := reporter.GenerateReport(suites, "text", os.Stdout)

// Generate JSON report to file
file, _ := os.Create("report.json")
defer file.Close()
err = reporter.GenerateReport(suites, "json", file)
```

## Report Formats

### Text Format
Human-readable console output:
```
=== OAuth2 Authorization Code + PKCE ===
Verifies OAuth 2.0 Authorization Code flow with PKCE (RFC 7636) compliance
Duration: 1.2s

PKCE Challenge Generation                PASS
Authorization Endpoint Discovery         PASS
Token Endpoint Discovery                 FAIL
  Error: Connection timeout

Suite Summary: 3 total, 2 passed, 1 failed, 0 skipped
```

### JSON Format
Machine-readable structured output:
```json
{
  "timestamp": "2025-07-23T07:00:00Z",
  "test_suites": [
    {
      "name": "OAuth2 Authorization Code + PKCE",
      "description": "Verifies OAuth 2.0 Authorization Code flow with PKCE compliance",
      "tests": [
        {
          "name": "PKCE Challenge Generation",
          "description": "Generate PKCE code verifier and challenge",
          "status": "PASS",
          "duration": 1234567,
          "details": {
            "challenge_method": "S256",
            "verifier_length": 43
          }
        }
      ],
      "duration": 1200000000,
      "summary": {
        "total": 1,
        "passed": 1,
        "failed": 0,
        "skipped": 0
      }
    }
  ],
  "summary": {
    "total": 1,
    "passed": 1,
    "failed": 0,
    "skipped": 0
  }
}
```

### YAML Format
Human-readable structured output:
```yaml
timestamp: 2025-07-23T07:00:00Z
test_suites:
  - name: OAuth2 Authorization Code + PKCE
    description: Verifies OAuth 2.0 Authorization Code flow with PKCE compliance
    tests:
      - name: PKCE Challenge Generation
        description: Generate PKCE code verifier and challenge
        status: PASS
        duration: 1234567ns
```

### HTML Format
Rich web-based report with styling and interactive elements:
```html
<!DOCTYPE html>
<html>
<head>
    <title>FAPI Compliance Test Report</title>
    <style>/* Styling for professional appearance */</style>
</head>
<body>
    <div class="header">
        <h1>FAPI Compliance Test Report</h1>
        <p>Generated: 2025-07-23 07:00:00 UTC</p>
    </div>
    <!-- Test results with color coding and details -->
</body>
</html>
```

## Usage Patterns

### Basic Test Execution
```go
// 1. Create configuration
config := verifier.VerifierConfig{
    ClientID: "test-client",
    AuthorizationEndpoint: "https://auth.example.com/oauth2/authorize",
    TokenEndpoint: "https://auth.example.com/oauth2/token",
    Scopes: []string{"openid"},
}

// 2. Create test runner
runner := verifier.NewTestRunner(config)

// 3. Add verifiers (profiles)
runner.AddVerifier(oauth2Verifier)
runner.AddVerifier(fapiVerifier)

// 4. Execute tests
ctx := context.Background()
suites, err := runner.RunAll(ctx)

// 5. Generate report
reporter := verifier.NewReporter()
err = reporter.GenerateReport(suites, "text", os.Stdout)
```

### Custom Verifier Implementation
```go
type MyCustomVerifier struct {
    client *http.Client
}

func (v *MyCustomVerifier) Name() string {
    return "My Custom Profile"
}

func (v *MyCustomVerifier) Description() string {
    return "Custom verification logic for specific requirements"
}

func (v *MyCustomVerifier) Verify(ctx context.Context, config verifier.VerifierConfig) (*verifier.TestSuite, error) {
    suite := &verifier.TestSuite{
        Name:        v.Name(),
        Description: v.Description(),
        Tests:       []verifier.TestResult{},
    }
    
    startTime := time.Now()
    
    // Test 1: Custom verification logic
    suite.Tests = append(suite.Tests, v.runCustomTest(config))
    
    suite.Duration = time.Since(startTime)
    suite.Summary = calculateSummary(suite.Tests)
    
    return suite, nil
}

func (v *MyCustomVerifier) runCustomTest(config verifier.VerifierConfig) verifier.TestResult {
    startTime := time.Now()
    
    // Implement test logic
    if testCondition {
        return verifier.TestResult{
            Name:        "Custom Test",
            Description: "Tests custom requirement",
            Status:      verifier.StatusPass,
            Duration:    time.Since(startTime),
            Details: map[string]interface{}{
                "custom_detail": "success",
            },
        }
    }
    
    return verifier.TestResult{
        Name:        "Custom Test",
        Description: "Tests custom requirement", 
        Status:      verifier.StatusFail,
        Duration:    time.Since(startTime),
        Error:       "Custom test failed",
    }
}
```

## Error Handling

### Test Execution Errors
```go
suites, err := runner.RunAll(ctx)
if err != nil {
    // Handle execution errors
    log.Printf("Test execution failed: %v", err)
    return
}

// Check for test failures
for _, suite := range suites {
    if suite.Summary.Failed > 0 {
        log.Printf("Profile %s had %d failing tests", suite.Name, suite.Summary.Failed)
    }
}
```

### Report Generation Errors
```go
err := reporter.GenerateReport(suites, "json", writer)
if err != nil {
    switch {
    case strings.Contains(err.Error(), "unsupported format"):
        log.Fatal("Invalid report format specified")
    case strings.Contains(err.Error(), "write"):
        log.Fatal("Failed to write report output")
    default:
        log.Fatalf("Report generation failed: %v", err)
    }
}
```

## Best Practices

### Test Design
- **Atomic tests**: Each test should verify one specific requirement
- **Clear naming**: Use descriptive test names that explain what is being verified
- **Detailed errors**: Provide specific error messages for failures
- **Skip appropriately**: Use SKIP status for tests that require manual verification or aren't applicable

### Result Details
```go
// Good: Provide useful details for passed tests
return verifier.TestResult{
    Name:   "HTTPS Enforcement",
    Status: verifier.StatusPass,
    Details: map[string]interface{}{
        "authorization_endpoint_scheme": "https",
        "token_endpoint_scheme":         "https",
        "all_endpoints_secure":          true,
    },
}

// Good: Provide specific error information for failures
return verifier.TestResult{
    Name:   "Client Authentication",
    Status: verifier.StatusFail,
    Error:  "Neither mTLS nor private_key_jwt authentication configured",
    Details: map[string]interface{}{
        "mtls_cert_provided":      false,
        "private_key_jwt_provided": false,
        "required_methods":        []string{"tls_client_auth", "private_key_jwt"},
    },
}
```

### Performance Considerations
- **Timeouts**: Always use context with reasonable timeouts
- **Parallel execution**: Tests within a verifier run sequentially, but multiple verifiers can run concurrently
- **Resource cleanup**: Clean up resources (HTTP connections, temporary files) in test implementations
- **Memory usage**: Avoid storing large response bodies in test details

## Integration with Profile System

The verifier package serves as the foundation for the entire profile system:

1. **Profile registration**: Profiles register factory functions that create verifiers
2. **Configuration flow**: CLI config is converted to `VerifierConfig`
3. **Test execution**: `TestRunner` orchestrates verifier execution
4. **Result aggregation**: Multiple profile results are combined
5. **Report generation**: Results are formatted for output

This design enables the modular, extensible architecture that supports mandatory, optional, and regional FAPI profiles.