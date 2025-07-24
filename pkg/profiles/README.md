# profiles/ Package

The profiles package implements the modular plugin architecture for FAPI compliance testing. It provides a registry system for managing different compliance profiles and their dependencies, enabling flexible composition of test suites.

## Purpose

- Implement modular plugin architecture for FAPI compliance profiles
- Provide profile registry with dependency resolution and conflict detection
- Support mandatory, optional, and regional profile categorization
- Enable dynamic profile composition for comprehensive compliance testing
- Abstract profile implementations behind a unified interface

## Architecture Overview

```
profiles/
├── registry.go           # Profile registry and dependency management
├── init.go              # Profile registration and factory setup
├── mandatory/           # Core FAPI profiles (always required)
│   ├── oauth2_pkce.go   # OAuth2 Authorization Code + PKCE
│   ├── fapi_ro.go       # FAPI Read-Only Profile
│   └── fapi_rw.go       # FAPI Read-Write Profile
├── optional/            # Extension profiles (feature-specific)
│   ├── mtls.go          # Mutual TLS authentication
│   ├── jar.go           # JWT Secured Authorization Request
│   ├── par.go           # Pushed Authorization Requests
│   └── ...              # Other optional profiles
└── regional/            # Country/region-specific profiles
    ├── ob_uk.go         # UK Open Banking
    ├── open_finance_br.go # Brazil Open Finance
    └── ...              # Other regional profiles
```

## Key Components

### Profile Registry System

#### `ProfileRegistry` struct
Central registry for managing all available profiles:

```go
type ProfileRegistry struct {
    profiles map[string]*ProfileInfo // Map of profile ID to profile info
}
```

#### `ProfileInfo` struct
Complete metadata and factory for a compliance profile:

```go
type ProfileInfo struct {
    ID          string      `json:"id"`          // Unique profile identifier
    Name        string      `json:"name"`        // Display name
    Description string      `json:"description"` // Detailed description
    Type        ProfileType `json:"type"`        // Profile category
    Dependencies []string   `json:"dependencies,omitempty"` // Required profiles
    Conflicts   []string    `json:"conflicts,omitempty"`    // Conflicting profiles
    Factory     func(*httpClient.Client) verifier.Verifier `json:"-"` // Verifier factory
}
```

#### `ProfileType` enum
Profile categorization system:

```go
type ProfileType string

const (
    Mandatory ProfileType = "mandatory" // Core FAPI profiles
    Optional  ProfileType = "optional"  // Feature-specific extensions
    Regional  ProfileType = "regional"  // Country/region-specific
)
```

### Global Registry
```go
var DefaultRegistry = NewProfileRegistry() // Global registry instance
```

## Registry Functions

### `NewProfileRegistry() *ProfileRegistry`
Creates a new profile registry.

**Returns:**
- `*ProfileRegistry`: Empty registry ready for profile registration

### `(*ProfileRegistry) Register(profile *ProfileInfo) error`
Registers a new profile in the registry.

**Parameters:**
- `profile *ProfileInfo`: Complete profile information including factory function

**Returns:**
- `error`: Registration errors (empty ID, missing factory, etc.)

**Example:**
```go
registry.Register(&ProfileInfo{
    ID:          "oauth2-pkce",
    Name:        "OAuth2 Authorization Code + PKCE", 
    Description: "OAuth 2.0 Authorization Code flow with PKCE (RFC 7636)",
    Type:        Mandatory,
    Factory: func(client *httpClient.Client) verifier.Verifier {
        return mandatory.NewAuthCodePKCEVerifier(client)
    },
})
```

### `(*ProfileRegistry) Get(id string) (*ProfileInfo, bool)`
Retrieves a specific profile by ID.

**Parameters:**
- `id string`: Profile identifier

**Returns:**
- `*ProfileInfo`: Profile information if found
- `bool`: True if profile exists, false otherwise

### `(*ProfileRegistry) List() []*ProfileInfo`
Returns all registered profiles sorted by type then ID.

**Returns:**
- `[]*ProfileInfo`: All profiles ordered by: Mandatory → Optional → Regional

### `(*ProfileRegistry) ListByType(profileType ProfileType) []*ProfileInfo`
Returns profiles of a specific type.

**Parameters:**
- `profileType ProfileType`: Type filter (Mandatory, Optional, Regional)

**Returns:**
- `[]*ProfileInfo`: Profiles of the specified type, sorted by ID

### `(*ProfileRegistry) ResolveProfiles(profileIDs []string) ([]*ProfileInfo, error)`
Resolves a list of profile IDs, validating dependencies and conflicts.

**Validation Logic:**
- Checks that all profile IDs exist
- Validates that all dependencies are included
- Ensures no conflicting profiles are selected
- Returns resolved profiles in dependency order

**Parameters:**
- `profileIDs []string`: List of profile IDs to resolve

**Returns:**
- `[]*ProfileInfo`: Resolved profiles with dependencies validated
- `error`: Dependency or conflict resolution errors

**Example:**
```go
profiles, err := registry.ResolveProfiles([]string{"fapi-rw", "ob-uk"})
if err != nil {
    // Handle dependency errors like:
    // "profile fapi-rw requires dependency oauth2-pkce"
    // "profile ob-uk requires dependency mtls"
}
```

### `(*ProfileRegistry) CreateVerifiers(profileIDs []string, client *httpClient.Client) ([]verifier.Verifier, error)`
Creates verifier instances for the specified profiles.

**Process:**
1. Resolves profiles and validates dependencies
2. Creates verifier instances using factory functions
3. Returns ready-to-use verifiers

**Parameters:**
- `profileIDs []string`: Profile IDs to instantiate
- `client *httpClient.Client`: HTTP client for verifiers

**Returns:**
- `[]verifier.Verifier`: Instantiated verifier implementations
- `error`: Resolution or instantiation errors

## Profile Categories

### Mandatory Profiles
Core FAPI compliance profiles that form the foundation:

#### `oauth2-pkce`
- **Purpose**: OAuth 2.0 Authorization Code flow with PKCE
- **Dependencies**: None (baseline requirement)
- **Tests**: PKCE generation, endpoint discovery, authorization flow

#### `fapi-ro` 
- **Purpose**: FAPI Read-Only security profile
- **Dependencies**: `oauth2-pkce`
- **Tests**: HTTPS enforcement, strong authentication, security headers

#### `fapi-rw`
- **Purpose**: FAPI Read-Write security profile (payment initiation)
- **Dependencies**: `oauth2-pkce`, `fapi-ro`
- **Tests**: Request objects, intent registration, token binding

### Optional Profiles
Feature-specific extensions that can be combined as needed:

#### `mtls`
- **Purpose**: Mutual TLS client certificate authentication
- **Dependencies**: None
- **Tests**: Certificate configuration, TLS handshake, binding

#### `jar`
- **Purpose**: JWT Secured Authorization Request
- **Dependencies**: None
- **Tests**: Request object signing, validation, security requirements

#### `par`
- **Purpose**: Pushed Authorization Requests
- **Dependencies**: None
- **Tests**: PAR endpoint, request format, response validation

#### `ciba`, `dpop`, `jarm`
- **Purpose**: Additional FAPI extensions
- **Status**: Placeholder implementations (future development)

### Regional Profiles
Country or region-specific compliance requirements:

#### `ob-uk`
- **Purpose**: UK Open Banking Implementation Entity (OBIE) compliance
- **Dependencies**: `fapi-rw`, `mtls`, `jar`
- **Tests**: OBIE scopes, intent registration, directory certificates

#### `open-finance-br`
- **Purpose**: Brazil Open Finance (Sistema Financeiro Aberto)
- **Dependencies**: `fapi-rw`, `mtls`, `jar`
- **Tests**: Brazilian scopes, CPF/CNPJ, LGPD compliance, PIX integration

#### `berlin-group`, `cdr-au`, `open-banking-ng`
- **Purpose**: Other regional standards
- **Status**: Placeholder implementations (future development)

## Usage Patterns

### Basic Profile Usage
```go
// Get default registry
registry := profiles.DefaultRegistry

// List available profiles
allProfiles := registry.List()
mandatoryProfiles := registry.ListByType(profiles.Mandatory)

// Create verifiers for specific profiles
verifiers, err := registry.CreateVerifiers(
    []string{"oauth2-pkce", "fapi-ro"}, 
    httpClient,
)
```

### CLI Integration
```go
// CLI specifies profiles to test
profileIDs := []string{"oauth2-pkce", "fapi-ro", "mtls", "jar"}

// Registry creates and validates verifiers
verifiers, err := profiles.DefaultRegistry.CreateVerifiers(profileIDs, client)
if err != nil {
    fmt.Fprintf(os.Stderr, "Profile resolution failed: %v\n", err)
    os.Exit(1)
}

// Add verifiers to test runner
runner := verifier.NewTestRunner(config)
for _, v := range verifiers {
    runner.AddVerifier(v)
}
```

### Custom Profile Registration
```go
// Register a custom profile
registry.Register(&ProfileInfo{
    ID:          "custom-bank",
    Name:        "Custom Bank Profile",
    Description: "Bank-specific compliance requirements",
    Type:        Regional,
    Dependencies: []string{"fapi-rw", "mtls"},
    Factory: func(client *httpClient.Client) verifier.Verifier {
        return NewCustomBankVerifier(client)
    },
})
```

## Dependency Resolution

### Dependency Graph Example
```
ob-uk
├── fapi-rw
│   ├── fapi-ro
│   │   └── oauth2-pkce
│   └── oauth2-pkce (already resolved)
├── mtls
└── jar
```

### Resolution Process
1. **Expansion**: Add all dependencies recursively
2. **Validation**: Check that all dependencies are available
3. **Conflict Detection**: Ensure no conflicting profiles
4. **Ordering**: Return profiles in dependency order

### Error Examples
```go
// Missing dependency
profiles.DefaultRegistry.ResolveProfiles([]string{"fapi-rw"})
// Error: "profile fapi-rw requires dependency oauth2-pkce"

// Unknown profile
profiles.DefaultRegistry.ResolveProfiles([]string{"invalid-profile"})
// Error: "unknown profile: invalid-profile"

// Conflict (hypothetical)
profiles.DefaultRegistry.ResolveProfiles([]string{"profile-a", "profile-b"})
// Error: "profile profile-a conflicts with profile-b"
```

## Profile Implementation Guidelines

### Creating a New Profile

1. **Choose appropriate directory**:
   - `mandatory/` - Core FAPI requirements
   - `optional/` - Feature-specific extensions  
   - `regional/` - Country/region-specific

2. **Implement the Verifier interface**:
```go
type MyProfileVerifier struct {
    client *httpClient.Client
}

func NewMyProfileVerifier(client *httpClient.Client) *MyProfileVerifier {
    return &MyProfileVerifier{client: client}
}

func (v *MyProfileVerifier) Name() string {
    return "My Profile Name"
}

func (v *MyProfileVerifier) Description() string {
    return "Detailed description of what this profile tests"
}

func (v *MyProfileVerifier) Verify(ctx context.Context, config verifier.VerifierConfig) (*verifier.TestSuite, error) {
    // Implementation details
}
```

3. **Register in init.go**:
```go
DefaultRegistry.Register(&ProfileInfo{
    ID:          "my-profile",
    Name:        "My Profile Name",
    Description: "Detailed description",
    Type:        Optional, // or Mandatory/Regional
    Dependencies: []string{"oauth2-pkce"}, // if needed
    Factory: func(client *httpClient.Client) verifier.Verifier {
        return NewMyProfileVerifier(client)
    },
})
```

### Best Practices

#### Test Organization
- **Logical grouping**: Group related tests within a profile
- **Clear naming**: Use descriptive test names
- **Comprehensive coverage**: Test positive and negative cases
- **Error handling**: Provide specific error messages

#### Dependency Management
- **Minimal dependencies**: Only require what's actually needed
- **Logical relationships**: Dependencies should make technical sense
- **Avoid conflicts**: Design profiles to be composable

#### Documentation
- **Clear descriptions**: Explain what the profile tests
- **Specification references**: Link to relevant RFCs/standards
- **Usage examples**: Show common profile combinations

## Testing and Validation

### Registry Testing
```go
func TestProfileRegistry(t *testing.T) {
    registry := NewProfileRegistry()
    
    // Test registration
    err := registry.Register(&ProfileInfo{
        ID: "test-profile",
        Name: "Test Profile",
        Type: Optional,
        Factory: func(client *httpClient.Client) verifier.Verifier {
            return &MockVerifier{}
        },
    })
    assert.NoError(t, err)
    
    // Test retrieval
    profile, exists := registry.Get("test-profile")
    assert.True(t, exists)
    assert.Equal(t, "Test Profile", profile.Name)
}
```

### Dependency Resolution Testing
```go
func TestDependencyResolution(t *testing.T) {
    // Register profiles with dependencies
    registry.Register(profileWithDependencies)
    
    // Test successful resolution
    profiles, err := registry.ResolveProfiles([]string{"parent-profile"})
    assert.NoError(t, err)
    assert.Len(t, profiles, 2) // parent + dependency
    
    // Test missing dependency error
    _, err = registry.ResolveProfiles([]string{"parent-without-dep"})
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "requires dependency")
}
```

## Future Enhancements

### Planned Features
- **Profile versioning**: Support multiple versions of the same profile
- **Dynamic loading**: Load profiles from external modules
- **Profile composition**: Create composite profiles with custom test sets
- **Conditional dependencies**: Dependencies based on configuration
- **Profile inheritance**: Allow profiles to extend others
- **Performance optimization**: Parallel test execution within profiles
- **Profile metadata**: Additional metadata like compliance standards, versions

### Extension Points
The architecture is designed to support:
- **Custom profile types**: Beyond Mandatory/Optional/Regional
- **Advanced dependency logic**: Conditional or alternative dependencies
- **Profile parameters**: Configurable behavior within profiles
- **Test filtering**: Dynamic test selection based on context
- **Result aggregation**: Custom result processing and analysis