package profiles

import (
	"context"
	"strings"
	"testing"

	httpClient "fapictl/pkg/http"
	"fapictl/pkg/verifier"
)

// Mock verifier for testing
type mockVerifier struct {
	name        string
	description string
}

func (m *mockVerifier) Name() string        { return m.name }
func (m *mockVerifier) Description() string { return m.description }
func (m *mockVerifier) Verify(ctx context.Context, config verifier.VerifierConfig) (*verifier.TestSuite, error) {
	return &verifier.TestSuite{
		Name:        m.name,
		Description: m.description,
		Tests:       []verifier.TestResult{},
		Summary:     verifier.TestSummary{},
	}, nil
}

func TestRegistry_Register(t *testing.T) {
	registry := NewProfileRegistry()

	profile := &ProfileInfo{
		ID:           "test-profile",
		Name:         "Test Profile",
		Description:  "A test profile",
		Type:         Mandatory,
		Dependencies: []string{},
		Conflicts:    []string{},
		Factory: func(client *httpClient.Client) verifier.Verifier {
			return &mockVerifier{name: "Test Profile", description: "A test profile"}
		},
	}

	err := registry.Register(profile)
	if err != nil {
		t.Errorf("Register() error = %v", err)
	}

	// Test duplicate registration - current implementation allows it
	err = registry.Register(profile)
	if err != nil {
		t.Errorf("Register() duplicate registration error = %v", err)
	}
}

func TestRegistry_Get(t *testing.T) {
	registry := NewProfileRegistry()

	profile := &ProfileInfo{
		ID:           "test-profile",
		Name:         "Test Profile",
		Description:  "A test profile",
		Type:         Mandatory,
		Dependencies: []string{},
		Conflicts:    []string{},
		Factory: func(client *httpClient.Client) verifier.Verifier {
			return &mockVerifier{name: "Test Profile", description: "A test profile"}
		},
	}

	registry.Register(profile)

	// Test successful get
	retrieved, exists := registry.Get("test-profile")
	if !exists {
		t.Error("Get() profile should exist")
	}

	if retrieved.ID != "test-profile" {
		t.Errorf("Get() ID = %s, want test-profile", retrieved.ID)
	}

	// Test non-existent profile
	_, exists = registry.Get("nonexistent")
	if exists {
		t.Error("Get() nonexistent profile should not exist")
	}
}

func TestRegistry_List(t *testing.T) {
	registry := NewProfileRegistry()

	profiles := []*ProfileInfo{
		{
			ID:   "mandatory-1",
			Name: "Mandatory Profile 1",
			Type: Mandatory,
			Factory: func(client *httpClient.Client) verifier.Verifier {
				return &mockVerifier{name: "Mandatory Profile 1"}
			},
		},
		{
			ID:   "optional-1",
			Name: "Optional Profile 1",
			Type: Optional,
			Factory: func(client *httpClient.Client) verifier.Verifier {
				return &mockVerifier{name: "Optional Profile 1"}
			},
		},
		{
			ID:   "regional-1",
			Name: "Regional Profile 1",
			Type: Regional,
			Factory: func(client *httpClient.Client) verifier.Verifier {
				return &mockVerifier{name: "Regional Profile 1"}
			},
		},
	}

	for _, profile := range profiles {
		registry.Register(profile)
	}

	// Test list all
	all := registry.List()
	if len(all) != 3 {
		t.Errorf("List() length = %d, want 3", len(all))
	}

	// Test list by type
	mandatory := registry.ListByType(Mandatory)
	if len(mandatory) != 1 {
		t.Errorf("ListByType(Mandatory) length = %d, want 1", len(mandatory))
	}

	if mandatory[0].ID != "mandatory-1" {
		t.Errorf("ListByType(Mandatory)[0].ID = %s, want mandatory-1", mandatory[0].ID)
	}

	optional := registry.ListByType(Optional)
	if len(optional) != 1 {
		t.Errorf("ListByType(Optional) length = %d, want 1", len(optional))
	}

	regional := registry.ListByType(Regional)
	if len(regional) != 1 {
		t.Errorf("ListByType(Regional) length = %d, want 1", len(regional))
	}
}

func TestRegistry_ResolveProfiles(t *testing.T) {
	registry := NewProfileRegistry()

	// Create profiles with dependencies
	profiles := []*ProfileInfo{
		{
			ID:           "base",
			Name:         "Base Profile",
			Type:         Mandatory,
			Dependencies: []string{},
			Factory: func(client *httpClient.Client) verifier.Verifier {
				return &mockVerifier{name: "Base Profile"}
			},
		},
		{
			ID:           "dependent",
			Name:         "Dependent Profile",
			Type:         Optional,
			Dependencies: []string{"base"},
			Factory: func(client *httpClient.Client) verifier.Verifier {
				return &mockVerifier{name: "Dependent Profile"}
			},
		},
		{
			ID:           "multi-dependent",
			Name:         "Multi Dependent Profile",
			Type:         Regional,
			Dependencies: []string{"base", "dependent"},
			Factory: func(client *httpClient.Client) verifier.Verifier {
				return &mockVerifier{name: "Multi Dependent Profile"}
			},
		},
	}

	for _, profile := range profiles {
		registry.Register(profile)
	}

	// Test simple dependency resolution
	resolved, err := registry.ResolveProfiles([]string{"dependent"})
	if err != nil {
		t.Errorf("ResolveProfiles() error = %v", err)
	}

	// Should resolve dependency automatically
	found := make(map[string]bool)
	for _, profile := range resolved {
		found[profile.ID] = true
	}

	if !found["dependent"] {
		t.Error("Expected dependent profile to be resolved")
	}

	// Test multi-level dependency resolution
	resolved, err = registry.ResolveProfiles([]string{"multi-dependent"})
	if err != nil {
		t.Errorf("ResolveProfiles() error = %v", err)
	}

	found = make(map[string]bool)
	for _, profile := range resolved {
		found[profile.ID] = true
	}

	if !found["multi-dependent"] {
		t.Error("Expected multi-dependent profile to be resolved")
	}
}

func TestRegistry_ResolveProfiles_MissingDependency(t *testing.T) {
	registry := NewProfileRegistry()

	profile := &ProfileInfo{
		ID:           "dependent",
		Name:         "Dependent Profile",
		Type:         Optional,
		Dependencies: []string{"nonexistent"},
		Factory: func(client *httpClient.Client) verifier.Verifier {
			return &mockVerifier{name: "Dependent Profile"}
		},
	}

	registry.Register(profile)

	_, err := registry.ResolveProfiles([]string{"dependent"})
	if err == nil {
		t.Error("Expected error for missing dependency, got nil")
	}

	if !strings.Contains(err.Error(), "unknown profile") {
		t.Errorf("Expected unknown profile error, got: %v", err)
	}
}

func TestRegistry_ResolveProfiles_CircularDependency(t *testing.T) {
	registry := NewProfileRegistry()

	profiles := []*ProfileInfo{
		{
			ID:           "circular-a",
			Name:         "Circular A",
			Type:         Optional,
			Dependencies: []string{"circular-b"},
			Factory: func(client *httpClient.Client) verifier.Verifier {
				return &mockVerifier{name: "Circular A"}
			},
		},
		{
			ID:           "circular-b",
			Name:         "Circular B",
			Type:         Optional,
			Dependencies: []string{"circular-a"},
			Factory: func(client *httpClient.Client) verifier.Verifier {
				return &mockVerifier{name: "Circular B"}
			},
		},
	}

	for _, profile := range profiles {
		registry.Register(profile)
	}

	_, err := registry.ResolveProfiles([]string{"circular-a"})
	if err == nil {
		t.Error("Expected error for circular dependency, got nil")
	}

	if !strings.Contains(err.Error(), "circular dependency") {
		t.Errorf("Expected circular dependency error, got: %v", err)
	}
}

func TestRegistry_ValidateConflicts(t *testing.T) {
	registry := NewProfileRegistry()

	profiles := []*ProfileInfo{
		{
			ID:        "profile-a",
			Name:      "Profile A",
			Type:      Optional,
			Conflicts: []string{"profile-b"},
			Factory: func(client *httpClient.Client) verifier.Verifier {
				return &mockVerifier{name: "Profile A"}
			},
		},
		{
			ID:        "profile-b",
			Name:      "Profile B",
			Type:      Optional,
			Conflicts: []string{"profile-a"},
			Factory: func(client *httpClient.Client) verifier.Verifier {
				return &mockVerifier{name: "Profile B"}
			},
		},
		{
			ID:   "profile-c",
			Name: "Profile C",
			Type: Optional,
			Factory: func(client *httpClient.Client) verifier.Verifier {
				return &mockVerifier{name: "Profile C"}
			},
		},
	}

	for _, profile := range profiles {
		registry.Register(profile)
	}

	// Test no conflicts
	_, err := registry.ResolveProfiles([]string{"profile-a", "profile-c"})
	if err != nil {
		t.Errorf("ResolveProfiles() unexpected error = %v", err)
	}

	// Test conflicting profiles
	_, err = registry.ResolveProfiles([]string{"profile-a", "profile-b"})
	if err == nil {
		t.Error("Expected conflict error, got nil")
	}

	if !strings.Contains(err.Error(), "conflict") {
		t.Errorf("Expected conflict error, got: %v", err)
	}
}

func TestRegistry_CreateVerifiers(t *testing.T) {
	registry := NewProfileRegistry()

	profile := &ProfileInfo{
		ID:   "test-profile",
		Name: "Test Profile",
		Type: Optional,
		Factory: func(client *httpClient.Client) verifier.Verifier {
			return &mockVerifier{name: "Test Profile", description: "A test profile"}
		},
	}

	registry.Register(profile)

	client := &httpClient.Client{}
	verifiers, err := registry.CreateVerifiers([]string{"test-profile"}, client)
	if err != nil {
		t.Fatalf("CreateVerifiers() error = %v", err)
	}

	if len(verifiers) != 1 {
		t.Errorf("CreateVerifiers() length = %d, want 1", len(verifiers))
	}

	v := verifiers[0]
	if v.Name() != "Test Profile" {
		t.Errorf("Verifier Name() = %s, want Test Profile", v.Name())
	}

	if v.Description() != "A test profile" {
		t.Errorf("Verifier Description() = %s, want A test profile", v.Description())
	}
}

func TestProfileType_String(t *testing.T) {
	tests := []struct {
		profileType ProfileType
		want        string
	}{
		{Mandatory, "mandatory"},
		{Optional, "optional"},
		{Regional, "regional"},
	}

	for _, tt := range tests {
		if got := string(tt.profileType); got != tt.want {
			t.Errorf("ProfileType string = %s, want %s", got, tt.want)
		}
	}
}

func TestDefaultRegistry_Integration(t *testing.T) {
	// Test that default registry has expected profiles
	profiles := DefaultRegistry.List()

	if len(profiles) == 0 {
		t.Error("DefaultRegistry should have registered profiles")
	}

	// Check for expected mandatory profiles
	mandatoryProfiles := DefaultRegistry.ListByType(Mandatory)
	expectedMandatory := []string{"oauth2-pkce", "fapi-ro", "fapi-rw"}

	mandatoryIDs := make(map[string]bool)
	for _, profile := range mandatoryProfiles {
		mandatoryIDs[profile.ID] = true
	}

	for _, expected := range expectedMandatory {
		if !mandatoryIDs[expected] {
			t.Errorf("Expected mandatory profile %s not found", expected)
		}
	}

	// Test profile resolution for FAPI-RW
	resolved, err := DefaultRegistry.ResolveProfiles([]string{"fapi-rw"})
	if err != nil {
		t.Errorf("DefaultRegistry profile resolution error = %v", err)
	}

	// Should successfully resolve
	if len(resolved) == 0 {
		t.Error("FAPI-RW should resolve successfully")
	}
}
