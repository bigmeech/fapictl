package profiles

import (
	"fmt"
	"sort"
	"strings"

	httpClient "fapictl/pkg/http"
	"fapictl/pkg/verifier"
)

type ProfileType string

const (
	Mandatory ProfileType = "mandatory"
	Optional  ProfileType = "optional"
	Regional  ProfileType = "regional"
)

type ProfileInfo struct {
	ID           string                                     `json:"id"`
	Name         string                                     `json:"name"`
	Description  string                                     `json:"description"`
	Type         ProfileType                                `json:"type"`
	Dependencies []string                                   `json:"dependencies,omitempty"`
	Conflicts    []string                                   `json:"conflicts,omitempty"`
	Factory      func(*httpClient.Client) verifier.Verifier `json:"-"`
}

type ProfileRegistry struct {
	profiles map[string]*ProfileInfo
}

func NewProfileRegistry() *ProfileRegistry {
	return &ProfileRegistry{
		profiles: make(map[string]*ProfileInfo),
	}
}

func (r *ProfileRegistry) Register(profile *ProfileInfo) error {
	if profile.ID == "" {
		return fmt.Errorf("profile ID cannot be empty")
	}

	if profile.Factory == nil {
		return fmt.Errorf("profile factory function cannot be nil")
	}

	r.profiles[profile.ID] = profile
	return nil
}

func (r *ProfileRegistry) Get(id string) (*ProfileInfo, bool) {
	profile, exists := r.profiles[id]
	return profile, exists
}

func (r *ProfileRegistry) List() []*ProfileInfo {
	var profiles []*ProfileInfo
	for _, profile := range r.profiles {
		profiles = append(profiles, profile)
	}

	// Sort by type then by ID
	sort.Slice(profiles, func(i, j int) bool {
		if profiles[i].Type != profiles[j].Type {
			return profiles[i].Type < profiles[j].Type
		}
		return profiles[i].ID < profiles[j].ID
	})

	return profiles
}

func (r *ProfileRegistry) ListByType(profileType ProfileType) []*ProfileInfo {
	var profiles []*ProfileInfo
	for _, profile := range r.profiles {
		if profile.Type == profileType {
			profiles = append(profiles, profile)
		}
	}

	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].ID < profiles[j].ID
	})

	return profiles
}

func (r *ProfileRegistry) ResolveProfiles(profileIDs []string) ([]*ProfileInfo, error) {
	resolvedMap := make(map[string]*ProfileInfo)
	resolvingMap := make(map[string]bool) // Track profiles currently being resolved
	var errors []string

	// Recursively resolve dependencies
	var resolveDependencies func(id string) error
	resolveDependencies = func(id string) error {
		// Skip if already resolved
		if _, exists := resolvedMap[id]; exists {
			return nil
		}

		// Check for circular dependency
		if resolvingMap[id] {
			return fmt.Errorf("circular dependency detected involving profile: %s", id)
		}

		// Get profile
		profile, exists := r.Get(id)
		if !exists {
			return fmt.Errorf("unknown profile: %s", id)
		}

		// Mark as being resolved
		resolvingMap[id] = true

		// Resolve dependencies first
		for _, dep := range profile.Dependencies {
			if err := resolveDependencies(dep); err != nil {
				return err
			}
		}

		// Mark as resolved
		resolvedMap[id] = profile
		delete(resolvingMap, id)

		return nil
	}

	// Resolve all requested profiles and their dependencies
	for _, id := range profileIDs {
		if err := resolveDependencies(id); err != nil {
			errors = append(errors, err.Error())
		}
	}

	if len(errors) > 0 {
		return nil, fmt.Errorf("profile resolution failed: %s", strings.Join(errors, ", "))
	}

	// Convert map to slice
	var resolved []*ProfileInfo
	for _, profile := range resolvedMap {
		resolved = append(resolved, profile)
	}

	// Check conflicts
	for i, profile1 := range resolved {
		for j, profile2 := range resolved {
			if i != j {
				for _, conflict := range profile1.Conflicts {
					if conflict == profile2.ID {
						errors = append(errors, fmt.Sprintf("profile %s conflicts with %s", profile1.ID, profile2.ID))
					}
				}
			}
		}
	}

	if len(errors) > 0 {
		return nil, fmt.Errorf("profile validation failed: %s", strings.Join(errors, ", "))
	}

	return resolved, nil
}

func (r *ProfileRegistry) CreateVerifiers(profileIDs []string, client *httpClient.Client) ([]verifier.Verifier, error) {
	profiles, err := r.ResolveProfiles(profileIDs)
	if err != nil {
		return nil, err
	}

	var verifiers []verifier.Verifier
	for _, profile := range profiles {
		verifier := profile.Factory(client)
		verifiers = append(verifiers, verifier)
	}

	return verifiers, nil
}

// Default registry instance
var DefaultRegistry = NewProfileRegistry()
