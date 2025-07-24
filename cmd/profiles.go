package cmd

import (
	"fmt"
	"strings"

	"fapictl/pkg/profiles"
	"github.com/spf13/cobra"
)

var profilesCmd = &cobra.Command{
	Use:   "profiles",
	Short: "List available FAPI compliance profiles",
	Long: `List all available FAPI compliance profiles organized by type.
	
Profiles are grouped into:
- Mandatory: Core FAPI profiles (fapi-ro, fapi-rw)
- Optional: Extension profiles (ciba, dpop, mtls, jar, jarm, par)  
- Regional: Country/region-specific profiles (ob-uk, open-finance-br, etc.)`,
	Run: runProfiles,
}

var (
	profileType string
	showDetails bool
)

func init() {
	profilesCmd.Flags().StringVarP(&profileType, "type", "t", "", "Filter by profile type: mandatory, optional, regional")
	profilesCmd.Flags().BoolVarP(&showDetails, "details", "d", false, "Show detailed profile information")
}

func runProfiles(cmd *cobra.Command, args []string) {
	registry := profiles.DefaultRegistry

	var profilesToShow []*profiles.ProfileInfo

	if profileType != "" {
		switch strings.ToLower(profileType) {
		case "mandatory":
			profilesToShow = registry.ListByType(profiles.Mandatory)
		case "optional":
			profilesToShow = registry.ListByType(profiles.Optional)
		case "regional":
			profilesToShow = registry.ListByType(profiles.Regional)
		default:
			fmt.Printf("Unknown profile type: %s\n", profileType)
			fmt.Println("Valid types: mandatory, optional, regional")
			return
		}
	} else {
		profilesToShow = registry.List()
	}

	if len(profilesToShow) == 0 {
		fmt.Println("No profiles found")
		return
	}

	currentType := ""
	for _, profile := range profilesToShow {
		// Print type header if it changed
		if string(profile.Type) != currentType {
			currentType = string(profile.Type)
			fmt.Printf("\n%s Profiles:\n", strings.Title(currentType))
			fmt.Println(strings.Repeat("=", len(currentType)+10))
		}

		// Print profile information
		fmt.Printf("  %s - %s\n", profile.ID, profile.Name)

		if showDetails {
			fmt.Printf("    Description: %s\n", profile.Description)

			if len(profile.Dependencies) > 0 {
				fmt.Printf("    Dependencies: %s\n", strings.Join(profile.Dependencies, ", "))
			}

			if len(profile.Conflicts) > 0 {
				fmt.Printf("    Conflicts: %s\n", strings.Join(profile.Conflicts, ", "))
			}

			fmt.Println()
		}
	}

	if !showDetails {
		fmt.Printf("\nUse --details flag to show more information about each profile\n")
		fmt.Printf("Example usage:\n")
		fmt.Printf("  fapictl test --config config.yaml --profiles fapi-ro,mtls,jar\n")
		fmt.Printf("  fapictl test --config config.yaml --profiles fapi-rw,ob-uk\n")
	}
}
