package cmd

import (
	"fmt"
	"strings"

	"fapictl/pkg/colors"
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
			fmt.Printf(colors.Error("Unknown profile type: ")+"%s\n", profileType)
			fmt.Println(colors.Info("Valid types: ") + "mandatory, optional, regional")
			return
		}
	} else {
		profilesToShow = registry.List()
	}

	if len(profilesToShow) == 0 {
		fmt.Println(colors.Warning("No profiles found"))
		return
	}

	currentType := ""
	for _, profile := range profilesToShow {
		// Print type header if it changed
		if string(profile.Type) != currentType {
			currentType = string(profile.Type)
			fmt.Printf("\n"+colors.Header("%s Profiles:")+"\n", strings.Title(currentType))
			fmt.Println(colors.Header(strings.Repeat("=", len(currentType)+10)))
		}

		// Print profile information
		fmt.Printf("  "+colors.Key("%s")+" - "+colors.Value("%s")+"\n", profile.ID, profile.Name)

		if showDetails {
			fmt.Printf("    "+colors.Gray("Description: ")+"%s\n", profile.Description)

			if len(profile.Dependencies) > 0 {
				fmt.Printf("    "+colors.Gray("Dependencies: ")+colors.Cyan("%s")+"\n", strings.Join(profile.Dependencies, ", "))
			}

			if len(profile.Conflicts) > 0 {
				fmt.Printf("    "+colors.Gray("Conflicts: ")+colors.Warning("%s")+"\n", strings.Join(profile.Conflicts, ", "))
			}

			fmt.Println()
		}
	}

	if !showDetails {
		fmt.Printf("\n" + colors.Info("Use --details flag to show more information about each profile") + "\n")
		fmt.Printf(colors.Header("Example usage:") + "\n")
		fmt.Printf("  " + colors.Code("fapictl test --config config.yaml --profiles fapi-ro,mtls,jar") + "\n")
		fmt.Printf("  " + colors.Code("fapictl test --config config.yaml --profiles fapi-rw,ob-uk") + "\n")
	}
}
