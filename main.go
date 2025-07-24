package main

import (
	"fmt"
	"os"

	"fapictl/cmd"
	"github.com/spf13/cobra"
)

var (
	version    = "dev"
	buildTime  = "unknown"
	commitHash = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "fapictl",
	Short: "Financial-grade API (FAPI) compliance testing tool",
	Long: `fapictl is a command-line tool for testing and validating the compliance 
of OAuth 2.0 and OpenID Connect servers with the Financial-grade API (FAPI) 
security profiles.`,
	Version: fmt.Sprintf("%s (built: %s, commit: %s)", version, buildTime, commitHash),
}

func init() {
	cmd.AddCommands(rootCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
