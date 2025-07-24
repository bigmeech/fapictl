package cmd

import "github.com/spf13/cobra"

func AddCommands(rootCmd *cobra.Command) {
	rootCmd.AddCommand(testCmd)
	rootCmd.AddCommand(signRequestCmd)
	rootCmd.AddCommand(profilesCmd)
	rootCmd.AddCommand(generateCmd)
	rootCmd.AddCommand(wizardCmd)
}
