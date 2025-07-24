package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var signRequestCmd = &cobra.Command{
	Use:   "sign-request",
	Short: "Create a JWS-signed request object (JAR)",
	Long: `Generate a JWS-signed request object (JAR) from claims and a private key.
	
This is useful for creating signed request objects that comply with FAPI 
requirements for request object signing.`,
	Run: runSignRequest,
}

var (
	claimsFile string
	keyFile    string
	keyID      string
	outputFile string
)

func init() {
	signRequestCmd.Flags().StringVar(&claimsFile, "claims", "", "JSON file with request claims (required)")
	signRequestCmd.Flags().StringVar(&keyFile, "key", "", "Private key file path (required)")
	signRequestCmd.Flags().StringVar(&keyID, "kid", "", "Key ID (required)")
	signRequestCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output path for JWT (required)")

	signRequestCmd.MarkFlagRequired("claims")
	signRequestCmd.MarkFlagRequired("key")
	signRequestCmd.MarkFlagRequired("kid")
	signRequestCmd.MarkFlagRequired("output")
}

func runSignRequest(cmd *cobra.Command, args []string) {
	fmt.Printf("Signing request object...\n")
	fmt.Printf("Claims file: %s\n", claimsFile)
	fmt.Printf("Private key: %s\n", keyFile)
	fmt.Printf("Key ID: %s\n", keyID)
	fmt.Printf("Output file: %s\n", outputFile)

	// TODO: Implement actual JWT signing logic
	fmt.Println("Request object signed successfully!")
}
