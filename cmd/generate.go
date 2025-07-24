package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fapictl/pkg/crypto"
	"github.com/spf13/cobra"
)

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate cryptographic materials for FAPI testing",
	Long: `Generate cryptographic materials needed for FAPI compliance testing including:
- Private keys (RSA, ECDSA)
- Self-signed certificates
- PKCE challenges
- JWT key pairs with JWK format`,
}

// PKCE command
var generatePKCECmd = &cobra.Command{
	Use:   "pkce",
	Short: "Generate PKCE challenge and verifier",
	Long: `Generate a PKCE (Proof Key for Code Exchange) challenge and verifier pair.
The verifier is a cryptographically random string and the challenge is derived 
using SHA256 hash of the verifier (S256 method).`,
	Run: runGeneratePKCE,
}

// Private key command
var generateKeyCmd = &cobra.Command{
	Use:   "key",
	Short: "Generate private keys for JWT signing",
	Long: `Generate private keys for JWT signing and client authentication.
Supports RSA and ECDSA key types in PEM format.`,
	Run: runGenerateKey,
}

// Certificate command
var generateCertCmd = &cobra.Command{
	Use:   "cert",
	Short: "Generate self-signed certificates for testing",
	Long: `Generate self-signed X.509 certificates for mTLS testing.
Creates both certificate and private key files in PEM format.
Note: Self-signed certificates are for testing only - production 
deployments should use certificates from trusted CAs.`,
	Run: runGenerateCert,
}

// JWK command
var generateJWKCmd = &cobra.Command{
	Use:   "jwk",
	Short: "Generate JWK (JSON Web Key) format keys",
	Long: `Generate keys in JWK (JSON Web Key) format for JOSE operations.
Creates both private and public JWKs with proper key identifiers.`,
	Run: runGenerateJWK,
}

// Command flags
var (
	// Common flags
	genOutputDir string
	genKeyID     string
	genOverwrite bool

	// Key generation flags
	genKeyType string
	genKeySize int
	genCurve   string

	// Certificate flags
	genCertSubject string
	genCertDays    int
	genCertDNS     []string
	genCertIPs     []string

	// PKCE flags
	genShowDetails bool
)

func init() {
	// Add subcommands
	generateCmd.AddCommand(generatePKCECmd)
	generateCmd.AddCommand(generateKeyCmd)
	generateCmd.AddCommand(generateCertCmd)
	generateCmd.AddCommand(generateJWKCmd)

	// Common flags
	generateCmd.PersistentFlags().StringVarP(&genOutputDir, "output", "o", ".", "Output directory for generated files")
	generateCmd.PersistentFlags().BoolVar(&genOverwrite, "overwrite", false, "Overwrite existing files")

	// PKCE flags
	generatePKCECmd.Flags().BoolVarP(&genShowDetails, "details", "d", false, "Show detailed PKCE information")
	generatePKCECmd.Flags().StringVar(&genKeyID, "save", "", "Save PKCE pair to files with given prefix")

	// Key generation flags
	generateKeyCmd.Flags().StringVarP(&genKeyType, "type", "t", "rsa", "Key type: rsa, ecdsa")
	generateKeyCmd.Flags().IntVarP(&genKeySize, "size", "s", 2048, "RSA key size in bits (2048, 3072, 4096)")
	generateKeyCmd.Flags().StringVarP(&genCurve, "curve", "c", "P-256", "ECDSA curve: P-256, P-384, P-521")
	generateKeyCmd.Flags().StringVar(&genKeyID, "kid", "", "Key identifier (generated if not specified)")

	// Certificate flags
	generateCertCmd.Flags().StringVar(&genCertSubject, "subject", "CN=fapictl-test", "Certificate subject (e.g., CN=example.com,O=Test)")
	generateCertCmd.Flags().IntVar(&genCertDays, "days", 365, "Certificate validity in days")
	generateCertCmd.Flags().StringSliceVar(&genCertDNS, "dns", nil, "DNS names for SAN extension")
	generateCertCmd.Flags().StringSliceVar(&genCertIPs, "ip", nil, "IP addresses for SAN extension")
	generateCertCmd.Flags().StringVarP(&genKeyType, "key-type", "t", "rsa", "Private key type: rsa, ecdsa")
	generateCertCmd.Flags().IntVarP(&genKeySize, "key-size", "s", 2048, "RSA key size in bits")
	generateCertCmd.Flags().StringVarP(&genCurve, "curve", "c", "P-256", "ECDSA curve")

	// JWK flags
	generateJWKCmd.Flags().StringVarP(&genKeyType, "type", "t", "rsa", "Key type: rsa, ecdsa")
	generateJWKCmd.Flags().IntVarP(&genKeySize, "size", "s", 2048, "RSA key size in bits")
	generateJWKCmd.Flags().StringVarP(&genCurve, "curve", "c", "P-256", "ECDSA curve")
	generateJWKCmd.Flags().StringVar(&genKeyID, "kid", "", "Key identifier (generated if not specified)")
}

func runGeneratePKCE(cmd *cobra.Command, args []string) {
	// Generate PKCE challenge
	challenge, err := crypto.GeneratePKCEChallenge()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating PKCE challenge: %v\n", err)
		os.Exit(1)
	}

	if genShowDetails {
		fmt.Println("PKCE Challenge Generated Successfully")
		fmt.Println("===================================")
		fmt.Printf("Method: %s\n", challenge.Method)
		fmt.Printf("Code Verifier Length: %d characters\n", len(challenge.Verifier))
		fmt.Printf("Code Challenge Length: %d characters\n", len(challenge.Challenge))
		fmt.Println()
	}

	fmt.Printf("Code Verifier: %s\n", challenge.Verifier)
	fmt.Printf("Code Challenge: %s\n", challenge.Challenge)
	fmt.Printf("Challenge Method: %s\n", challenge.Method)

	// Save to files if requested
	if genKeyID != "" {
		verifierFile := fmt.Sprintf("%s/%s_verifier.txt", genOutputDir, genKeyID)
		challengeFile := fmt.Sprintf("%s/%s_challenge.txt", genOutputDir, genKeyID)

		if err := saveToFile(verifierFile, challenge.Verifier, genOverwrite); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving verifier: %v\n", err)
			os.Exit(1)
		}

		if err := saveToFile(challengeFile, challenge.Challenge, genOverwrite); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving challenge: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("\nSaved to files:\n")
		fmt.Printf("  Verifier: %s\n", verifierFile)
		fmt.Printf("  Challenge: %s\n", challengeFile)
	}
}

func runGenerateKey(cmd *cobra.Command, args []string) {
	// Generate key ID if not provided
	if genKeyID == "" {
		genKeyID = fmt.Sprintf("fapictl-key-%d", time.Now().Unix())
	}

	var privateKey interface{}
	var err error

	switch genKeyType {
	case "rsa":
		privateKey, err = rsa.GenerateKey(rand.Reader, genKeySize)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating RSA key: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Generated RSA private key (%d bits)\n", genKeySize)

	case "ecdsa":
		var c elliptic.Curve
		switch genCurve {
		case "P-256":
			c = elliptic.P256()
		case "P-384":
			c = elliptic.P384()
		case "P-521":
			c = elliptic.P521()
		default:
			fmt.Fprintf(os.Stderr, "Unsupported curve: %s\n", genCurve)
			os.Exit(1)
		}

		privateKey, err = ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating ECDSA key: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Generated ECDSA private key (%s curve)\n", genCurve)

	default:
		fmt.Fprintf(os.Stderr, "Unsupported key type: %s\n", genKeyType)
		os.Exit(1)
	}

	// Encode private key to PEM
	var privateKeyPEM []byte
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		privateKeyDER := x509.MarshalPKCS1PrivateKey(key)
		privateKeyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyDER,
		})
	case *ecdsa.PrivateKey:
		privateKeyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling ECDSA key: %v\n", err)
			os.Exit(1)
		}
		privateKeyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: privateKeyDER,
		})
	}

	// Generate public key PEM
	publicKey := getPublicKey(privateKey)
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling public key: %v\n", err)
		os.Exit(1)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	})

	// Save to files
	privateKeyFile := fmt.Sprintf("%s/%s-private.pem", genOutputDir, genKeyID)
	publicKeyFile := fmt.Sprintf("%s/%s-public.pem", genOutputDir, genKeyID)

	if err := saveToFile(privateKeyFile, string(privateKeyPEM), genOverwrite); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving private key: %v\n", err)
		os.Exit(1)
	}

	if err := saveToFile(publicKeyFile, string(publicKeyPEM), genOverwrite); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving public key: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Key ID: %s\n", genKeyID)
	fmt.Printf("Private key saved to: %s\n", privateKeyFile)
	fmt.Printf("Public key saved to: %s\n", publicKeyFile)
	fmt.Printf("\nConfiguration usage:\n")
	fmt.Printf("private_key_jwt:\n")
	fmt.Printf("  kid: \"%s\"\n", genKeyID)
	fmt.Printf("  key: \"%s\"\n", privateKeyFile)
}

func runGenerateCert(cmd *cobra.Command, args []string) {
	// Parse certificate subject
	subject, err := parseSubject(genCertSubject)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing subject: %v\n", err)
		os.Exit(1)
	}

	// Generate private key
	var privateKey interface{}
	switch genKeyType {
	case "rsa":
		privateKey, err = rsa.GenerateKey(rand.Reader, genKeySize)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating RSA key: %v\n", err)
			os.Exit(1)
		}
	case "ecdsa":
		var c elliptic.Curve
		switch genCurve {
		case "P-256":
			c = elliptic.P256()
		case "P-384":
			c = elliptic.P384()
		case "P-521":
			c = elliptic.P521()
		default:
			fmt.Fprintf(os.Stderr, "Unsupported curve: %s\n", genCurve)
			os.Exit(1)
		}
		privateKey, err = ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating ECDSA key: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unsupported key type: %s\n", genKeyType)
		os.Exit(1)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, genCertDays),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Add SAN extensions
	if len(genCertDNS) > 0 {
		template.DNSNames = genCertDNS
	}

	// Parse IP addresses
	for _, ipStr := range genCertIPs {
		if ip := parseIP(ipStr); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}

	// Create certificate
	publicKey := getPublicKey(privateKey)
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating certificate: %v\n", err)
		os.Exit(1)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	var privateKeyPEM []byte
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		privateKeyDER := x509.MarshalPKCS1PrivateKey(key)
		privateKeyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyDER,
		})
	case *ecdsa.PrivateKey:
		privateKeyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling ECDSA key: %v\n", err)
			os.Exit(1)
		}
		privateKeyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: privateKeyDER,
		})
	}

	// Generate filenames
	baseName := "fapictl-cert"
	if genKeyID != "" {
		baseName = genKeyID
	}

	certFile := fmt.Sprintf("%s/%s.crt", genOutputDir, baseName)
	keyFile := fmt.Sprintf("%s/%s.key", genOutputDir, baseName)

	// Save files
	if err := saveToFile(certFile, string(certPEM), genOverwrite); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving certificate: %v\n", err)
		os.Exit(1)
	}

	if err := saveToFile(keyFile, string(privateKeyPEM), genOverwrite); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving private key: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated self-signed certificate\n")
	fmt.Printf("Subject: %s\n", subject)
	fmt.Printf("Valid for: %d days\n", genCertDays)
	fmt.Printf("Certificate saved to: %s\n", certFile)
	fmt.Printf("Private key saved to: %s\n", keyFile)
	fmt.Printf("\nConfiguration usage:\n")
	fmt.Printf("mtls:\n")
	fmt.Printf("  cert: \"%s\"\n", certFile)
	fmt.Printf("  key: \"%s\"\n", keyFile)
	fmt.Printf("\nWARNING: Self-signed certificates are for testing only!\n")
	fmt.Printf("Production deployments should use certificates from trusted CAs.\n")
}

func runGenerateJWK(cmd *cobra.Command, args []string) {
	// Generate key ID if not provided
	if genKeyID == "" {
		genKeyID = fmt.Sprintf("fapictl-jwk-%d", time.Now().Unix())
	}

	// Generate private key first
	var privateKey interface{}
	var err error

	switch genKeyType {
	case "rsa":
		privateKey, err = rsa.GenerateKey(rand.Reader, genKeySize)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating RSA key: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Generated RSA JWK (%d bits)\n", genKeySize)

	case "ecdsa":
		var c elliptic.Curve
		switch genCurve {
		case "P-256":
			c = elliptic.P256()
		case "P-384":
			c = elliptic.P384()
		case "P-521":
			c = elliptic.P521()
		default:
			fmt.Fprintf(os.Stderr, "Unsupported curve: %s\n", genCurve)
			os.Exit(1)
		}

		privateKey, err = ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating ECDSA key: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Generated ECDSA JWK (%s curve)\n", genCurve)

	default:
		fmt.Fprintf(os.Stderr, "Unsupported key type: %s\n", genKeyType)
		os.Exit(1)
	}

	// Generate JWK representation
	jwk, err := generateJWK(privateKey, genKeyID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating JWK: %v\n", err)
		os.Exit(1)
	}

	// Generate public JWK
	publicJWK, err := generatePublicJWK(privateKey, genKeyID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating public JWK: %v\n", err)
		os.Exit(1)
	}

	// Save to files
	privateJWKFile := fmt.Sprintf("%s/%s-private.jwk", genOutputDir, genKeyID)
	publicJWKFile := fmt.Sprintf("%s/%s-public.jwk", genOutputDir, genKeyID)

	if err := saveToFile(privateJWKFile, jwk, genOverwrite); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving private JWK: %v\n", err)
		os.Exit(1)
	}

	if err := saveToFile(publicJWKFile, publicJWK, genOverwrite); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving public JWK: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Key ID: %s\n", genKeyID)
	fmt.Printf("Private JWK saved to: %s\n", privateJWKFile)
	fmt.Printf("Public JWK saved to: %s\n", publicJWKFile)
	fmt.Printf("\nConfiguration usage:\n")
	fmt.Printf("private_key_jwt:\n")
	fmt.Printf("  kid: \"%s\"\n", genKeyID)
	fmt.Printf("  key: \"%s\"\n", privateJWKFile)
}

// Helper functions

func saveToFile(filename, content string, overwrite bool) error {
	// Check if file exists
	if _, err := os.Stat(filename); err == nil && !overwrite {
		return fmt.Errorf("file %s already exists (use --overwrite to overwrite)", filename)
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	// Write file with secure permissions
	return os.WriteFile(filename, []byte(content), 0600)
}

func getPublicKey(privateKey interface{}) interface{} {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return &key.PublicKey
	case *ecdsa.PrivateKey:
		return &key.PublicKey
	default:
		return nil
	}
}

func parseSubject(subject string) (pkix.Name, error) {
	// Simple subject parsing - supports CN, O, C format
	// Example: "CN=example.com,O=Test Org,C=US"
	name := pkix.Name{}

	pairs := strings.Split(subject, ",")
	for _, pair := range pairs {
		kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(kv) != 2 {
			continue
		}

		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])

		switch strings.ToUpper(key) {
		case "CN":
			name.CommonName = value
		case "O":
			name.Organization = []string{value}
		case "OU":
			name.OrganizationalUnit = []string{value}
		case "C":
			name.Country = []string{value}
		case "L":
			name.Locality = []string{value}
		case "ST", "S":
			name.Province = []string{value}
		}
	}

	return name, nil
}

func parseIP(ipStr string) net.IP {
	return net.ParseIP(ipStr)
}

// generateJWK creates a JWK (JSON Web Key) from a private key
func generateJWK(privateKey interface{}, keyID string) (string, error) {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return generateRSAJWK(key, keyID, true)
	case *ecdsa.PrivateKey:
		return generateECDSAJWK(key, keyID, true)
	default:
		return "", fmt.Errorf("unsupported private key type")
	}
}

// generatePublicJWK creates a public JWK from a private key
func generatePublicJWK(privateKey interface{}, keyID string) (string, error) {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return generateRSAJWK(key, keyID, false)
	case *ecdsa.PrivateKey:
		return generateECDSAJWK(key, keyID, false)
	default:
		return "", fmt.Errorf("unsupported private key type")
	}
}

// generateRSAJWK generates RSA JWK in JSON format
func generateRSAJWK(key *rsa.PrivateKey, keyID string, includePrivate bool) (string, error) {

	// Encode public key components
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())

	jwk := map[string]interface{}{
		"kty": "RSA",
		"kid": keyID,
		"use": "sig",
		"alg": "RS256",
		"n":   n,
		"e":   e,
	}

	if includePrivate {
		// Add private key components
		d := base64.RawURLEncoding.EncodeToString(key.D.Bytes())
		p := base64.RawURLEncoding.EncodeToString(key.Primes[0].Bytes())
		q := base64.RawURLEncoding.EncodeToString(key.Primes[1].Bytes())

		// Calculate CRT parameters
		dp := new(big.Int).Mod(key.D, new(big.Int).Sub(key.Primes[0], big.NewInt(1)))
		dq := new(big.Int).Mod(key.D, new(big.Int).Sub(key.Primes[1], big.NewInt(1)))
		qi := new(big.Int).ModInverse(key.Primes[1], key.Primes[0])

		jwk["d"] = d
		jwk["p"] = p
		jwk["q"] = q
		jwk["dp"] = base64.RawURLEncoding.EncodeToString(dp.Bytes())
		jwk["dq"] = base64.RawURLEncoding.EncodeToString(dq.Bytes())
		jwk["qi"] = base64.RawURLEncoding.EncodeToString(qi.Bytes())
	}

	jsonBytes, err := json.MarshalIndent(jwk, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWK: %v", err)
	}

	return string(jsonBytes), nil
}

// generateECDSAJWK generates ECDSA JWK in JSON format
func generateECDSAJWK(key *ecdsa.PrivateKey, keyID string, includePrivate bool) (string, error) {

	// Determine curve name
	var crv string
	switch key.Curve.Params().Name {
	case "P-256":
		crv = "P-256"
	case "P-384":
		crv = "P-384"
	case "P-521":
		crv = "P-521"
	default:
		return "", fmt.Errorf("unsupported curve: %s", key.Curve.Params().Name)
	}

	// Encode public key coordinates
	keySize := (key.Curve.Params().BitSize + 7) / 8
	xBytes := make([]byte, keySize)
	yBytes := make([]byte, keySize)

	key.X.FillBytes(xBytes)
	key.Y.FillBytes(yBytes)

	x := base64.RawURLEncoding.EncodeToString(xBytes)
	y := base64.RawURLEncoding.EncodeToString(yBytes)

	jwk := map[string]interface{}{
		"kty": "EC",
		"kid": keyID,
		"use": "sig",
		"alg": "ES256",
		"crv": crv,
		"x":   x,
		"y":   y,
	}

	if includePrivate {
		// Add private key
		dBytes := make([]byte, keySize)
		key.D.FillBytes(dBytes)
		d := base64.RawURLEncoding.EncodeToString(dBytes)

		jwk["d"] = d
	}

	jsonBytes, err := json.MarshalIndent(jwk, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JWK: %v", err)
	}

	return string(jsonBytes), nil
}
