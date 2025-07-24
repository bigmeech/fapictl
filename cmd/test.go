package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"fapictl/pkg/config"
	httpClient "fapictl/pkg/http"
	"fapictl/pkg/logger"
	"fapictl/pkg/profiles"
	"fapictl/pkg/verifier"
	"github.com/spf13/cobra"
)

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Run FAPI compliance tests",
	Long: `Run a full or partial FAPI compliance test suite against an OAuth 2.0/OIDC server.
	
Supports testing various FAPI profiles including:
- fapi-ro: Read-only profile
- fapi-rw: Read/write profile  
- Regional profiles: ob-uk, berlin-group, cdr-au, etc.`,
	Run: runTest,
}

var (
	configFile   string
	profile      string
	profilesList string
	reportFormat string
	verbose      bool
	veryVerbose  bool
	debug        bool
)

func init() {
	testCmd.Flags().StringVarP(&configFile, "config", "c", "", "Path to configuration file (required)")
	testCmd.Flags().StringVarP(&profile, "profile", "p", "", "Single FAPI profile to test (overrides config)")
	testCmd.Flags().StringVar(&profilesList, "profiles", "", "Comma-separated list of profiles to test (e.g., fapi-ro,mtls,jar)")
	testCmd.Flags().StringVar(&reportFormat, "report", "text", "Report format: text, json, yaml, html")
	testCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show detailed test execution information")
	testCmd.Flags().BoolVar(&veryVerbose, "very-verbose", false, "Show HTTP requests/responses and detailed debugging")
	testCmd.Flags().BoolVar(&debug, "debug", false, "Enable debug logging (same as --very-verbose)")
	testCmd.MarkFlagRequired("config")
}

func runTest(cmd *cobra.Command, args []string) {
	// Initialize logger based on verbosity flags
	var logLevel logger.LogLevel
	if debug || veryVerbose {
		logLevel = logger.LogLevelDebug
	} else if verbose {
		logLevel = logger.LogLevelVerbose
	} else {
		logLevel = logger.LogLevelInfo
	}
	log := logger.NewLogger(logLevel)

	// Load configuration
	log.Info("Loading configuration from: %s", configFile)
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		log.Error("Failed to load config: %v", err)
		os.Exit(1)
	}

	// Determine which profiles to test
	var profilesToTest []string

	if profilesList != "" {
		// Use explicitly specified profiles list
		profilesToTest = strings.Split(profilesList, ",")
		for i, p := range profilesToTest {
			profilesToTest[i] = strings.TrimSpace(p)
		}
	} else if profile != "" {
		// Use single profile override
		profilesToTest = []string{profile}
	} else if len(cfg.Profiles) > 0 {
		// Use profiles array from config
		profilesToTest = cfg.Profiles
	} else if cfg.Profile != "" {
		// Use legacy single profile from config
		profilesToTest = []string{cfg.Profile}
	} else {
		// Default to basic OAuth2 + PKCE
		profilesToTest = []string{"oauth2-pkce"}
	}

	// Validate configuration
	log.Verbose("Validating configuration")
	if err := cfg.Validate(); err != nil {
		log.Error("Invalid config: %v", err)
		os.Exit(1)
	}

	log.Info("Running FAPI compliance test")
	log.Info("Config: %s", configFile)
	log.Info("Profiles: %s", strings.Join(profilesToTest, ", "))
	log.Info("Client ID: %s", cfg.ClientID)
	log.Info("Report format: %s", reportFormat)
	log.Verbose("Authorization Endpoint: %s", cfg.AuthorizationEndpoint)
	log.Verbose("Token Endpoint: %s", cfg.TokenEndpoint)
	if cfg.PAREndpoint != "" {
		log.Verbose("PAR Endpoint: %s", cfg.PAREndpoint)
	}
	if cfg.IntrospectionEndpoint != "" {
		log.Verbose("Introspection Endpoint: %s", cfg.IntrospectionEndpoint)
	}
	if cfg.JWKSURI != "" {
		log.Verbose("JWKS URI: %s", cfg.JWKSURI)
	}

	// Create HTTP client with logging
	log.Verbose("Creating HTTP client with timeout: %v", 30*time.Second)
	if cfg.MTLS.Cert != "" && cfg.MTLS.Key != "" {
		log.Verbose("Using mTLS authentication")
	}

	clientOpts := httpClient.ClientOptions{
		Timeout:   30 * time.Second,
		MTLSCert:  cfg.MTLS.Cert,
		MTLSKey:   cfg.MTLS.Key,
		UserAgent: "fapictl/1.0",
		Logger:    log, // Pass logger for HTTP request/response logging
	}

	client, err := httpClient.NewClient(clientOpts)
	if err != nil {
		log.Error("Failed to create HTTP client: %v", err)
		os.Exit(1)
	}

	// Convert config to verifier config
	verifierConfig := verifier.VerifierConfig{
		ClientID:              cfg.ClientID,
		RedirectURI:           cfg.RedirectURI,
		AuthorizationEndpoint: cfg.AuthorizationEndpoint,
		TokenEndpoint:         cfg.TokenEndpoint,
		PAREndpoint:           cfg.PAREndpoint,
		IntrospectionEndpoint: cfg.IntrospectionEndpoint,
		JWKSURI:               cfg.JWKSURI,
		OIDCConfig:            cfg.OIDCConfig,
		Scopes:                cfg.Scopes,
		MTLSCert:              cfg.MTLS.Cert,
		MTLSKey:               cfg.MTLS.Key,
		PrivateKeyJWTKey:      cfg.PrivateKeyJWT.Key,
		PrivateKeyJWTKID:      cfg.PrivateKeyJWT.Kid,
	}

	// Create verifiers from profile registry
	log.Verbose("Creating verifiers for profiles: %s", strings.Join(profilesToTest, ", "))
	registry := profiles.DefaultRegistry
	verifierList, err := registry.CreateVerifiers(profilesToTest, client)
	if err != nil {
		log.Error("Failed to create verifiers: %v", err)
		os.Exit(1)
	}
	log.Verbose("Created %d verifiers", len(verifierList))

	// Create test runner and add verifiers
	runner := verifier.NewTestRunner(verifierConfig)
	for _, v := range verifierList {
		runner.AddVerifier(v)
	}

	// Handle test type filters
	if len(args) > 0 {
		switch args[0] {
		case "token":
			log.Info("Running token endpoint tests only")
			// TODO: Filter verifiers to only token-related tests
		case "auth":
			log.Info("Running authorization endpoint tests only")
			// TODO: Filter verifiers to only auth-related tests
		default:
			log.Error("Unknown test type: %s", args[0])
			os.Exit(1)
		}
	} else {
		log.Info("Running full test suite")
	}

	// Run tests
	log.Info("Starting test execution (timeout: 5 minutes)")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	start := time.Now()
	suites, err := runner.RunAll(ctx)
	duration := time.Since(start)

	if err != nil {
		log.Error("Test execution failed: %v", err)
		os.Exit(1)
	}

	log.Info("Test execution completed in %v", duration)

	// Generate and display report
	log.Verbose("Generating test report")
	reporter := verifier.NewReporter()

	// Always show text output to console
	if err := reporter.GenerateReport(suites, "text", os.Stdout); err != nil {
		log.Error("Failed to generate text report: %v", err)
	}

	// Generate additional report format if requested
	if reportFormat != "text" {
		log.Verbose("Generating %s report", reportFormat)
		reportFileName := generateReportFileName(reportFormat)
		reportFile, err := os.Create(reportFileName)
		if err != nil {
			log.Error("Failed to create report file: %v", err)
		} else {
			defer reportFile.Close()
			if err := reporter.GenerateReport(suites, reportFormat, reportFile); err != nil {
				log.Error("Failed to generate %s report: %v", reportFormat, err)
			} else {
				log.Success("Detailed %s report saved to: %s", reportFormat, reportFileName)
			}
		}
	}

	// Exit with error code if any tests failed
	for _, suite := range suites {
		if suite.Summary.Failed > 0 {
			os.Exit(1)
		}
	}
}

func generateReportFileName(format string) string {
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	return fmt.Sprintf("fapi_audit_%s.%s", timestamp, format)
}
