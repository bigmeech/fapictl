package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fapictl/pkg/config"
	"fapictl/pkg/crypto"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	yaml "gopkg.in/yaml.v3"
)

var wizardCmd = &cobra.Command{
	Use:   "wizard",
	Short: "Interactive wizard to configure and run FAPI tests",
	Long: `Interactive wizard that guides you through:
- Configuring your FAPI test setup
- Generating required cryptographic materials  
- Writing configuration file
- Running tests

Features a modern terminal interface with forms and real-time validation.`,
	Run: runWizard,
}

var (
	wizardOutputDir  string
	wizardConfigFile string
	wizardSkipTests  bool
	wizardVerbose    bool
	wizardDryRun     bool
)

func init() {
	wizardCmd.Flags().StringVar(&wizardOutputDir, "output-dir", ".", "Directory to save generated files")
	wizardCmd.Flags().StringVar(&wizardConfigFile, "config-file", "fapictl-config.yaml", "Name of config file to create")
	wizardCmd.Flags().BoolVar(&wizardSkipTests, "skip-tests", false, "Skip running tests after configuration")
	wizardCmd.Flags().BoolVarP(&wizardVerbose, "verbose", "v", false, "Verbose output during wizard")
	wizardCmd.Flags().BoolVar(&wizardDryRun, "dry-run", false, "Show what would be done without creating files or running tests")
}

type wizardStep int

const (
	stepWelcome wizardStep = iota
	stepBasics
	stepEndpoints
	stepProfiles
	stepAuth
	stepGenerate
	stepComplete
)

type wizardModel struct {
	step       wizardStep
	config     *config.Config
	form       *huh.Form
	outputDir  string
	configFile string
	verbose    bool
	dryRun     bool
	skipTests  bool
	err        error
	progress   int
	totalSteps int
	generated  []string
	runTests   bool

	// Form data
	clientID           string
	redirectURI        string
	scopes             string
	authEndpoint       string
	tokenEndpoint      string
	parEndpoint        string
	jwksURI            string
	introspectEndpoint string
	selectedProfiles   []string
	authMethod         string
	existingMTLS       bool
	mtlsCertPath       string
	mtlsKeyPath        string
	existingJWT        bool
	jwtKeyPath         string
	jwtKeyID           string
}

type stepCompleteMsg struct{}
type generateCompleteMsg struct {
	files []string
}

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#7C3AED")).
			MarginBottom(1)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#059669")).
			MarginBottom(1)

	progressStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6366F1"))

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#10B981"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#EF4444"))

	infoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6B7280"))
)

func runWizard(cmd *cobra.Command, args []string) {
	model := &wizardModel{
		step:       stepWelcome,
		config:     &config.Config{},
		outputDir:  wizardOutputDir,
		configFile: wizardConfigFile,
		verbose:    wizardVerbose,
		dryRun:     wizardDryRun,
		skipTests:  wizardSkipTests,
		totalSteps: 6,
	}

	// Ensure output directory exists (skip in dry run)
	if !model.dryRun {
		if err := os.MkdirAll(model.outputDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create output directory: %v\n", err)
			os.Exit(1)
		}
	}

	model.buildWelcomeForm()

	p := tea.NewProgram(model, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running wizard: %v\n", err)
		os.Exit(1)
	}
}

func (m *wizardModel) Init() tea.Cmd {
	return m.form.Init()
}

func (m *wizardModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		}
	case stepCompleteMsg:
		m.nextStep()
		return m, m.form.Init()
	case generateCompleteMsg:
		m.generated = msg.files
		m.nextStep()
		return m, m.form.Init()
	}

	var cmd tea.Cmd
	form, cmd := m.form.Update(msg)
	m.form = form.(*huh.Form)

	if m.form.State == huh.StateCompleted {
		return m, m.handleFormComplete()
	}

	return m, cmd
}

func (m *wizardModel) View() string {
	var s strings.Builder

	// Header
	s.WriteString(titleStyle.Render("🧙 FAPI Compliance Test Wizard"))
	s.WriteString("\n")

	if m.dryRun {
		s.WriteString(infoStyle.Render("🔍 DRY RUN MODE: No files will be created"))
		s.WriteString("\n")
	}

	// Progress
	progress := fmt.Sprintf("Step %d of %d", int(m.step)+1, m.totalSteps)
	s.WriteString(progressStyle.Render(progress))
	s.WriteString("\n\n")

	// Error handling
	if m.err != nil {
		s.WriteString(errorStyle.Render(fmt.Sprintf("❌ Error: %v", m.err)))
		s.WriteString("\n\n")
	}

	// Step content
	switch m.step {
	case stepWelcome:
		s.WriteString(headerStyle.Render("Welcome"))
		s.WriteString("\nThis wizard will help you configure and run FAPI compliance tests.\n\n")
	case stepBasics:
		s.WriteString(headerStyle.Render("Basic Configuration"))
		s.WriteString("\nLet's start with your OAuth 2.0 client configuration.\n\n")
	case stepEndpoints:
		s.WriteString(headerStyle.Render("OAuth 2.0 Endpoints"))
		s.WriteString("\nConfigure your OAuth 2.0/OpenID Connect server endpoints.\n\n")
	case stepProfiles:
		s.WriteString(headerStyle.Render("FAPI Profiles"))
		s.WriteString("\nSelect which FAPI compliance profiles to test.\n\n")
	case stepAuth:
		s.WriteString(headerStyle.Render("Authentication"))
		s.WriteString("\nConfigure client authentication methods.\n\n")
	case stepGenerate:
		s.WriteString(headerStyle.Render("Generate Materials"))
		s.WriteString("\nGenerating cryptographic materials and configuration...\n\n")
		if len(m.generated) > 0 {
			s.WriteString(successStyle.Render("✅ Generated files:"))
			s.WriteString("\n")
			for _, file := range m.generated {
				s.WriteString(fmt.Sprintf("  📁 %s\n", file))
			}
			s.WriteString("\n")
		}
	case stepComplete:
		s.WriteString(headerStyle.Render("Complete"))
		s.WriteString("\n")
		s.WriteString(successStyle.Render("🎉 Configuration wizard completed successfully!"))
		s.WriteString("\n\n")
	}

	// Form
	s.WriteString(m.form.View())

	// Footer
	s.WriteString("\n\n")
	s.WriteString(infoStyle.Render("Press Ctrl+C to quit"))

	return s.String()
}

func (m *wizardModel) nextStep() {
	m.step++
	m.buildFormForStep()
}

func (m *wizardModel) handleFormComplete() tea.Cmd {
	switch m.step {
	case stepWelcome:
		return func() tea.Msg { return stepCompleteMsg{} }
	case stepBasics:
		m.updateConfigFromBasics()
		return func() tea.Msg { return stepCompleteMsg{} }
	case stepEndpoints:
		m.updateConfigFromEndpoints()
		return func() tea.Msg { return stepCompleteMsg{} }
	case stepProfiles:
		m.updateConfigFromProfiles()
		return func() tea.Msg { return stepCompleteMsg{} }
	case stepAuth:
		m.updateConfigFromAuth()
		return func() tea.Msg { return stepCompleteMsg{} }
	case stepGenerate:
		return m.generateMaterials()
	case stepComplete:
		if !m.skipTests && !m.dryRun && m.runTests {
			return m.executeTests()
		}
		return tea.Quit
	}
	return nil
}

func (m *wizardModel) buildFormForStep() {
	switch m.step {
	case stepBasics:
		m.buildBasicsForm()
	case stepEndpoints:
		m.buildEndpointsForm()
	case stepProfiles:
		m.buildProfilesForm()
	case stepAuth:
		m.buildAuthForm()
	case stepGenerate:
		m.buildGenerateForm()
	case stepComplete:
		m.buildCompleteForm()
	}
}

func (m *wizardModel) buildWelcomeForm() {
	m.form = huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title("Ready to configure your FAPI compliance tests?").
				Affirmative("Yes, let's start!").
				Negative("No, exit").
				Value(new(bool)),
		),
	)
}

func (m *wizardModel) buildBasicsForm() {
	m.form = huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("OAuth 2.0 Client ID").
				Description("Your registered client identifier").
				Placeholder("my-client-id").
				Value(&m.clientID).
				Validate(func(s string) error {
					if s == "" {
						return fmt.Errorf("client ID is required")
					}
					return nil
				}),

			huh.NewInput().
				Title("Redirect URI").
				Description("OAuth 2.0 redirect URI").
				Placeholder("http://localhost:8080/callback").
				Value(&m.redirectURI),

			huh.NewInput().
				Title("OAuth 2.0 Scopes").
				Description("Space-separated list of scopes").
				Placeholder("openid accounts payments").
				Value(&m.scopes),
		),
	)
}

func (m *wizardModel) buildEndpointsForm() {
	m.form = huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Authorization Endpoint").
				Description("OAuth 2.0 authorization endpoint URL").
				Placeholder("https://auth.example.com/authorize").
				Value(&m.authEndpoint).
				Validate(func(s string) error {
					if s == "" {
						return fmt.Errorf("authorization endpoint is required")
					}
					return nil
				}),

			huh.NewInput().
				Title("Token Endpoint").
				Description("OAuth 2.0 token endpoint URL").
				Placeholder("https://auth.example.com/token").
				Value(&m.tokenEndpoint).
				Validate(func(s string) error {
					if s == "" {
						return fmt.Errorf("token endpoint is required")
					}
					return nil
				}),
		),

		huh.NewGroup(
			huh.NewInput().
				Title("PAR Endpoint (Optional)").
				Description("Pushed Authorization Request endpoint").
				Placeholder("https://auth.example.com/par").
				Value(&m.parEndpoint),

			huh.NewInput().
				Title("JWKS URI (Optional)").
				Description("JSON Web Key Set URI").
				Placeholder("https://auth.example.com/.well-known/jwks.json").
				Value(&m.jwksURI),

			huh.NewInput().
				Title("Introspection Endpoint (Optional)").
				Description("Token introspection endpoint").
				Placeholder("https://auth.example.com/introspect").
				Value(&m.introspectEndpoint),
		),
	)
}

func (m *wizardModel) buildProfilesForm() {
	profiles := []huh.Option[string]{
		huh.NewOption("FAPI Read-Write (Recommended)", "fapi-rw").Selected(true),
		huh.NewOption("Mutual TLS (Recommended)", "mtls").Selected(true),
		huh.NewOption("PKCE (Recommended)", "pkce").Selected(true),
		huh.NewOption("Pushed Authorization Requests", "par"),
		huh.NewOption("JWT Secured Authorization Requests", "jar"),
		huh.NewOption("JWT Secured Authorization Response Mode", "jarm"),
		huh.NewOption("Open Banking UK", "ob-uk"),
		huh.NewOption("Open Finance Brazil", "open-finance-br"),
	}

	m.form = huh.NewForm(
		huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title("Select FAPI Profiles").
				Description("Choose which profiles to test (recommended profiles are pre-selected)").
				Options(profiles...).
				Value(&m.selectedProfiles).
				Validate(func(profiles []string) error {
					if len(profiles) == 0 {
						return fmt.Errorf("at least one profile must be selected")
					}
					return nil
				}),
		),
	)
}

func (m *wizardModel) buildAuthForm() {
	authOptions := []huh.Option[string]{
		huh.NewOption("Mutual TLS only", "mtls"),
		huh.NewOption("Private Key JWT only", "jwt"),
		huh.NewOption("Both (Recommended)", "both").Selected(true),
	}

	var groups []*huh.Group

	// Main auth method selection
	groups = append(groups, huh.NewGroup(
		huh.NewSelect[string]().
			Title("Authentication Method").
			Description("How should the client authenticate?").
			Options(authOptions...).
			Value(&m.authMethod),
	))

	// mTLS configuration group
	mtlsGroup := huh.NewGroup(
		huh.NewConfirm().
			Title("Do you have existing mTLS certificates?").
			Value(&m.existingMTLS),
	)
	groups = append(groups, mtlsGroup)

	// mTLS file paths (if existing certs)
	if m.existingMTLS {
		mtlsPathGroup := huh.NewGroup(
			huh.NewInput().
				Title("mTLS Certificate Path").
				Value(&m.mtlsCertPath),
			huh.NewInput().
				Title("mTLS Private Key Path").
				Value(&m.mtlsKeyPath),
		)
		groups = append(groups, mtlsPathGroup)
	}

	// JWT configuration group
	jwtGroup := huh.NewGroup(
		huh.NewConfirm().
			Title("Do you have an existing JWT signing key?").
			Value(&m.existingJWT),
	)
	groups = append(groups, jwtGroup)

	// JWT file paths (if existing key)
	if m.existingJWT {
		jwtPathGroup := huh.NewGroup(
			huh.NewInput().
				Title("JWT Signing Key Path").
				Value(&m.jwtKeyPath),
			huh.NewInput().
				Title("JWT Key ID (kid)").
				Value(&m.jwtKeyID),
		)
		groups = append(groups, jwtPathGroup)
	}

	m.form = huh.NewForm(groups...)
}

func (m *wizardModel) buildGenerateForm() {
	m.form = huh.NewForm(
		huh.NewGroup(
			huh.NewNote().
				Title("Generating Files").
				Description("Please wait while we generate your cryptographic materials and configuration..."),
		),
	)
}

func (m *wizardModel) buildCompleteForm() {
	var description strings.Builder

	if m.dryRun {
		description.WriteString("In dry run mode - no files were actually created.\n")
	} else {
		description.WriteString(fmt.Sprintf("Configuration saved to: %s\n",
			filepath.Join(m.outputDir, m.configFile)))
		if len(m.generated) > 0 {
			description.WriteString("\nGenerated files:\n")
			for _, file := range m.generated {
				description.WriteString(fmt.Sprintf("• %s\n", file))
			}
		}
	}

	options := []*huh.Group{
		huh.NewGroup(
			huh.NewNote().
				Title("Setup Complete!").
				Description(description.String()),
		),
	}

	if !m.skipTests && !m.dryRun {
		options = append(options,
			huh.NewGroup(
				huh.NewConfirm().
					Title("Run tests now?").
					Description("Execute the FAPI compliance tests with your new configuration").
					Value(&m.runTests),
			),
		)
	}

	m.form = huh.NewForm(options...)
}

func (m *wizardModel) updateConfigFromBasics() {
	m.config.ClientID = m.clientID
	m.config.RedirectURI = m.redirectURI
	if m.redirectURI == "" {
		m.config.RedirectURI = "http://localhost:8080/callback"
	}

	if m.scopes != "" {
		m.config.Scopes = strings.Fields(m.scopes)
	} else {
		m.config.Scopes = []string{"openid", "accounts", "payments"}
	}
}

func (m *wizardModel) updateConfigFromEndpoints() {
	m.config.AuthorizationEndpoint = m.authEndpoint
	m.config.TokenEndpoint = m.tokenEndpoint
	m.config.PAREndpoint = m.parEndpoint
	m.config.JWKSURI = m.jwksURI
	m.config.IntrospectionEndpoint = m.introspectEndpoint
}

func (m *wizardModel) updateConfigFromProfiles() {
	m.config.Profiles = m.selectedProfiles
}

func (m *wizardModel) updateConfigFromAuth() {
	// Configure mTLS
	if m.authMethod == "mtls" || m.authMethod == "both" {
		if m.existingMTLS {
			m.config.MTLS.Cert = m.mtlsCertPath
			m.config.MTLS.Key = m.mtlsKeyPath
		} else {
			m.config.MTLS.Cert = filepath.Join(m.outputDir, "client-cert.pem")
			m.config.MTLS.Key = filepath.Join(m.outputDir, "client-key.pem")
		}
	}

	// Configure JWT
	if m.authMethod == "jwt" || m.authMethod == "both" {
		if m.existingJWT {
			m.config.PrivateKeyJWT.Key = m.jwtKeyPath
			m.config.PrivateKeyJWT.Kid = m.jwtKeyID
		} else {
			m.config.PrivateKeyJWT.Key = filepath.Join(m.outputDir, "jwt-signing-key.pem")
			m.config.PrivateKeyJWT.Kid = fmt.Sprintf("fapictl-key-%d", time.Now().Unix())
		}
	}
}

func (m *wizardModel) generateMaterials() tea.Cmd {
	return func() tea.Msg {
		var generated []string

		if m.dryRun {
			// Simulate file generation for dry run
			if m.config.MTLS.Cert != "" && !m.existingMTLS {
				generated = append(generated, m.config.MTLS.Cert+" (dry run)")
				generated = append(generated, m.config.MTLS.Key+" (dry run)")
			}
			if m.config.PrivateKeyJWT.Key != "" && !m.existingJWT {
				generated = append(generated, m.config.PrivateKeyJWT.Key+" (dry run)")
			}
			generated = append(generated, filepath.Join(m.outputDir, m.configFile)+" (dry run)")
		} else {
			// Generate mTLS materials
			if m.config.MTLS.Cert != "" && !m.existingMTLS {
				if err := m.generateMTLSMaterials(); err != nil {
					m.err = err
					return generateCompleteMsg{generated}
				}
				generated = append(generated, m.config.MTLS.Cert, m.config.MTLS.Key)
			}

			// Generate JWT key
			if m.config.PrivateKeyJWT.Key != "" && !m.existingJWT {
				if err := m.generateJWTKey(); err != nil {
					m.err = err
					return generateCompleteMsg{generated}
				}
				generated = append(generated, m.config.PrivateKeyJWT.Key)
			}

			// Write configuration
			if err := m.writeConfig(); err != nil {
				m.err = err
				return generateCompleteMsg{generated}
			}
			generated = append(generated, filepath.Join(m.outputDir, m.configFile))
		}

		return generateCompleteMsg{generated}
	}
}

func (m *wizardModel) generateMTLSMaterials() error {
	// Generate RSA private key
	privateKey, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %v", err)
	}

	// Generate self-signed certificate
	cert, err := crypto.GenerateSelfSignedCert(privateKey, "fapictl-client", []string{"localhost"}, 365*24*time.Hour)
	if err != nil {
		return fmt.Errorf("failed to generate certificate: %v", err)
	}

	// Save certificate
	certPEM, err := crypto.EncodeCertificatePEM(cert)
	if err != nil {
		return fmt.Errorf("failed to encode certificate: %v", err)
	}

	if err := wizardSaveToFile(m.config.MTLS.Cert, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to save certificate: %v", err)
	}

	// Save private key
	keyPEM, err := crypto.EncodePrivateKeyPEM(privateKey)
	if err != nil {
		return fmt.Errorf("failed to encode private key: %v", err)
	}

	if err := wizardSaveToFile(m.config.MTLS.Key, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to save private key: %v", err)
	}

	return nil
}

func (m *wizardModel) generateJWTKey() error {
	// Generate RSA private key for JWT signing
	privateKey, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %v", err)
	}

	// Save private key
	keyPEM, err := crypto.EncodePrivateKeyPEM(privateKey)
	if err != nil {
		return fmt.Errorf("failed to encode private key: %v", err)
	}

	if err := wizardSaveToFile(m.config.PrivateKeyJWT.Key, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to save private key: %v", err)
	}

	return nil
}

func (m *wizardModel) writeConfig() error {
	configPath := filepath.Join(m.outputDir, m.configFile)

	// Convert config to YAML
	yamlData, err := yaml.Marshal(m.config)
	if err != nil {
		return fmt.Errorf("failed to marshal configuration: %v", err)
	}

	// Add header comment
	header := fmt.Sprintf("# FAPI Compliance Test Configuration\n# Generated by fapictl wizard on %s\n\n", time.Now().Format(time.RFC3339))
	configContent := header + string(yamlData)

	if err := wizardSaveToFile(configPath, configContent, 0644); err != nil {
		return fmt.Errorf("failed to save configuration: %v", err)
	}

	return nil
}

func (m *wizardModel) executeTests() tea.Cmd {
	return func() tea.Msg {
		// Build the configuration path
		configPath := filepath.Join(m.outputDir, m.configFile)

		fmt.Printf("\n🚀 Running FAPI compliance tests with configuration: %s\n\n", configPath)

		// Save current command line args
		originalArgs := os.Args

		// Build test command arguments
		testArgs := []string{"fapictl", "test", "--config", configPath}
		if m.verbose {
			testArgs = append(testArgs, "--verbose")
		}

		// Set new args for test command
		os.Args = testArgs

		// Restore original args when done
		defer func() {
			os.Args = originalArgs
		}()

		// Execute the test command directly
		runTest(nil, []string{})

		return tea.Quit
	}
}

// Helper function to save content to file with proper permissions
func wizardSaveToFile(filename, content string, perm os.FileMode) error {
	// Ensure directory exists
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return os.WriteFile(filename, []byte(content), perm)
}
