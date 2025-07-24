# profiles/regional/ Directory

This directory contains region-specific and country-specific FAPI compliance profiles that implement regulatory requirements and local standards for open banking and financial API ecosystems around the world.

## Purpose

Regional profiles extend the core FAPI specifications with jurisdiction-specific requirements, regulatory compliance tests, and local market implementations. These profiles ensure compliance with national open banking standards and regional regulatory frameworks.

## Design Principles

- **Regulatory Alignment**: Implement specific regulatory requirements for each jurisdiction
- **Cultural Adaptation**: Account for local business practices and technical standards
- **FAPI Foundation**: Build upon mandatory FAPI profiles with regional extensions
- **Interoperability**: Maintain compatibility with global FAPI standards while adding local requirements

## Profile Categories

### Europe
- **Berlin Group NextGenPSD2**: EU PSD2 compliance framework
- **Individual EU country implementations**: Country-specific adaptations

### Americas  
- **Brazil Open Finance**: Sistema Financeiro Aberto compliance
- **Canada**: Canadian open banking framework (future)
- **Mexico**: Mexican financial API standards (future)

### Asia-Pacific
- **Australia CDR**: Consumer Data Right compliance
- **Hong Kong**: Hong Kong Monetary Authority standards (future)
- **Singapore**: MAS open banking requirements (future)

### Africa & Middle East
- **Nigeria Open Banking**: Nigerian open banking standards
- **South Africa**: South African Reserve Bank requirements (future)

## Implemented Profiles

### 1. UK Open Banking (`ob_uk.go`)

**Profile ID**: `ob-uk`  
**Dependencies**: `fapi-rw`, `mtls`, `jar`  
**Standards**: OBIE Read/Write API Specification, PSD2 RTS

#### Purpose
Tests compliance with UK Open Banking Implementation Entity (OBIE) specifications, which implement PSD2 requirements for the UK market with additional OBIE-specific requirements.

#### Key Regulatory Requirements
- **PSD2 Compliance**: Strong Customer Authentication (SCA), consent management
- **OBIE Directory**: Client certificates must be issued by OBIE Directory
- **Account Information Services (AIS)**: Account access permissions and data clusters
- **Payment Initiation Services (PIS)**: Payment consent and execution flows
- **Confirmation of Funds (CoF)**: Funds confirmation services

#### Key Tests
- **UK Open Banking Scopes**: Validates OBIE-specific scope usage (`accounts`, `payments`, `fundsconfirmations`)
- **Intent-based Authorization**: Tests account-request and payment-consent flows
- **Strong Customer Authentication (SCA)**: Validates PSD2 SCA compliance
- **Account Request Permissions**: Tests OBIE data cluster permissions structure
- **Payment Initiation Security**: Validates payment security requirements
- **Directory Certificate Validation**: Checks certificates are from OBIE Directory
- **Customer Authentication Methods**: Tests bank customer authentication flows
- **Data Cluster Permissions**: Validates OBIE permission model compliance

#### Configuration Requirements
```yaml
profiles:
  - oauth2-pkce
  - fapi-ro
  - fapi-rw
  - mtls
  - jar
  - ob-uk

# OBIE-specific scopes
scopes:
  - openid
  - accounts        # Account information access
  - payments        # Payment initiation
  - fundsconfirmations  # Confirmation of funds

# OBIE Directory certificate required
mtls:
  cert: "./certs/obie-client.crt"  # Must be OBIE Directory issued
  key: "./certs/obie-client.key"

# Request object signing required
private_key_jwt:
  kid: "obie-key-1"
  key: "./keys/obie-signing.pem"
```

#### Sample Output
```
=== UK Open Banking ===
UK Open Banking Scopes                   PASS
Intent-based Authorization               SKIP
  Error: Intent registration testing requires API integration
Strong Customer Authentication (SCA)     SKIP
  Error: SCA testing requires customer authentication flow
Account Request Permissions              SKIP
  Error: Account permissions testing requires API integration
Payment Initiation Security              PASS
Directory Certificate Validation         FAIL
  Error: UK Open Banking requires OBIE Directory certificates
Customer Authentication Methods          SKIP
  Error: Customer authentication testing requires bank integration

Suite Summary: 8 total, 2 passed, 1 failed, 5 skipped
```

### 2. Brazil Open Finance (`open_finance_br.go`)

**Profile ID**: `open-finance-br`  
**Dependencies**: `fapi-rw`, `mtls`, `jar`  
**Standards**: Sistema Financeiro Aberto (SFA), BCB Resolutions

#### Purpose
Tests compliance with Brazilian Open Finance regulations administered by the Central Bank of Brazil (BCB), implementing the Sistema Financeiro Aberto framework.

#### Key Regulatory Requirements
- **BCB Compliance**: Central Bank of Brazil regulatory requirements
- **CPF/CNPJ Integration**: Brazilian individual/corporate identity verification
- **PIX Integration**: Brazilian instant payment system integration
- **LGPD Compliance**: Lei Geral de Proteção de Dados (Brazilian GDPR)
- **Directory Authority**: Certificates from authorized Brazilian directory

#### Key Tests
- **Brazil Open Finance Scopes**: Validates Brazilian-specific scopes (`accounts`, `credit-cards-accounts`, `loans`, `payments`, etc.)
- **CPF/CNPJ Authorization**: Tests Brazilian identity document integration
- **Brazilian Consent Management**: Validates BCB consent framework requirements
- **Brazil Directory Certificate**: Checks certificates from authorized Brazilian directory
- **PIX Integration Requirements**: Tests PIX instant payment integration
- **LGPD Compliance**: Validates data protection law compliance
- **Dynamic Client Registration**: Tests DCR compliance with Brazilian requirements
- **Operational Risk Requirements**: Validates operational risk management per BCB rules

#### Configuration Requirements
```yaml
profiles:
  - oauth2-pkce
  - fapi-ro
  - fapi-rw
  - mtls
  - jar
  - open-finance-br

# Brazilian Open Finance scopes
scopes:
  - openid
  - accounts
  - credit-cards-accounts
  - loans
  - financings
  - payments
  - consents

# Brazilian directory certificate required
mtls:
  cert: "./certs/brazil-directory.crt"
  key: "./certs/brazil-directory.key"

# Request object signing required
private_key_jwt:
  kid: "brazil-key-1"
  key: "./keys/brazil-signing.pem"
```

#### Sample Output
```
=== Brazil Open Finance ===
Brazil Open Finance Scopes               PASS
CPF/CNPJ Authorization                   SKIP
  Error: CPF/CNPJ validation requires customer identification flow
Brazilian Consent Management             SKIP
  Error: Consent management testing requires API integration
Brazil Directory Certificate             FAIL
  Error: Brazil Open Finance requires certificates from authorized directory
PIX Integration Requirements             SKIP
  Error: PIX integration testing requires payment API integration
LGPD Compliance                          SKIP
  Error: LGPD compliance testing requires data handling analysis
Dynamic Client Registration              SKIP
  Error: Dynamic client registration testing requires DCR endpoint
Operational Risk Requirements            PASS

Suite Summary: 8 total, 2 passed, 1 failed, 5 skipped
```

## Placeholder Profiles (Future Implementation)

### 3. Berlin Group NextGenPSD2 (`berlin_group.go`)

**Profile ID**: `berlin-group`  
**Dependencies**: `fapi-ro`  
**Standards**: Berlin Group NextGenPSD2 XS2A Framework  
**Status**: Placeholder implementation

#### Purpose
Will test compliance with Berlin Group's NextGenPSD2 XS2A (Access to Account) framework, which provides a common implementation approach for PSD2 across Europe.

#### Planned Features
- PSD2 RTS compliance testing
- XS2A API specification validation
- ASPSP (Account Servicing Payment Service Provider) requirements
- TPP (Third Party Provider) certification validation
- European payments and account information standards

### 4. Australian Consumer Data Right (`cdr_au.go`)

**Profile ID**: `cdr-au`  
**Dependencies**: `fapi-rw`, `mtls`, `jar`  
**Standards**: Australian CDR Standards  
**Status**: Placeholder implementation

#### Purpose
Will test compliance with Australian Consumer Data Right (CDR) framework administered by the Australian Competition and Consumer Commission (ACCC).

#### Planned Features
- CDR Register integration and certificate validation
- Banking sector data standards
- Energy sector data standards (future)
- Telecommunications sector data standards (future)
- Australian Privacy Act compliance

### 5. Nigerian Open Banking (`open_banking_ng.go`)

**Profile ID**: `open-banking-ng`  
**Dependencies**: `fapi-ro`  
**Standards**: CBN Open Banking Framework  
**Status**: Placeholder implementation

#### Purpose  
Will test compliance with Central Bank of Nigeria (CBN) open banking framework and regulatory requirements.

#### Planned Features
- CBN regulatory compliance
- Nigerian financial sector requirements
- Local payment system integration
- Nigerian data protection law compliance

## Regional Profile Usage

### Common Deployment Patterns

#### UK Market Deployment
```bash
# Full UK Open Banking compliance testing
fapictl test --profiles oauth2-pkce,fapi-ro,fapi-rw,mtls,jar,ob-uk

# Account Information Service Provider (AISP) testing
fapictl test --profiles oauth2-pkce,fapi-ro,mtls,jar,ob-uk --scopes "openid,accounts"

# Payment Initiation Service Provider (PISP) testing  
fapictl test --profiles oauth2-pkce,fapi-ro,fapi-rw,mtls,jar,ob-uk --scopes "openid,payments"
```

#### Brazilian Market Deployment
```bash
# Full Brazilian Open Finance compliance
fapictl test --profiles oauth2-pkce,fapi-ro,fapi-rw,mtls,jar,open-finance-br

# Account data sharing (Phase 2)
fapictl test --profiles oauth2-pkce,fapi-ro,mtls,jar,open-finance-br

# Payment initiation (Phase 3) 
fapictl test --profiles oauth2-pkce,fapi-ro,fapi-rw,mtls,jar,open-finance-br --scopes "openid,payments"
```

#### European Union (Generic PSD2)
```bash
# Generic PSD2 compliance (when implemented)
fapictl test --profiles oauth2-pkce,fapi-ro,fapi-rw,berlin-group

# Account Information Service
fapictl test --profiles oauth2-pkce,fapi-ro,berlin-group

# Payment Initiation Service
fapictl test --profiles oauth2-pkce,fapi-ro,fapi-rw,berlin-group
```

## Implementation Guidelines

### Adding New Regional Profiles

#### Research Phase
1. **Regulatory Framework**: Study local regulations and requirements
2. **Technical Standards**: Analyze published technical specifications
3. **Market Practices**: Understand local implementation patterns
4. **Certification Process**: Document certification and compliance procedures

#### Implementation Template
```go
package regional

import (
    "context"
    "strings"
    "time"
    
    httpClient "fapictl/pkg/http"
    "fapictl/pkg/verifier"
)

type MyRegionVerifier struct {
    client *httpClient.Client
}

func NewMyRegionVerifier(client *httpClient.Client) *MyRegionVerifier {
    return &MyRegionVerifier{client: client}
}

func (v *MyRegionVerifier) Name() string {
    return "My Region Open Banking"
}

func (v *MyRegionVerifier) Description() string {
    return "Verifies [Country/Region] open banking regulatory compliance"
}

func (v *MyRegionVerifier) Verify(ctx context.Context, config verifier.VerifierConfig) (*verifier.TestSuite, error) {
    suite := &verifier.TestSuite{
        Name:        v.Name(),
        Description: v.Description(),
        Tests:       []verifier.TestResult{},
    }
    
    startTime := time.Now()
    
    // Regional-specific tests
    suite.Tests = append(suite.Tests, v.testRegionalScopes(config))
    suite.Tests = append(suite.Tests, v.testRegionalCertificates(config))
    suite.Tests = append(suite.Tests, v.testRegulatoryCompliance(config))
    
    suite.Duration = time.Since(startTime)
    suite.Summary = v.calculateSummary(suite.Tests)
    
    return suite, nil
}
```

#### Best Practices for Regional Profiles

##### Regulatory Accuracy
- **Source Verification**: Use official regulatory documents and specifications
- **Version Tracking**: Track specification versions and regulatory updates
- **Authority Validation**: Verify requirements with local regulatory authorities
- **Market Consultation**: Engage with local market participants

##### Test Design
- **Comprehensive Coverage**: Test all regulatory requirements
- **Practical Focus**: Prioritize tests that catch real compliance issues
- **Clear Documentation**: Explain regulatory context for each test
- **Actionable Feedback**: Provide clear guidance for compliance issues

##### Configuration Flexibility
```go
func (v *RegionalVerifier) testRegionalRequirement(config verifier.VerifierConfig) verifier.TestResult {
    // Check for regional-specific configuration
    regionalConfig := v.extractRegionalConfig(config)
    
    if !v.isRegionalFeatureConfigured(regionalConfig) {
        return verifier.TestResult{
            Name:        "Regional Feature",
            Description: "Tests region-specific regulatory requirement",
            Status:      verifier.StatusSkip,
            Error:       "Regional feature not configured for this jurisdiction",
            Details: map[string]interface{}{
                "required_config": "regional_parameter_name",
                "jurisdiction":    "country_code",
                "regulation_ref":  "regulation_section",
            },
        }
    }
    
    // Perform regional validation
    // ...
}
```

## Compliance Considerations

### Certification and Audit
Regional profiles support various compliance scenarios:

#### Self-Assessment
```bash
# Basic compliance checking during development
fapictl test --profiles oauth2-pkce,fapi-ro,fapi-rw,ob-uk
```

#### Pre-Certification Testing
```bash
# Comprehensive testing before formal certification
fapictl test --profiles oauth2-pkce,fapi-ro,fapi-rw,mtls,jar,par,ob-uk --report html
```

#### Audit Trail Generation
```bash
# Generate detailed audit reports for compliance documentation
fapictl test --config production-config.yaml --profiles full-compliance-stack --report json > audit-report.json
```

### Continuous Compliance
```bash
# Automated compliance testing in CI/CD
fapictl test --config $CONFIG_FILE --profiles $COMPLIANCE_PROFILES --report json
```

## Troubleshooting Regional Issues

### Common Regional Configuration Problems

#### Directory Certificate Issues
```
Directory Certificate Validation         FAIL
Error: [Region] requires certificates from authorized directory
```
**Solution**: Obtain certificates from the appropriate regional directory authority.

#### Scope Configuration Issues
```
Regional Scopes                          FAIL
Error: No [region]-specific scopes found
```
**Solution**: Configure appropriate regional scopes in the configuration file.

#### Regulatory Parameter Missing
```
Regulatory Compliance Test               FAIL
Error: [Region] requires specific regulatory parameters
```
**Solution**: Add region-specific configuration parameters as documented.

### Regional Support Resources

#### Documentation References
- **UK**: [Open Banking Implementation Entity](https://www.openbanking.org.uk/)
- **Brazil**: [Open Finance Brasil](https://openfinancebrasil.org.br/)
- **EU**: [Berlin Group](https://www.berlin-group.org/)
- **Australia**: [Consumer Data Right](https://consumerdataright.gov.au/)

#### Certification Bodies
Each region typically has designated certification authorities:
- **UK**: OBIE Directory and FCA oversight
- **Brazil**: Central Bank of Brazil (BCB) certification
- **EU**: National competent authorities per PSD2
- **Australia**: ACCC CDR Register

This directory enables comprehensive testing of regional open banking and financial API compliance requirements, ensuring implementations meet local regulatory standards while maintaining global FAPI security principles.