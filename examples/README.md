# Configuration Examples

This directory contains various configuration examples for different FAPI compliance scenarios.

## Available Examples

### Basic Configurations
- [`basic-oauth2-pkce.yaml`](basic-oauth2-pkce.yaml) - Minimal OAuth2 + PKCE setup
- [`basic-fapi-ro.yaml`](basic-fapi-ro.yaml) - Basic FAPI Read-Only configuration
- [`basic-fapi-rw.yaml`](basic-fapi-rw.yaml) - Basic FAPI Read-Write configuration

### Security Enhanced
- [`fapi-with-mtls.yaml`](fapi-with-mtls.yaml) - FAPI with Mutual TLS authentication
- [`fapi-with-jar.yaml`](fapi-with-jar.yaml) - FAPI with JWT Secured Authorization Requests
- [`fapi-full-security.yaml`](fapi-full-security.yaml) - Complete FAPI setup with all security features

### Regional Compliance
- [`uk-open-banking.yaml`](uk-open-banking.yaml) - UK Open Banking configuration
- [`uk-open-banking-production.yaml`](uk-open-banking-production.yaml) - Production UK Open Banking setup
- [`brazil-open-finance.yaml`](brazil-open-finance.yaml) - Brazilian Open Finance configuration
- [`brazil-open-finance-production.yaml`](brazil-open-finance-production.yaml) - Production Brazilian setup

### Testing & Development
- [`sandbox-testing.yaml`](sandbox-testing.yaml) - Sandbox environment testing
- [`local-development.yaml`](local-development.yaml) - Local development setup
- [`ci-cd-testing.yaml`](ci-cd-testing.yaml) - CI/CD pipeline configuration

### Advanced Use Cases
- [`multi-profile-testing.yaml`](multi-profile-testing.yaml) - Testing multiple profiles
- [`custom-endpoints.yaml`](custom-endpoints.yaml) - Custom endpoint configurations
- [`legacy-compatibility.yaml`](legacy-compatibility.yaml) - Legacy single-profile format

## Usage

Copy any example configuration and modify it for your needs:

```bash
# Copy an example
cp examples/basic-fapi-ro.yaml my-config.yaml

# Edit the configuration
vim my-config.yaml

# Run tests with your configuration
fapictl test --config my-config.yaml
```

## Configuration Variables

Many examples use placeholder values that you'll need to replace:

- `YOUR_CLIENT_ID` - Your registered OAuth2 client ID
- `YOUR_REDIRECT_URI` - Your application's callback URL
- `AUTH_SERVER_BASE` - Your authorization server's base URL
- `./certs/` - Path to your certificate files
- `./keys/` - Path to your private key files

## Getting Help

- Run `fapictl wizard` for interactive configuration
- Use `fapictl validate config --config your-config.yaml` to check syntax
- See [`../PROFILE_USAGE.md`](../PROFILE_USAGE.md) for detailed profile documentation