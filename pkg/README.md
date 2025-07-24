# pkg/ Directory

This directory contains the core packages and libraries that power fapictl's FAPI compliance testing functionality.

## Directory Structure

```
pkg/
├── config/          # Configuration file parsing and validation
├── crypto/          # Cryptographic utilities (PKCE, JWT, etc.)
├── http/            # HTTP client with security features (mTLS, TLS 1.2+)
├── profiles/        # Modular FAPI profile verification system
└── verifier/        # Test execution framework and reporting
```

## Package Overview

### Core Infrastructure
- **config/** - Handles YAML configuration parsing, validation, and management
- **http/** - Provides secure HTTP client with mTLS support and proper TLS configuration
- **crypto/** - Implements cryptographic operations required for FAPI compliance
- **verifier/** - Core testing framework with result aggregation and multi-format reporting

### Testing Profiles
- **profiles/** - Modular plugin architecture for FAPI compliance verification
  - Mandatory profiles (OAuth2, FAPI-RO, FAPI-RW)
  - Optional extensions (mTLS, JAR, PAR, CIBA, DPoP)
  - Regional implementations (UK Open Banking, Brazil Open Finance, etc.)

## Architecture Principles

1. **Modularity**: Each package has a single, well-defined responsibility
2. **Security-First**: All components implement security best practices by default
3. **Extensibility**: Plugin architecture allows easy addition of new profiles
4. **Standards Compliance**: Strict adherence to OAuth 2.0, OIDC, and FAPI specifications

## Inter-Package Dependencies

```
profiles/ ────┐
              ├─── verifier/ ───── config/
http/ ────────┘                    │
                                   │
crypto/ ───────────────────────────┘
```

- **profiles/** depends on **verifier/**, **http/**, and **crypto/**
- **verifier/** depends on **config/** for test configuration
- All packages can use shared utilities from **crypto/** and **http/**

## Usage Patterns

Most functionality is accessed through the **profiles/** package, which orchestrates:
- Configuration loading via **config/**
- Secure HTTP communications via **http/**
- Cryptographic operations via **crypto/**
- Test execution and reporting via **verifier/**

For detailed documentation of each package, see the README files in their respective directories.