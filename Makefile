# fapictl Makefile

# Variables
BINARY_NAME=fapictl
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
COMMIT_HASH=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS=-ldflags "-X main.version=${VERSION} -X main.buildTime=${BUILD_TIME} -X main.commitHash=${COMMIT_HASH}"

# Build directory
BUILD_DIR=build
DIST_DIR=dist

# Go related variables
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=gofmt
GOLINT=golangci-lint

# Platform targets
PLATFORMS=linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: all build clean test coverage lint fmt vet tidy deps install uninstall release help

## Default target
all: clean fmt lint vet test build

## Build the binary
build:
	@echo "Building ${BINARY_NAME}..."
	@mkdir -p ${BUILD_DIR}
	${GOBUILD} ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME} .

## Build for all platforms
build-all: clean
	@echo "Building for all platforms..."
	@mkdir -p ${DIST_DIR}
	@for platform in $(PLATFORMS); do \
		OS=$$(echo $$platform | cut -d'/' -f1); \
		ARCH=$$(echo $$platform | cut -d'/' -f2); \
		OUTPUT_NAME=${BINARY_NAME}-$$OS-$$ARCH; \
		if [ $$OS = "windows" ]; then OUTPUT_NAME=$$OUTPUT_NAME.exe; fi; \
		echo "Building $$OUTPUT_NAME..."; \
		GOOS=$$OS GOARCH=$$ARCH ${GOBUILD} ${LDFLAGS} -o ${DIST_DIR}/$$OUTPUT_NAME .; \
	done

## Run tests
test:
	@echo "Running tests..."
	${GOTEST} -v ./...

## Run tests with coverage
coverage:
	@echo "Running tests with coverage..."
	${GOTEST} -v -race -coverprofile=coverage.out ./...
	${GOCMD} tool cover -html=coverage.out -o coverage.html

## Run linter
lint:
	@echo "Running linter..."
	@if command -v ${GOLINT} >/dev/null 2>&1; then \
		${GOLINT} run ./...; \
	else \
		echo "golangci-lint not installed. Install with: curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b \$$(go env GOPATH)/bin v1.54.2"; \
	fi

## Format code
fmt:
	@echo "Formatting code..."
	${GOFMT} -s -w .

## Run go vet
vet:
	@echo "Running go vet..."
	${GOCMD} vet ./...

## Tidy dependencies
tidy:
	@echo "Tidying dependencies..."
	${GOMOD} tidy

## Download dependencies
deps:
	@echo "Downloading dependencies..."
	${GOMOD} download

## Install binary to GOPATH/bin
install: build
	@echo "Installing ${BINARY_NAME}..."
	${GOCMD} install ${LDFLAGS} .

## Uninstall binary from GOPATH/bin
uninstall:
	@echo "Uninstalling ${BINARY_NAME}..."
	@rm -f $$(which ${BINARY_NAME})

## Clean build artifacts
clean:
	@echo "Cleaning..."
	${GOCLEAN}
	@rm -rf ${BUILD_DIR}
	@rm -rf ${DIST_DIR}
	@rm -f coverage.out coverage.html

## Create a release (used by CI)
release: clean build-all
	@echo "Creating release artifacts..."
	@cd ${DIST_DIR} && for file in *; do \
		if [[ $$file == *.exe ]]; then \
			zip $${file%.*}.zip $$file; \
		else \
			tar -czf $$file.tar.gz $$file; \
		fi; \
	done

## Run development server (builds and runs)
dev: build
	@echo "Running development build..."
	./${BUILD_DIR}/${BINARY_NAME} --help

## Check if tools are installed
check-tools:
	@echo "Checking required tools..."
	@command -v go >/dev/null 2>&1 || { echo "Go is required but not installed."; exit 1; }
	@echo "✓ Go is installed"
	@if command -v ${GOLINT} >/dev/null 2>&1; then \
		echo "✓ golangci-lint is installed"; \
	else \
		echo "⚠ golangci-lint not found. Install with: curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b \$$(go env GOPATH)/bin v1.54.2"; \
	fi

## Show help
help:
	@echo "Available targets:"
	@echo "  all         - Run clean, fmt, lint, vet, test, and build"
	@echo "  build       - Build the binary"
	@echo "  build-all   - Build for all platforms"
	@echo "  test        - Run tests"
	@echo "  coverage    - Run tests with coverage report"
	@echo "  lint        - Run linter"
	@echo "  fmt         - Format code"
	@echo "  vet         - Run go vet"
	@echo "  tidy        - Tidy dependencies"
	@echo "  deps        - Download dependencies"
	@echo "  install     - Install binary to GOPATH/bin"
	@echo "  uninstall   - Remove binary from GOPATH/bin"
	@echo "  clean       - Clean build artifacts"
	@echo "  release     - Create release artifacts"
	@echo "  dev         - Build and show help"
	@echo "  check-tools - Check if required tools are installed"
	@echo "  help        - Show this help message"