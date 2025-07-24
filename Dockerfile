# Build stage
FROM golang:1.21-alpine AS builder

# Install git and ca-certificates
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build arguments
ARG VERSION=dev
ARG BUILD_TIME
ARG COMMIT_HASH

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X main.version=${VERSION} -X main.buildTime=${BUILD_TIME} -X main.commitHash=${COMMIT_HASH} -w -s" \
    -o fapictl .

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -g 1001 -S fapictl && \
    adduser -u 1001 -S fapictl -G fapictl

# Set working directory
WORKDIR /home/fapictl

# Copy binary from builder stage
COPY --from=builder /app/fapictl /usr/local/bin/fapictl

# Change ownership
RUN chown fapictl:fapictl /usr/local/bin/fapictl

# Switch to non-root user
USER fapictl

# Expose port (if needed for future web interface)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD fapictl --version || exit 1

# Set entrypoint
ENTRYPOINT ["fapictl"]
CMD ["--help"]