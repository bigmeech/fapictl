package http

import (
	"net/http"
	"time"

	"fapictl/pkg/logger"
)

// LoggingTransport wraps an http.RoundTripper to log requests and responses
type LoggingTransport struct {
	Transport http.RoundTripper
	Logger    *logger.Logger
}

// NewLoggingTransport creates a new logging transport wrapper
func NewLoggingTransport(transport http.RoundTripper, log *logger.Logger) *LoggingTransport {
	if transport == nil {
		transport = http.DefaultTransport
	}

	return &LoggingTransport{
		Transport: transport,
		Logger:    log,
	}
}

// RoundTrip executes the HTTP request and logs the details
func (t *LoggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()

	// Execute the request
	resp, err := t.Transport.RoundTrip(req)
	duration := time.Since(start)

	// Log the HTTP exchange
	if t.Logger != nil {
		t.Logger.HTTP(req, resp, duration)
	}

	return resp, err
}
