package logger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"fapictl/pkg/colors"
)

// LogLevel represents the logging verbosity level
type LogLevel int

const (
	LogLevelQuiet LogLevel = iota
	LogLevelInfo
	LogLevelVerbose
	LogLevelDebug
)

// Logger handles verbose output for fapictl
type Logger struct {
	level  LogLevel
	output io.Writer
}

// NewLogger creates a new logger with the specified level
func NewLogger(level LogLevel) *Logger {
	return &Logger{
		level:  level,
		output: os.Stdout,
	}
}

// SetOutput sets the output writer for the logger
func (l *Logger) SetOutput(w io.Writer) {
	l.output = w
}

// Info logs informational messages (always shown unless quiet)
func (l *Logger) Info(format string, args ...interface{}) {
	if l.level >= LogLevelInfo {
		l.printf(colors.Info("INFO: ")+format, args...)
	}
}

// Verbose logs detailed execution information
func (l *Logger) Verbose(format string, args ...interface{}) {
	if l.level >= LogLevelVerbose {
		l.printf(colors.Gray("VERBOSE: ")+format, args...)
	}
}

// Debug logs debug information and HTTP traffic
func (l *Logger) Debug(format string, args ...interface{}) {
	if l.level >= LogLevelDebug {
		l.printf(colors.Magenta("DEBUG: ")+format, args...)
	}
}

// Success logs success messages
func (l *Logger) Success(format string, args ...interface{}) {
	if l.level >= LogLevelInfo {
		l.printf(colors.Success("SUCCESS: ")+format, args...)
	}
}

// Warning logs warning messages
func (l *Logger) Warning(format string, args ...interface{}) {
	if l.level >= LogLevelInfo {
		l.printf(colors.Warning("WARNING: ")+format, args...)
	}
}

// Error logs error messages
func (l *Logger) Error(format string, args ...interface{}) {
	if l.level >= LogLevelInfo {
		l.printf(colors.Error("ERROR: ")+format, args...)
	}
}

// Step logs test step information
func (l *Logger) Step(step int, total int, description string) {
	if l.level >= LogLevelVerbose {
		l.printf(colors.Gray("STEP %d/%d: ")+"%s", step, total, description)
	}
}

// HTTP logs HTTP request/response information
func (l *Logger) HTTP(req *http.Request, resp *http.Response, duration time.Duration) {
	if l.level < LogLevelDebug {
		return
	}

	l.printf("\n" + strings.Repeat("=", 80))
	l.printf(colors.Cyan("HTTP Request/Response (Duration: %v)"), duration)
	l.printf(strings.Repeat("=", 80))

	// Log request
	if req != nil {
		l.logHTTPRequest(req)
	}

	// Log response
	if resp != nil {
		l.logHTTPResponse(resp)
	}

	l.printf(strings.Repeat("=", 80) + "\n")
}

// logHTTPRequest logs detailed HTTP request information
func (l *Logger) logHTTPRequest(req *http.Request) {
	l.printf("\n" + colors.Header("REQUEST:"))
	l.printf("Method: %s", req.Method)
	l.printf("URL: %s", req.URL.String())
	l.printf("Proto: %s", req.Proto)

	// Log headers
	if len(req.Header) > 0 {
		l.printf("\nRequest Headers:")
		for name, values := range req.Header {
			for _, value := range values {
				// Mask sensitive headers
				if l.isSensitiveHeader(name) {
					value = l.maskSensitiveValue(value)
				}
				l.printf("  %s: %s", name, value)
			}
		}
	}

	// Log body if present
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err == nil && len(body) > 0 {
			l.printf("\nRequest Body:")
			l.logFormattedContent(body, req.Header.Get("Content-Type"))
		}
		// Restore body for actual request
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
}

// logHTTPResponse logs detailed HTTP response information
func (l *Logger) logHTTPResponse(resp *http.Response) {
	l.printf("\n" + colors.Header("RESPONSE:"))
	l.printf("Status: %s", resp.Status)
	l.printf("Proto: %s", resp.Proto)

	// Log headers
	if len(resp.Header) > 0 {
		l.printf("\nResponse Headers:")
		for name, values := range resp.Header {
			for _, value := range values {
				l.printf("  %s: %s", name, value)
			}
		}
	}

	// Log body if present
	if resp.Body != nil {
		body, err := io.ReadAll(resp.Body)
		if err == nil && len(body) > 0 {
			l.printf("\nResponse Body:")
			l.logFormattedContent(body, resp.Header.Get("Content-Type"))
		}
		// Restore body for actual usage
		resp.Body = io.NopCloser(bytes.NewReader(body))
	}
}

// logFormattedContent logs content with appropriate formatting
func (l *Logger) logFormattedContent(content []byte, contentType string) {
	contentStr := string(content)

	// Try to format JSON
	if strings.Contains(contentType, "application/json") || l.isJSON(contentStr) {
		l.logJSON(contentStr)
		return
	}

	// Format form data
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		l.logFormData(contentStr)
		return
	}

	// Default: log as plain text with indentation
	lines := strings.Split(contentStr, "\n")
	for _, line := range lines {
		l.printf("  %s", line)
	}
}

// logJSON logs JSON content with proper formatting
func (l *Logger) logJSON(jsonStr string) {
	var jsonObj interface{}
	if err := json.Unmarshal([]byte(jsonStr), &jsonObj); err == nil {
		if formatted, err := json.MarshalIndent(jsonObj, "  ", "  "); err == nil {
			lines := strings.Split(string(formatted), "\n")
			for _, line := range lines {
				l.printf("  %s", line)
			}
			return
		}
	}

	// Fallback to raw JSON
	lines := strings.Split(jsonStr, "\n")
	for _, line := range lines {
		l.printf("  %s", line)
	}
}

// logFormData logs form-encoded data in a readable format
func (l *Logger) logFormData(formData string) {
	pairs := strings.Split(formData, "&")
	for _, pair := range pairs {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			key := parts[0]
			value := parts[1]

			// Mask sensitive values
			if l.isSensitiveKey(key) {
				value = l.maskSensitiveValue(value)
			}

			l.printf("  %s: %s", key, value)
		} else {
			l.printf("  %s", pair)
		}
	}
}

// Test logs test execution information
func (l *Logger) Test(testName string, status string, duration time.Duration, details string) {
	if l.level >= LogLevelVerbose {
		var coloredStatus string
		switch strings.ToUpper(status) {
		case "PASS":
			coloredStatus = colors.Success("PASS")
		case "FAIL":
			coloredStatus = colors.Error("FAIL")
		case "SKIP":
			coloredStatus = colors.Skip("SKIP")
		default:
			coloredStatus = colors.Info(status)
		}

		l.printf("%s %s (%v)", coloredStatus, testName, duration)
		if details != "" && l.level >= LogLevelDebug {
			l.printf("   Details: %s", details)
		}
	}
}

// PKCE logs PKCE generation details
func (l *Logger) PKCE(verifier, challenge, method string) {
	if l.level >= LogLevelDebug {
		l.printf("\n" + colors.Header("PKCE Generation:"))
		l.printf("Method: %s", method)
		l.printf("Verifier: %s", l.maskSensitiveValue(verifier))
		l.printf("Challenge: %s", challenge)
	}
}

// JWT logs JWT token information
func (l *Logger) JWT(tokenType, token string) {
	if l.level >= LogLevelDebug {
		l.printf("\n"+colors.Header("JWT Token (%s):"), tokenType)

		// Split JWT into parts
		parts := strings.Split(token, ".")
		if len(parts) == 3 {
			l.printf("Header: %s", l.truncateToken(parts[0]))
			l.printf("Payload: %s", l.truncateToken(parts[1]))
			l.printf("Signature: %s", l.maskSensitiveValue(parts[2]))
		} else {
			l.printf("Token: %s", l.truncateToken(token))
		}
	}
}

// Certificate logs certificate information
func (l *Logger) Certificate(certType, subject, issuer string, expires time.Time) {
	if l.level >= LogLevelVerbose {
		l.printf("\n📜 Certificate (%s):", certType)
		l.printf("Subject: %s", subject)
		l.printf("Issuer: %s", issuer)
		l.printf("Expires: %s", expires.Format(time.RFC3339))
	}
}

// Endpoint logs endpoint information
func (l *Logger) Endpoint(name, url, method string) {
	if l.level >= LogLevelVerbose {
		l.printf(colors.Cyan("%s Endpoint: ")+"%s %s", name, method, colors.URL(url))
	}
}

// Helper methods

func (l *Logger) printf(format string, args ...interface{}) {
	timestamp := time.Now().Format("15:04:05.000")
	fmt.Fprintf(l.output, "[%s] %s\n", timestamp, fmt.Sprintf(format, args...))
}

func (l *Logger) isSensitiveHeader(name string) bool {
	sensitive := []string{
		"authorization", "cookie", "set-cookie", "x-api-key",
		"x-auth-token", "x-access-token", "bearer", "basic",
	}

	lowerName := strings.ToLower(name)
	for _, s := range sensitive {
		if strings.Contains(lowerName, s) {
			return true
		}
	}
	return false
}

func (l *Logger) isSensitiveKey(key string) bool {
	sensitive := []string{
		"client_secret", "password", "token", "code", "verifier",
		"client_assertion", "assertion", "private_key", "secret",
	}

	lowerKey := strings.ToLower(key)
	for _, s := range sensitive {
		if strings.Contains(lowerKey, s) {
			return true
		}
	}
	return false
}

func (l *Logger) maskSensitiveValue(value string) string {
	if len(value) <= 8 {
		return strings.Repeat("*", len(value))
	}

	// Show first 4 and last 4 characters
	return value[:4] + strings.Repeat("*", len(value)-8) + value[len(value)-4:]
}

func (l *Logger) truncateToken(token string) string {
	if len(token) <= 50 {
		return token
	}
	return token[:20] + "..." + token[len(token)-20:]
}

func (l *Logger) isJSON(str string) bool {
	str = strings.TrimSpace(str)
	return (strings.HasPrefix(str, "{") && strings.HasSuffix(str, "}")) ||
		(strings.HasPrefix(str, "[") && strings.HasSuffix(str, "]"))
}

// Global logger instance
var defaultLogger *Logger

// InitLogger initializes the global logger
func InitLogger(level LogLevel) {
	defaultLogger = NewLogger(level)
}

// GetLogger returns the global logger instance
func GetLogger() *Logger {
	if defaultLogger == nil {
		defaultLogger = NewLogger(LogLevelInfo)
	}
	return defaultLogger
}

// Convenience functions for global logger
func Info(format string, args ...interface{})    { GetLogger().Info(format, args...) }
func Verbose(format string, args ...interface{}) { GetLogger().Verbose(format, args...) }
func Debug(format string, args ...interface{})   { GetLogger().Debug(format, args...) }
func Success(format string, args ...interface{}) { GetLogger().Success(format, args...) }
func Warning(format string, args ...interface{}) { GetLogger().Warning(format, args...) }
func Error(format string, args ...interface{})   { GetLogger().Error(format, args...) }
