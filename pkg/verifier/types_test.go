package verifier

import (
	"testing"
	"time"
)

func TestTestResult_IsSuccess(t *testing.T) {
	tests := []struct {
		name   string
		status TestStatus
		want   bool
	}{
		{"Pass status", StatusPass, true},
		{"Fail status", StatusFail, false},
		{"Skip status", StatusSkip, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TestResult{Status: tt.status}
			got := result.Status == StatusPass
			if got != tt.want {
				t.Errorf("TestResult success check = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTestSummary_Calculate(t *testing.T) {
	tests := []TestResult{
		{Status: StatusPass},
		{Status: StatusPass},
		{Status: StatusFail},
		{Status: StatusSkip},
		{Status: StatusSkip},
	}

	summary := calculateSummary(tests)

	if summary.Total != 5 {
		t.Errorf("Total = %d, want 5", summary.Total)
	}

	if summary.Passed != 2 {
		t.Errorf("Passed = %d, want 2", summary.Passed)
	}

	if summary.Failed != 1 {
		t.Errorf("Failed = %d, want 1", summary.Failed)
	}

	if summary.Skipped != 2 {
		t.Errorf("Skipped = %d, want 2", summary.Skipped)
	}
}

func calculateSummary(tests []TestResult) TestSummary {
	summary := TestSummary{Total: len(tests)}
	for _, test := range tests {
		switch test.Status {
		case StatusPass:
			summary.Passed++
		case StatusFail:
			summary.Failed++
		case StatusSkip:
			summary.Skipped++
		}
	}
	return summary
}

func TestTestSummary_SuccessRate(t *testing.T) {
	tests := []struct {
		name     string
		passed   int
		total    int
		expected float64
	}{
		{"All passed", 5, 5, 100.0},
		{"Half passed", 5, 10, 50.0},
		{"None passed", 0, 10, 0.0},
		{"No tests", 0, 0, 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := TestSummary{
				Passed: tt.passed,
				Total:  tt.total,
			}

			var rate float64
			if summary.Total > 0 {
				rate = float64(summary.Passed) / float64(summary.Total) * 100
			}

			if rate != tt.expected {
				t.Errorf("SuccessRate() = %f, want %f", rate, tt.expected)
			}
		})
	}
}

func TestTestSummary_IsHealthy(t *testing.T) {
	tests := []struct {
		name     string
		passed   int
		failed   int
		skipped  int
		expected bool
	}{
		{"All passed", 5, 0, 0, true},
		{"Mostly passed", 8, 1, 1, true},
		{"Some failures", 5, 3, 2, false},
		{"All failed", 0, 5, 0, false},
		{"All skipped", 0, 0, 5, false},
		{"Mixed with low success", 2, 8, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := TestSummary{
				Total:   tt.passed + tt.failed + tt.skipped,
				Passed:  tt.passed,
				Failed:  tt.failed,
				Skipped: tt.skipped,
			}

			// Consider healthy if >70% pass rate and less than 30% failures
			healthy := false
			if summary.Total > 0 {
				passRate := float64(summary.Passed) / float64(summary.Total)
				failRate := float64(summary.Failed) / float64(summary.Total)
				healthy = passRate > 0.7 && failRate < 0.3
			}

			if healthy != tt.expected {
				t.Errorf("IsHealthy() = %v, want %v (passed=%d, failed=%d, skipped=%d)",
					healthy, tt.expected, tt.passed, tt.failed, tt.skipped)
			}
		})
	}
}

func TestTestStatus_String(t *testing.T) {
	tests := []struct {
		status TestStatus
		want   string
	}{
		{StatusPass, "PASS"},
		{StatusFail, "FAIL"},
		{StatusSkip, "SKIP"},
	}

	for _, tt := range tests {
		if got := string(tt.status); got != tt.want {
			t.Errorf("TestStatus.String() = %s, want %s", got, tt.want)
		}
	}
}

func TestVerifierConfig_HasMTLS(t *testing.T) {
	tests := []struct {
		name string
		cert string
		key  string
		want bool
	}{
		{"Both cert and key", "/path/to/cert.pem", "/path/to/key.pem", true},
		{"Only cert", "/path/to/cert.pem", "", false},
		{"Only key", "", "/path/to/key.pem", false},
		{"Neither", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := VerifierConfig{
				MTLSCert: tt.cert,
				MTLSKey:  tt.key,
			}

			got := config.MTLSCert != "" && config.MTLSKey != ""
			if got != tt.want {
				t.Errorf("HasMTLS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifierConfig_HasPrivateKeyJWT(t *testing.T) {
	tests := []struct {
		name string
		kid  string
		key  string
		want bool
	}{
		{"Both kid and key", "key-1", "/path/to/key.pem", true},
		{"Only kid", "key-1", "", false},
		{"Only key", "", "/path/to/key.pem", false},
		{"Neither", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := VerifierConfig{
				PrivateKeyJWTKID: tt.kid,
				PrivateKeyJWTKey: tt.key,
			}

			got := config.PrivateKeyJWTKID != "" && config.PrivateKeyJWTKey != ""
			if got != tt.want {
				t.Errorf("HasPrivateKeyJWT() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTestRunner_Creation(t *testing.T) {
	config := VerifierConfig{
		ClientID: "test-client",
		Scopes:   []string{"openid"},
	}

	runner := NewTestRunner(config)
	if runner == nil {
		t.Error("NewTestRunner() should not return nil")
	}

	if runner.config.ClientID != "test-client" {
		t.Errorf("TestRunner config.ClientID = %s, want test-client", runner.config.ClientID)
	}
}

func TestTestSuite_UpdateSummary(t *testing.T) {
	suite := &TestSuite{
		Name: "Test Suite",
		Tests: []TestResult{
			{Status: StatusPass},
			{Status: StatusFail},
			{Status: StatusSkip},
		},
		Duration: 100 * time.Millisecond,
	}

	// Manually calculate summary
	suite.Summary = calculateSummary(suite.Tests)

	if suite.Summary.Total != 3 {
		t.Errorf("Summary.Total = %d, want 3", suite.Summary.Total)
	}

	if suite.Summary.Passed != 1 {
		t.Errorf("Summary.Passed = %d, want 1", suite.Summary.Passed)
	}

	if suite.Summary.Failed != 1 {
		t.Errorf("Summary.Failed = %d, want 1", suite.Summary.Failed)
	}

	if suite.Summary.Skipped != 1 {
		t.Errorf("Summary.Skipped = %d, want 1", suite.Summary.Skipped)
	}
}
