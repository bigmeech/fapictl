package verifier

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Reporter struct{}

func NewReporter() *Reporter {
	return &Reporter{}
}

func (r *Reporter) GenerateReport(suites []*TestSuite, format string, writer io.Writer) error {
	switch format {
	case "json":
		return r.generateJSONReport(suites, writer)
	case "yaml":
		return r.generateYAMLReport(suites, writer)
	case "html":
		return r.generateHTMLReport(suites, writer)
	case "text":
		return r.generateTextReport(suites, writer)
	default:
		return fmt.Errorf("unsupported report format: %s", format)
	}
}

func (r *Reporter) generateJSONReport(suites []*TestSuite, writer io.Writer) error {
	report := struct {
		Timestamp time.Time    `json:"timestamp"`
		Suites    []*TestSuite `json:"test_suites"`
		Summary   TestSummary  `json:"summary"`
	}{
		Timestamp: time.Now(),
		Suites:    suites,
		Summary:   r.calculateOverallSummary(suites),
	}

	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func (r *Reporter) generateYAMLReport(suites []*TestSuite, writer io.Writer) error {
	report := struct {
		Timestamp time.Time    `yaml:"timestamp"`
		Suites    []*TestSuite `yaml:"test_suites"`
		Summary   TestSummary  `yaml:"summary"`
	}{
		Timestamp: time.Now(),
		Suites:    suites,
		Summary:   r.calculateOverallSummary(suites),
	}

	encoder := yaml.NewEncoder(writer)
	defer encoder.Close()
	return encoder.Encode(report)
}

func (r *Reporter) generateHTMLReport(suites []*TestSuite, writer io.Writer) error {
	tmpl := `
<!DOCTYPE html>
<html>
<head>
    <title>FAPI Compliance Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f5f5f5; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .suite { margin-bottom: 30px; border: 1px solid #ddd; border-radius: 5px; }
        .suite-header { background-color: #e9ecef; padding: 15px; border-bottom: 1px solid #ddd; }
        .test { padding: 10px; border-bottom: 1px solid #eee; }
        .test:last-child { border-bottom: none; }
        .pass { color: #28a745; }
        .fail { color: #dc3545; }
        .skip { color: #6c757d; }
        .summary { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-top: 20px; }
        .details { background-color: #f8f9fa; padding: 10px; margin-top: 5px; border-radius: 3px; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>FAPI Compliance Test Report</h1>
        <p>Generated: {{.Timestamp.Format "2006-01-02 15:04:05 UTC"}}</p>
        <div class="summary">
            <h3>Overall Summary</h3>
            <p>Total: {{.Summary.Total}} | Passed: <span class="pass">{{.Summary.Passed}}</span> | Failed: <span class="fail">{{.Summary.Failed}}</span> | Skipped: <span class="skip">{{.Summary.Skipped}}</span></p>
        </div>
    </div>

    {{range .Suites}}
    <div class="suite">
        <div class="suite-header">
            <h2>{{.Name}}</h2>
            <p>{{.Description}}</p>
            <p>Duration: {{.Duration}} | Tests: {{.Summary.Total}} | Passed: <span class="pass">{{.Summary.Passed}}</span> | Failed: <span class="fail">{{.Summary.Failed}}</span> | Skipped: <span class="skip">{{.Summary.Skipped}}</span></p>
        </div>
        {{range .Tests}}
        <div class="test">
            <h4><span class="{{.Status | lower}}">{{.Status}}</span> {{.Name}}</h4>
            <p>{{.Description}}</p>
            <p><small>Duration: {{.Duration}}</small></p>
            {{if .Error}}
            <p><strong>Error:</strong> {{.Error}}</p>
            {{end}}
        </div>
        {{end}}
    </div>
    {{end}}
</body>
</html>
`

	funcMap := template.FuncMap{
		"lower": strings.ToLower,
	}

	t, err := template.New("report").Funcs(funcMap).Parse(tmpl)
	if err != nil {
		return err
	}

	data := struct {
		Timestamp time.Time
		Suites    []*TestSuite
		Summary   TestSummary
	}{
		Timestamp: time.Now(),
		Suites:    suites,
		Summary:   r.calculateOverallSummary(suites),
	}

	return t.Execute(writer, data)
}

func (r *Reporter) generateTextReport(suites []*TestSuite, writer io.Writer) error {
	overall := r.calculateOverallSummary(suites)

	fmt.Fprintf(writer, "FAPI Compliance Test Report\n")
	fmt.Fprintf(writer, "Generated: %s\n\n", time.Now().Format("2006-01-02 15:04:05 UTC"))

	for _, suite := range suites {
		fmt.Fprintf(writer, "=== %s ===\n", suite.Name)
		fmt.Fprintf(writer, "%s\n", suite.Description)
		fmt.Fprintf(writer, "Duration: %s\n\n", suite.Duration)

		for _, test := range suite.Tests {
			status := test.Status
			switch status {
			case StatusPass:
				status = "PASS"
			case StatusFail:
				status = "FAIL"
			case StatusSkip:
				status = "SKIP"
			}

			fmt.Fprintf(writer, "%-40s %s\n", test.Name, status)
			if test.Error != "" {
				fmt.Fprintf(writer, "  Error: %s\n", test.Error)
			}
		}

		fmt.Fprintf(writer, "\nSuite Summary: %d total, %d passed, %d failed, %d skipped\n\n",
			suite.Summary.Total, suite.Summary.Passed, suite.Summary.Failed, suite.Summary.Skipped)
	}

	fmt.Fprintf(writer, "=== Overall Summary ===\n")
	fmt.Fprintf(writer, "Total: %d | Passed: %d | Failed: %d | Skipped: %d\n",
		overall.Total, overall.Passed, overall.Failed, overall.Skipped)

	return nil
}

func (r *Reporter) calculateOverallSummary(suites []*TestSuite) TestSummary {
	var summary TestSummary

	for _, suite := range suites {
		summary.Total += suite.Summary.Total
		summary.Passed += suite.Summary.Passed
		summary.Failed += suite.Summary.Failed
		summary.Skipped += suite.Summary.Skipped
	}

	return summary
}
