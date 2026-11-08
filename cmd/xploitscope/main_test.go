package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/url"
	"strings"
	"testing"
)

func TestHelpShowsBannerAndScanCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"help"}, &stdout, &stderr); err != nil {
		t.Fatalf("run help: %v", err)
	}
	for _, expected := range []string{"Developer : Hex", "scan --url URL", "--authorized"} {
		if !strings.Contains(stdout.String(), expected) {
			t.Errorf("help output does not contain %q", expected)
		}
	}
}

func TestAnalysisReportIsReadableByDefault(t *testing.T) {
	raw, err := json.Marshal(analysisReport{
		Mode:             "offline_passive",
		ObservationCount: 1,
		Modules:          []string{"sqli"},
		Findings: []displayFinding{{
			Module:         "sqli",
			Title:          "Database error text appears in the response",
			Severity:       "medium",
			Confidence:     6,
			Status:         "potential",
			URL:            "https://example.test/",
			Location:       "response body, line 3",
			OWASP:          "A05:2025 Injection",
			Evidence:       "SQL error",
			Recommendation: "Review server-side errors.",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := printAnalysisReport(&output, raw); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"Indicators: 1", "[MEDIUM]", "URL:", "response body, line 3", "A05:2025 Injection", "confidence 6/10", "Fix:"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("report does not contain %q", expected)
		}
	}
}

func TestAnalyzeRequiresInput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"analyze"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "requires --input FILE") {
		t.Fatalf("expected missing-input error, got %v", err)
	}
}

func TestScanRequiresExplicitAuthorization(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"scan", "--url", "https://example.com"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "authorization") {
		t.Fatalf("expected authorization gate, got %v", err)
	}
}

func TestValidateScanURLBlocksLocalTargets(t *testing.T) {
	withCredentials := "https://" + "user" + ":" + "secret" + "@example.com/"
	for _, target := range []string{
		"http://127.0.0.1/",
		"http://10.0.0.1/",
		"http://169.254.169.254/",
		"http://192.0.2.1/",
		"http://[::1]/",
		"http://example.com:8080/",
		"file:///etc/passwd",
		withCredentials,
	} {
		if _, err := validateScanURL(target); err == nil {
			t.Errorf("expected target to be blocked: %q", target)
		}
	}
}

func TestPublicIPValidation(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "10.0.0.1", "192.0.2.1", "169.254.169.254", "2001:db8::1"} {
		if isPublicIP(net.ParseIP(address)) {
			t.Errorf("reserved address was allowed: %s", address)
		}
	}
	for _, address := range []string{"8.8.8.8", "2001:4860:4860::8888"} {
		if !isPublicIP(net.ParseIP(address)) {
			t.Errorf("public address was rejected: %s", address)
		}
	}
}

func TestSameOriginChecksSchemeHostAndPort(t *testing.T) {
	base, _ := url.Parse("https://example.com/start")
	same, _ := url.Parse("https://example.com/next")
	differentHost, _ := url.Parse("https://other.example/next")
	differentScheme, _ := url.Parse("http://example.com/next")

	if !sameOrigin(base, same) {
		t.Fatal("same-origin URL was rejected")
	}
	if sameOrigin(base, differentHost) || sameOrigin(base, differentScheme) {
		t.Fatal("cross-origin URL was accepted")
	}
}
