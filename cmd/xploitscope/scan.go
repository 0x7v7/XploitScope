package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const maxScanBody = 1 << 20

var hostnamePattern = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.?$`)

type scanResult struct {
	Target        string             `json:"target"`
	ScannedAt     time.Time          `json:"scanned_at"`
	StatusCode    int                `json:"status_code"`
	TLSVersion    string             `json:"tls_version,omitempty"`
	Findings      json.RawMessage    `json:"findings"`
	OWASPCoverage []categoryCoverage `json:"owasp_top_10_2025_coverage"`
	Limitations   []string           `json:"limitations"`
}

type categoryCoverage struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Note   string `json:"note"`
}

func runScan(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: xploitscope scan --url https://HOST --authorized [--output report.json]")
		flags.PrintDefaults()
	}
	target := flags.String("url", "", "one public HTTP(S) URL you are authorized to assess")
	authorized := flags.Bool("authorized", false, "confirm you own this target or have written authorization")
	output := flags.String("output", "", "write the full JSON report to this file")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() > 1 {
		return errors.New("scan accepts at most one URL")
	}
	inputReader := bufio.NewReader(os.Stdin)
	if *target == "" && flags.NArg() == 1 {
		*target = flags.Arg(0)
	}
	if *target == "" {
		if !isTerminal(os.Stdin) {
			return errors.New("scan requires --url URL when stdin is not an interactive terminal")
		}
		fmt.Fprint(stdout, "Target URL: ")
		line, err := inputReader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("read target URL: %w", err)
		}
		*target = strings.TrimSpace(line)
		if *target == "" {
			return errors.New("target URL cannot be empty")
		}
	}
	if !*authorized {
		if !isTerminal(os.Stdin) {
			return errors.New("scan requires --authorized; only scan systems you own or have written permission to assess")
		}
		fmt.Fprint(stdout, "Do you own this target or have written authorization? Type 'yes' to continue: ")
		line, err := inputReader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("read authorization confirmation: %w", err)
		}
		if strings.TrimSpace(line) != "yes" {
			return errors.New("authorization was not confirmed; scan cancelled")
		}
	}

	parsed, err := validateScanURL(*target)
	if err != nil {
		return err
	}
	safeTarget := *parsed
	safeTarget.RawQuery = ""
	safeTarget.ForceQuery = false
	safeTarget.Fragment = ""
	fmt.Fprintln(stderr, "[*] Sending one low-impact GET request; no crawling or exploit payloads.")
	observation, status, tlsVersion, err := fetchSnapshot(parsed)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]any{"observations": []any{observation}})
	if err != nil {
		return fmt.Errorf("encode HTTP observation: %w", err)
	}

	var analysis bytes.Buffer
	if err := runWorkerCommand("analyze", payload, &analysis); err != nil {
		return err
	}
	var result struct {
		Findings json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(analysis.Bytes(), &result); err != nil {
		return fmt.Errorf("parse detector results: %w", err)
	}
	report := scanResult{
		Target:        safeTarget.String(),
		ScannedAt:     time.Now().UTC(),
		StatusCode:    status,
		TLSVersion:    tlsVersion,
		Findings:      result.Findings,
		OWASPCoverage: owaspCoverage,
		Limitations:   scanLimitations,
	}
	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("encode scan report: %w", err)
	}
	if *output != "" {
		if err := os.WriteFile(*output, append(reportJSON, '\n'), 0o600); err != nil {
			return fmt.Errorf("write scan report: %w", err)
		}
	}
	if err := printScanReport(stdout, report); err != nil {
		return err
	}
	if *output != "" {
		fmt.Fprintf(stdout, "\nJSON report saved to %s\n", *output)
	}
	return nil
}

var scanLimitations = []string{
	"Passive HTTP/TLS review only; findings are indicators, not confirmed vulnerabilities.",
	"OWASP A01, A03, A06, A07, A08, A09, and A10 are not assessed by this request.",
	"OWASP A02 coverage is limited to response configuration; A04 reports negotiated TLS only.",
	"OWASP A05 indicators do not confirm injection vulnerabilities.",
	"No login, crawling, form submission, injection payloads, or exploit validation is performed.",
}

var owaspCoverage = []categoryCoverage{
	{"A01:2025", "Broken Access Control", "not_assessed", "Requires authenticated roles and authorization-boundary testing."},
	{"A02:2025", "Security Misconfiguration", "partial", "Checks a limited set of response headers and cookie attributes."},
	{"A03:2025", "Software Supply Chain Failures", "not_assessed", "Requires dependency, build, and supply-chain inventory."},
	{"A04:2025", "Cryptographic Failures", "partial", "Reports negotiated TLS version only; does not audit cryptographic design or storage."},
	{"A05:2025", "Injection", "partial", "May flag errors or reflection in supplied snapshots; does not validate exploitability."},
	{"A06:2025", "Insecure Design", "not_assessed", "Requires application context and design review."},
	{"A07:2025", "Authentication Failures", "not_assessed", "Does not log in or test authentication/session flows."},
	{"A08:2025", "Software or Data Integrity Failures", "not_assessed", "Requires build, update, and integrity-control review."},
	{"A09:2025", "Security Logging and Alerting Failures", "not_assessed", "Cannot assess internal logging behavior from a public response."},
	{"A10:2025", "Mishandling of Exceptional Conditions", "not_assessed", "Requires controlled error-path testing and application context."},
}

func validateScanURL(raw string) (*url.URL, error) {
	if len(raw) > 4096 {
		return nil, errors.New("URL exceeds the 4096-byte limit")
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return nil, errors.New("provide a valid HTTP(S) URL without embedded credentials")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("only http and https URLs are supported")
	}
	host := strings.TrimSuffix(parsed.Hostname(), ".")
	if host == "" {
		return nil, errors.New("URL must contain a hostname")
	}
	if ip := net.ParseIP(host); ip != nil {
		if !isPublicIP(ip) {
			return nil, errors.New("private, local, and reserved IP targets are not allowed")
		}
	} else if !hostnamePattern.MatchString(host) {
		return nil, errors.New("URL hostname is invalid")
	}
	if parsed.Port() != "" {
		port, err := strconv.Atoi(parsed.Port())
		if err != nil || port < 1 || port > 65535 {
			return nil, errors.New("URL port is invalid")
		}
		expectedPort := "80"
		if parsed.Scheme == "https" {
			expectedPort = "443"
		}
		if parsed.Port() != expectedPort {
			return nil, errors.New("only the standard HTTP (80) and HTTPS (443) ports are allowed")
		}
	}
	return parsed, nil
}

func isPublicIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		for _, block := range []string{
			"0.0.0.0/8",
			"100.64.0.0/10",
			"192.0.0.0/24",
			"192.0.2.0/24",
			"192.88.99.0/24",
			"198.18.0.0/15",
			"198.51.100.0/24",
			"203.0.113.0/24",
			"240.0.0.0/4",
		} {
			_, network, _ := net.ParseCIDR(block)
			if network.Contains(ip4) {
				return false
			}
		}
	} else {
		_, globalIPv6, _ := net.ParseCIDR("2000::/3")
		_, documentationIPv6, _ := net.ParseCIDR("2001:db8::/32")
		if !globalIPv6.Contains(ip) || documentationIPv6.Contains(ip) {
			return false
		}
	}
	return true
}

func fetchSnapshot(target *url.URL) (map[string]any, int, string, error) {
	resolver := &net.Resolver{}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 15 * time.Second}
	transport := &http.Transport{
		Proxy:                  nil,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 64 << 10,
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  5 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, fmt.Errorf("invalid destination address: %w", err)
			}
			ips, err := resolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("resolve target host: %w", err)
			}
			if len(ips) == 0 {
				return nil, errors.New("target hostname resolved to no addresses")
			}
			for _, candidate := range ips {
				if !isPublicIP(candidate.IP) {
					return nil, errors.New("target hostname resolves to a private, local, or reserved address")
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("redirect limit exceeded")
			}
			original := via[0].URL
			if !sameOrigin(original, req.URL) {
				return errors.New("cross-origin redirect blocked")
			}
			return nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, 0, "", fmt.Errorf("create HTTP request: %w", err)
	}
	request.Header.Set("User-Agent", "XploitScope/0.1 (passive security configuration check)")
	request.Header.Set("Accept", "text/html,application/json;q=0.9,*/*;q=0.1")
	request.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, "", fmt.Errorf("request failed: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxScanBody+1))
	if err != nil {
		return nil, 0, "", fmt.Errorf("read HTTP response: %w", err)
	}
	if len(body) > maxScanBody {
		body = body[:maxScanBody]
	}
	headers := make(map[string]any, len(response.Header))
	for key, values := range response.Header {
		if strings.EqualFold(key, "Set-Cookie") {
			headers[key] = values
		} else if len(values) == 1 {
			headers[key] = values[0]
		} else {
			headers[key] = values
		}
	}

	responseURL := *response.Request.URL
	responseURL.RawQuery = ""
	responseURL.ForceQuery = false
	responseURL.Fragment = ""
	observation := map[string]any{
		"url":         responseURL.String(),
		"status_code": response.StatusCode,
		"headers":     headers,
		"body":        string(body),
	}
	tlsVersion := ""
	if response.TLS != nil {
		tlsVersion = tlsVersionName(response.TLS.Version)
	}
	observation["tls_version"] = tlsVersion
	return observation, response.StatusCode, tlsVersion, nil
}

func sameOrigin(left, right *url.URL) bool {
	return strings.EqualFold(left.Scheme, right.Scheme) &&
		strings.EqualFold(left.Hostname(), right.Hostname()) &&
		effectivePort(left) == effectivePort(right)
}

func effectivePort(value *url.URL) string {
	if port := value.Port(); port != "" {
		return port
	}
	if strings.EqualFold(value.Scheme, "https") {
		return "443"
	}
	return "80"
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%x)", version)
	}
}

func printScanReport(w io.Writer, report scanResult) error {
	var findings []struct {
		Module         string `json:"module"`
		Title          string `json:"title"`
		Severity       string `json:"severity"`
		Status         string `json:"status"`
		URL            string `json:"url"`
		Location       string `json:"location"`
		OWASP          string `json:"owasp"`
		Evidence       string `json:"evidence"`
		Recommendation string `json:"recommendation"`
	}
	if err := json.Unmarshal(report.Findings, &findings); err != nil {
		return fmt.Errorf("decode findings for display: %w", err)
	}
	color := func(code, text string) string {
		if os.Getenv("NO_COLOR") == "" {
			if file, ok := w.(*os.File); ok {
				if info, err := file.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
					return "\033[" + code + "m" + text + "\033[0m"
				}
			}
		}
		return text
	}
	fmt.Fprintf(w, "\n%s %s\n", color("1;36", "XploitScope passive assessment"), report.Target)
	fmt.Fprintf(w, "HTTP status: %d | TLS: %s | Findings: %d\n", report.StatusCode, displayOrNA(report.TLSVersion), len(findings))
	if len(findings) == 0 {
		fmt.Fprintln(w, color("32", "[+] No configured checks raised an indicator. This does not mean the site is vulnerability-free."))
	}
	for _, finding := range findings {
		severityColor := "37"
		switch strings.ToLower(finding.Severity) {
		case "critical":
			severityColor = "1;31"
		case "high":
			severityColor = "31"
		case "medium":
			severityColor = "33"
		case "low":
			severityColor = "36"
		}
		fmt.Fprintf(w, "\n%s [%s] %s (%s)\n", color(severityColor, "["+strings.ToUpper(finding.Severity)+"]"), finding.Module, finding.Title, finding.Status)
		if finding.URL != "" {
			fmt.Fprintf(w, "  URL: %s\n", finding.URL)
		}
		if finding.Location != "" {
			fmt.Fprintf(w, "  Location: %s\n", finding.Location)
		}
		if finding.OWASP != "" {
			fmt.Fprintf(w, "  OWASP: %s\n", finding.OWASP)
		}
		fmt.Fprintf(w, "  Evidence: %s\n  Recommendation: %s\n", finding.Evidence, finding.Recommendation)
	}
	fmt.Fprintln(w, "\nScope: one GET request; no crawling, login, payloads, or exploit validation.")
	fmt.Fprintln(w, "OWASP Top 10 2025 coverage is partial; see JSON report for category details.")
	fmt.Fprintln(w, "Review the JSON report for category details and limitations.")
	return nil
}

func displayOrNA(value string) string {
	if value == "" {
		return "not applicable"
	}
	return value
}

func isTerminal(file *os.File) bool {
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
