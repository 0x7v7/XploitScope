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
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var version = "dev"

const protocolVersion = 1

type request struct {
	Version int    `json:"version"`
	ID      string `json:"id"`
	Type    string `json:"type"`
}

type response struct {
	Version int             `json:"version"`
	ID      string          `json:"id"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
	Error   string          `json:"error"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "xploitscope:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printBanner(stdout)
		printUsage(stdout)
		return nil
	}

	switch args[0] {
	case "help", "-h", "--help":
		printBanner(stdout)
		printUsage(stdout)
		return nil
	case "version", "--version", "-version":
		printBanner(stdout)
		fmt.Fprintf(stdout, "XploitScope %s\n", version)
		return nil
	case "doctor":
		printBanner(stdout)
		flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
		flags.SetOutput(stderr)
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return fmt.Errorf("doctor does not accept positional arguments")
		}
		return runDoctor(stdout)
	case "modules":
		printBanner(stderr)
		if len(args) != 1 {
			return errors.New("modules does not accept options or arguments")
		}
		return runWorkerCommand("list_modules", nil, stdout)
	case "analyze":
		printBanner(stderr)
		return runAnalyze(args[1:], stdout, stderr)
	case "scan":
		printBanner(stderr)
		return runScan(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown command %q (run 'xploitscope help')", args[0])
	}
}

func printBanner(w io.Writer) {
	banner := ` __  __     _     _ _   ___
 \ \/ /_ __| |___(_) |_/ __| __ ___ _ __  ___
  >  <| '_ \ / _ \ |  _\__ \/ _/ _ \ '_ \/ -_)
 /_/\_\ .__/_\___/_|\__|___/\__\___/ .__/\___|
      |_|                          |_|

       Developer : Hex
`
	if terminal, ok := w.(*os.File); ok && os.Getenv("NO_COLOR") == "" {
		if info, err := terminal.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
			fmt.Fprint(w, "\033[36m", banner, "\033[0m")
			return
		}
	}
	fmt.Fprint(w, banner)
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `XploitScope - Web Security Assessment Framework

Usage:
  xploitscope <command> [options]

Commands:
  doctor                Check Go CLI and Python worker availability
  modules               List offline analysis modules
  analyze --input FILE  Analyze a local HTTP snapshot JSON file
  scan --url URL        Passively inspect one authorized public URL
  version               Print version information
  help                  Show this help

Scan sends one GET request (up to two same-origin redirects), without payloads,
crawling, or authentication. It requires --authorized. Only HTTP/TLS
configuration issues can be assessed this way; it does not confirm OWASP Top 10.
Analyze never sends network requests. It only processes the supplied local file.

Examples:
  xploitscope doctor
  xploitscope modules
  xploitscope scan --url https://your-authorized-site.example --authorized
  xploitscope analyze --input response.json --output findings.json`)
}

const maxScanBody = 1 << 20

var hostnamePattern = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.?$`)

type scanResult struct {
	Target        string             `json:"target"`
	ScannedAt     time.Time          `json:"scanned_at"`
	StatusCode    int                `json:"status_code"`
	TLSVersion    string             `json:"tls_version,omitempty"`
	Findings      json.RawMessage    `json:"findings"`
	OWASPCoverage []categoryCoverage `json:"owasp_top_10_2021_coverage"`
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
	"OWASP A01, A04, A06, A07, A08, A09, and A10 are not assessed by this request.",
	"OWASP A02 is only represented by the negotiated TLS version; A03 is not tested with payloads.",
	"OWASP A05 coverage is limited to response headers and cookie attributes.",
	"No login, crawling, form submission, injection payloads, or exploit validation is performed.",
}

var owaspCoverage = []categoryCoverage{
	{"A01:2021", "Broken Access Control", "not_assessed", "Requires authenticated role and authorization-boundary testing."},
	{"A02:2021", "Cryptographic Failures", "partial", "Reports negotiated TLS version only; does not audit all cipher or data-storage practices."},
	{"A03:2021", "Injection", "partial", "May flag database error text; does not send injection probes or confirm exploitability."},
	{"A04:2021", "Insecure Design", "not_assessed", "Requires application context and design review."},
	{"A05:2021", "Security Misconfiguration", "partial", "Checks selected response headers, cookie attributes, and deprecated TLS versions."},
	{"A06:2021", "Vulnerable and Outdated Components", "not_assessed", "Does not crawl assets or identify component versions."},
	{"A07:2021", "Identification and Authentication Failures", "not_assessed", "Does not log in or test authentication/session flows."},
	{"A08:2021", "Software and Data Integrity Failures", "not_assessed", "Requires build, update, and integrity-control review."},
	{"A09:2021", "Security Logging and Monitoring Failures", "not_assessed", "Cannot assess logging behavior from a public response."},
	{"A10:2021", "Server-Side Request Forgery", "not_assessed", "No URL-fetch behavior or SSRF probes are tested."},
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
	// Query strings can contain credentials or personal data; never include them in reports.
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
		fmt.Fprintf(w, "  Location: %s\n  Evidence: %s\n  Recommendation: %s\n", finding.URL, finding.Evidence, finding.Recommendation)
	}
	fmt.Fprintln(w, "\nScope: one GET request; no crawling, login, payloads, or exploit validation.")
	fmt.Fprintln(w, "OWASP Top 10 2021: A02/A03/A05 partial; all other categories not assessed.")
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

func runDoctor(w io.Writer) error {
	python, err := findPython()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "[ok] Python runtime: %s\n", python)

	worker, err := findWorker()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "[ok] Python worker: %s\n", worker)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, python, worker)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("start Python worker: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("read Python worker output: %w", err)
	}
	var workerErrors strings.Builder
	cmd.Stderr = &workerErrors
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start Python worker: %w", err)
	}

	requestLine, err := json.Marshal(request{Version: protocolVersion, ID: "doctor", Type: "ping"})
	if err != nil {
		return fmt.Errorf("encode worker health request: %w", err)
	}
	if _, err := fmt.Fprintf(stdin, "%s\n", requestLine); err != nil {
		_ = cmd.Process.Kill()
		return fmt.Errorf("send worker health request: %w", err)
	}
	_ = stdin.Close()

	line, err := bufio.NewReader(io.LimitReader(stdout, 64*1024)).ReadBytes('\n')
	if err != nil {
		_ = cmd.Process.Kill()
		return fmt.Errorf("read worker health response: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		return workerFailure(err, workerErrors.String())
	}

	var reply response
	if err := json.Unmarshal(line, &reply); err != nil {
		return fmt.Errorf("invalid worker health response: %w", err)
	}
	if reply.Version != protocolVersion || reply.ID != "doctor" {
		return errors.New("worker returned an unexpected health response")
	}
	if reply.Error != "" {
		return fmt.Errorf("worker health check failed: %s", reply.Error)
	}
	if reply.Type != "pong" {
		return errors.New("worker returned an unexpected health response")
	}
	fmt.Fprintln(w, "[ok] Python worker protocol: ready")
	return nil
}

func runAnalyze(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("analyze", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: xploitscope analyze --input FILE [--output FILE] [--module NAME[,NAME...]]")
		flags.PrintDefaults()
	}
	input := flags.String("input", "", "local JSON file containing HTTP observations")
	output := flags.String("output", "", "write JSON findings to this file (default: stdout)")
	modules := flags.String("module", "all", "comma-separated passive modules to run (default: all)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("analyze does not accept positional arguments")
	}
	if *input == "" {
		return errors.New("analyze requires --input FILE")
	}
	file, err := os.Open(*input)
	if err != nil {
		return fmt.Errorf("open input file: %w", err)
	}
	defer file.Close()

	const maxInputSize = 10 << 20
	raw, err := io.ReadAll(io.LimitReader(file, maxInputSize+1))
	if err != nil {
		return fmt.Errorf("read input file: %w", err)
	}
	if len(raw) > maxInputSize {
		return fmt.Errorf("input file exceeds the 10 MiB limit")
	}
	if !json.Valid(raw) {
		return errors.New("input file must contain valid JSON")
	}
	var inputData map[string]json.RawMessage
	if err := json.Unmarshal(raw, &inputData); err != nil || inputData == nil {
		return errors.New("input file must contain a JSON object")
	}
	if strings.TrimSpace(*modules) != "all" {
		selected := strings.Split(*modules, ",")
		for i, name := range selected {
			selected[i] = strings.TrimSpace(name)
			if selected[i] == "" {
				return errors.New("--module contains an empty module name")
			}
		}
		moduleJSON, err := json.Marshal(selected)
		if err != nil {
			return fmt.Errorf("encode selected modules: %w", err)
		}
		inputData["modules"] = moduleJSON
	}
	payload, err := json.Marshal(inputData)
	if err != nil {
		return fmt.Errorf("encode analysis input: %w", err)
	}

	var result bytes.Buffer
	if err := runWorkerCommand("analyze", payload, &result); err != nil {
		return err
	}
	if *output == "" {
		_, err = stdout.Write(result.Bytes())
		return err
	}
	if err := os.WriteFile(*output, result.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write output file: %w", err)
	}
	fmt.Fprintf(stdout, "Analysis written to %s\n", *output)
	return nil
}

func runWorkerCommand(kind string, payload json.RawMessage, output io.Writer) error {
	python, err := findPython()
	if err != nil {
		return err
	}
	worker, err := findWorker()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, python, worker)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("start Python worker: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("read Python worker output: %w", err)
	}
	var workerErrors strings.Builder
	cmd.Stderr = &workerErrors
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start Python worker: %w", err)
	}

	requestLine, err := json.Marshal(struct {
		Version int             `json:"version"`
		ID      string          `json:"id"`
		Type    string          `json:"type"`
		Payload json.RawMessage `json:"payload,omitempty"`
	}{protocolVersion, "cli", kind, payload})
	if err != nil {
		_ = cmd.Process.Kill()
		return fmt.Errorf("encode worker request: %w", err)
	}
	if _, err := fmt.Fprintf(stdin, "%s\n", requestLine); err != nil {
		_ = cmd.Process.Kill()
		return fmt.Errorf("send worker request: %w", err)
	}
	_ = stdin.Close()

	line, err := bufio.NewReader(io.LimitReader(stdout, 16<<20)).ReadBytes('\n')
	if err != nil {
		_ = cmd.Process.Kill()
		return fmt.Errorf("read worker response: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		return workerFailure(err, workerErrors.String())
	}
	var reply response
	if err := json.Unmarshal(line, &reply); err != nil {
		return fmt.Errorf("invalid worker response: %w", err)
	}
	if reply.Version != protocolVersion || reply.ID != "cli" {
		return errors.New("worker returned an unexpected response")
	}
	if reply.Type == "error" || reply.Error != "" {
		return fmt.Errorf("worker request failed: %s", reply.Error)
	}
	if reply.Type != "result" {
		return errors.New("worker returned an unexpected response type")
	}
	_, err = output.Write(append(reply.Payload, '\n'))
	return err
}

func workerFailure(err error, details string) error {
	details = strings.TrimSpace(details)
	if details == "" {
		return fmt.Errorf("Python worker exited unsuccessfully: %w", err)
	}
	return fmt.Errorf("Python worker exited unsuccessfully: %w: %s", err, details)
}

func findPython() (string, error) {
	candidates := []string{"python3", "python"}
	for _, candidate := range candidates {
		path, err := exec.LookPath(candidate)
		if err != nil {
			continue
		}
		check := exec.Command(path, "-c", "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)")
		if err := check.Run(); err == nil {
			return path, nil
		}
	}
	return "", errors.New("Python 3.10 or newer was not found on PATH")
}

func findWorker() (string, error) {
	if configured := os.Getenv("XPLOITSCOPE_WORKER"); configured != "" {
		if fileExists(configured) {
			return configured, nil
		}
		return "", fmt.Errorf("configured Python worker does not exist: %s", configured)
	}

	candidates := make([]string, 0, 5)
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, "python", "xploitscope_detector", "worker.py"))
	}
	if executable, err := os.Executable(); err == nil {
		executableDir := filepath.Dir(executable)
		candidates = append(candidates,
			filepath.Join(executableDir, "..", "share", "xploitscope", "xploitscope_detector", "worker.py"),
			filepath.Join(executableDir, "worker.py"),
		)
	}
	if dataDir := os.Getenv("XDG_DATA_HOME"); dataDir != "" {
		candidates = append(candidates, filepath.Join(dataDir, "xploitscope", "xploitscope_detector", "worker.py"))
	} else if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".local", "share", "xploitscope", "xploitscope_detector", "worker.py"))
	}

	for _, candidate := range candidates {
		if fileExists(candidate) {
			return candidate, nil
		}
	}
	return "", errors.New("Python worker not found; set XPLOITSCOPE_WORKER or run the Linux installer")
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
