package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

func runModuleList(w io.Writer) error {
	var raw bytes.Buffer
	if err := runWorkerCommand("list_modules", nil, &raw); err != nil {
		return err
	}
	var result struct {
		Modules []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Mode        string `json:"mode"`
		} `json:"modules"`
	}
	if err := json.Unmarshal(raw.Bytes(), &result); err != nil {
		return fmt.Errorf("parse module list: %w", err)
	}
	fmt.Fprintln(w, "Available checks (run `analyze` without --module to use all):")
	for _, module := range result.Modules {
		fmt.Fprintf(w, "  %-14s %-14s %s\n", module.Name, "["+module.Mode+"]", module.Description)
	}
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
	modules := flags.String("module", "all", "comma-separated modules (default: all; usually omit this)")
	format := flags.String("format", "text", "output format: text or json")
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
	if *format != "text" && *format != "json" {
		return errors.New("--format must be text or json")
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
	if *output != "" {
		if err := os.WriteFile(*output, result.Bytes(), 0o600); err != nil {
			return fmt.Errorf("write output file: %w", err)
		}
	}
	if *format == "json" {
		if _, err := stdout.Write(result.Bytes()); err != nil {
			return err
		}
	} else if err := printAnalysisReport(stdout, result.Bytes()); err != nil {
		return err
	}
	if *output != "" {
		fmt.Fprintf(stdout, "\nJSON report saved to %s\n", *output)
	}
	return nil
}

type displayFinding struct {
	Module         string `json:"module"`
	Title          string `json:"title"`
	Severity       string `json:"severity"`
	Confidence     int    `json:"confidence"`
	Status         string `json:"status"`
	URL            string `json:"url"`
	Location       string `json:"location"`
	OWASP          string `json:"owasp"`
	Evidence       string `json:"evidence"`
	Recommendation string `json:"recommendation"`
}

type analysisReport struct {
	Mode             string           `json:"analysis_mode"`
	ObservationCount int              `json:"observation_count"`
	Modules          []string         `json:"modules"`
	Findings         []displayFinding `json:"findings"`
	Notice           string           `json:"notice"`
}

func printAnalysisReport(w io.Writer, raw []byte) error {
	var report analysisReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return fmt.Errorf("parse analysis report: %w", err)
	}
	sort.SliceStable(report.Findings, func(i, j int) bool {
		left, right := severityRank(report.Findings[i].Severity), severityRank(report.Findings[j].Severity)
		if left != right {
			return left < right
		}
		return report.Findings[i].Confidence > report.Findings[j].Confidence
	})
	color := func(code, text string) string {
		if os.Getenv("NO_COLOR") == "" && isTerminalOutput(w) {
			return "\033[" + code + "m" + text + "\033[0m"
		}
		return text
	}
	fmt.Fprintln(w, color("1;36", "XploitScope | Passive Analysis"))
	fmt.Fprintf(w, "Observations: %d | Modules: %s\n", report.ObservationCount, strings.Join(report.Modules, ", "))
	fmt.Fprintln(w, strings.Repeat("-", 68))
	if len(report.Findings) == 0 {
		fmt.Fprintln(w, color("32", "No indicators found by the selected checks."))
		fmt.Fprintln(w, "This does not prove the application is free of vulnerabilities.")
	} else {
		counts := map[string]int{}
		for _, finding := range report.Findings {
			counts[strings.ToUpper(finding.Severity)]++
		}
		fmt.Fprintf(w, "Indicators: %d", len(report.Findings))
		for _, severity := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
			if counts[severity] > 0 {
				fmt.Fprintf(w, " | %s %d", severity, counts[severity])
			}
		}
		fmt.Fprint(w, "\n\n")
		for index, finding := range report.Findings {
			severity := strings.ToUpper(finding.Severity)
			code := "37"
			switch severity {
			case "CRITICAL":
				code = "1;31"
			case "HIGH":
				code = "31"
			case "MEDIUM":
				code = "33"
			case "LOW":
				code = "36"
			}
			fmt.Fprintf(w, "%s %02d. %s\n", color(code, "["+severity+"]"), index+1, finding.Title)
			fmt.Fprintf(w, "    Check:    %s", finding.Module)
			if finding.OWASP != "" {
				fmt.Fprintf(w, " | OWASP %s", finding.OWASP)
			}
			fmt.Fprintln(w)
			if finding.Confidence > 0 || finding.Status != "" {
				fmt.Fprintf(w, "    Triage:   %s", finding.Status)
				if finding.Confidence > 0 {
					fmt.Fprintf(w, " | confidence %d/10", finding.Confidence)
				}
				fmt.Fprintln(w)
			}
			if finding.URL != "" {
				fmt.Fprintf(w, "    URL:      %s\n", finding.URL)
			}
			if finding.Location != "" {
				fmt.Fprintf(w, "    Location: %s\n", finding.Location)
			}
			if finding.Evidence != "" {
				fmt.Fprintf(w, "    Evidence: %s\n", finding.Evidence)
			}
			if finding.Recommendation != "" {
				fmt.Fprintf(w, "    Fix:      %s\n", finding.Recommendation)
			}
			fmt.Fprintln(w)
		}
	}
	if report.Notice != "" {
		fmt.Fprintf(w, "Note: %s\n", report.Notice)
	}
	return nil
}

func severityRank(severity string) int {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	case "INFO":
		return 4
	default:
		return 5
	}
}

func isTerminalOutput(w io.Writer) bool {
	file, ok := w.(*os.File)
	return ok && isTerminal(file)
}
