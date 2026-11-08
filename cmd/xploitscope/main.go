package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

var version = "dev"

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
		if len(args) != 1 {
			return errors.New("modules does not accept options or arguments")
		}
		return runModuleList(stdout)
	case "analyze":
		return runAnalyze(args[1:], stdout, stderr)
	case "scan":
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
  modules               List available passive checks
  analyze --input FILE  Analyze a local snapshot (all checks by default)
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
  xploitscope analyze --input capture.json
  xploitscope scan --url https://your-authorized-site.example --authorized
  xploitscope analyze --input capture.json --module sqli --format json`)
}
