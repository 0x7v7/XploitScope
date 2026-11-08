package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

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
