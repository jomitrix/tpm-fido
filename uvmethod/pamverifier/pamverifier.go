// Package pamverifier is the PAM-backed implementation of uvmethod.Verifier.
// It displays a modern GTK4 / Libadwaita dialog and authenticates the user
// against the Linux PAM stack using their system password.
package pamverifier

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/psanford/tpm-fido/uvmethod"
)

// Verifier verifies the user by executing the tpm-fido-prompt helper.
type Verifier struct {
	mu         sync.Mutex
	promptPath string
}

func New(promptPath string) *Verifier {
	return &Verifier{promptPath: promptPath}
}

func (v *Verifier) Name() string { return "pam" }

func (v *Verifier) findPrompt() (string, error) {
	if v.promptPath != "" {
		if _, err := os.Stat(v.promptPath); err == nil {
			return v.promptPath, nil
		}
	}

	if envPath := os.Getenv("TPM_FIDO_PROMPT"); envPath != "" {
		if _, err := os.Stat(envPath); err == nil {
			return envPath, nil
		}
	}

	if p, err := exec.LookPath("tpm-fido-prompt"); err == nil {
		return p, nil
	}

	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), "tpm-fido-prompt")
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
		p = filepath.Join(filepath.Dir(exe), "cmd", "tpm-fido-prompt", "tpm-fido-prompt.py")
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	if home, err := os.UserHomeDir(); err == nil {
		p := filepath.Join(home, ".local", "bin", "tpm-fido-prompt")
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	candidates := []string{
		"cmd/tpm-fido-prompt/tpm-fido-prompt.py",
		"tpm-fido-prompt.py",
		"tpm-fido-prompt",
		"/usr/local/bin/tpm-fido-prompt",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}

	return "", fmt.Errorf("tpm-fido-prompt not found")
}

func (v *Verifier) Verify(ctx context.Context, rpID, user, mode string) (uvmethod.Outcome, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	bin, err := v.findPrompt()
	if err != nil {
		log.Printf("pamverifier: prompt binary not found: %s", err)
		return uvmethod.Unavailable, err
	}

	var cmd *exec.Cmd
	if systemdRun, err := exec.LookPath("systemd-run"); err == nil {
		args := []string{"--user", "--wait", "--pipe"}
		if strings.HasSuffix(bin, ".py") {
			args = append(args, "python3", bin, rpID, user, mode)
		} else {
			args = append(args, bin, rpID, user, mode)
		}
		cmd = exec.CommandContext(ctx, systemdRun, args...)
	} else {
		if strings.HasSuffix(bin, ".py") {
			cmd = exec.CommandContext(ctx, "python3", bin, rpID, user, mode)
		} else {
			cmd = exec.CommandContext(ctx, bin, rpID, user, mode)
		}
	}
	cmd.Env = os.Environ()

	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return cmd.Process.Signal(syscall.SIGTERM)
		}
		return nil
	}

	err = cmd.Run()
	if ctx.Err() != nil {
		log.Printf("pamverifier: verification canceled: %s", ctx.Err())
		return uvmethod.Rejected, ctx.Err()
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code := exitErr.ExitCode()
			if code == 1 {
				log.Printf("pamverifier: user canceled prompt")
				return uvmethod.Rejected, nil
			}
			log.Printf("pamverifier: prompt exited with code %d: %s", code, exitErr)
			return uvmethod.Unavailable, fmt.Errorf("prompt exited with code %d", code)
		}
		log.Printf("pamverifier: failed to execute prompt: %s", err)
		return uvmethod.Unavailable, err
	}

	log.Printf("pamverifier: successfully verified user for site=%s user=%s mode=%s", rpID, user, mode)
	return uvmethod.Verified, nil
}
