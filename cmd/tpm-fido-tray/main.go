// Command tpm-fido-tray is a system tray icon for tpm-fido.
// It provides a tray menu with "Open Passkey Manager" and "Quit".
// Clicking "Open Passkey Manager" launches tpm-fido-manager (or
// tpm-fido-manager.py) without blocking the tray process.
package main

import (
	_ "embed"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/getlantern/systray"
)

//go:embed icon/icon.png
var iconPNG []byte

func main() {
	if os.Getenv("TMPDIR") == "" {
		if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
			_ = os.Setenv("TMPDIR", runtimeDir)
		}
	}
	systray.Run(onTrayReady, onTrayExit)
}

func onTrayReady() {
	systray.SetIcon(iconPNG)
	systray.SetTitle("tpm-fido")
	systray.SetTooltip("tpm-fido: hardware-bound passkey authenticator")

	openItem := systray.AddMenuItem("Open Passkey Manager", "Manage resident credentials")
	systray.AddSeparator()
	quitItem := systray.AddMenuItem("Quit", "Quit tpm-fido-tray")

	go func() {
		for {
			select {
			case <-openItem.ClickedCh:
				launchManager()
			case <-quitItem.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}

func onTrayExit() {}

// launchManager starts tpm-fido-manager as a detached child process.
// It searches the same candidates that pamverifier uses for the prompt.
func launchManager() {
	managerPath, err := findManager()
	if err != nil {
		log.Printf("tpm-fido-tray: manager not found: %s", err)
		return
	}

	var cmd *exec.Cmd
	if filepath.Ext(managerPath) == ".py" {
		cmd = exec.Command("python3", managerPath)
	} else {
		cmd = exec.Command(managerPath)
	}
	cmd.Env = os.Environ()
	// Detach so the tray keeps running even if manager is closed.
	if err := cmd.Start(); err != nil {
		log.Printf("tpm-fido-tray: failed to launch manager: %s", err)
		return
	}
	// Reap async so it doesn't become a zombie.
	go func() {
		time.Sleep(200 * time.Millisecond)
		cmd.Wait()
	}()
}

func findManager() (string, error) {
	if envPath := os.Getenv("TPM_FIDO_MANAGER"); envPath != "" {
		if _, err := os.Stat(envPath); err == nil {
			return envPath, nil
		}
	}

	if p, err := exec.LookPath("tpm-fido-manager"); err == nil {
		return p, nil
	}

	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		for _, name := range []string{"tpm-fido-manager", "cmd/tpm-fido-manager/tpm-fido-manager.py"} {
			p := filepath.Join(dir, name)
			if _, err := os.Stat(p); err == nil {
				return p, nil
			}
		}
	}

	if home, err := os.UserHomeDir(); err == nil {
		p := filepath.Join(home, ".local", "bin", "tpm-fido-manager")
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	return "", os.ErrNotExist
}
