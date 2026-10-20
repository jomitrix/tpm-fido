package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// ensureSystemdUserService checks if a systemd user service for tpm-fido exists
// and is enabled. If not, it automatically generates and enables it on first run
// so any user downloading or compiling the repository gets seamless autostart.
func ensureSystemdUserService() {
	// Only applicable on Linux systems with systemd user session running
	if _, err := exec.LookPath("systemctl"); err != nil {
		return
	}

	// Quick check if systemd user manager is responsive
	cmd := exec.Command("systemctl", "--user", "is-system-running")
	if out, err := cmd.CombinedOutput(); err != nil && !bytes.Contains(out, []byte("running")) && !bytes.Contains(out, []byte("degraded")) {
		// systemd --user is not active in this session
		return
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return
	}

	userServicePath := filepath.Join(home, ".config", "systemd", "user", "tpm-fido.service")
	systemLevelService := "/usr/lib/systemd/user/tpm-fido.service"

	userServiceExists := false
	if _, err := os.Stat(userServicePath); err == nil {
		userServiceExists = true
	}

	systemLevelExists := false
	if _, err := os.Stat(systemLevelService); err == nil {
		systemLevelExists = true
	}

	// 1. If no service unit exists anywhere, create one in ~/.config/systemd/user/
	if !userServiceExists && !systemLevelExists {
		binPath, err := os.Executable()
		if err != nil {
			if looked, err := exec.LookPath("tpm-fido"); err == nil {
				binPath = looked
			} else {
				binPath = filepath.Join(home, ".local", "bin", "tpm-fido")
			}
		} else {
			// Resolve any symlinks to find the real binary path
			if realPath, err := filepath.EvalSymlinks(binPath); err == nil {
				binPath = realPath
			}
		}

		serviceContent := fmt.Sprintf(`[Unit]
Description=TPM 2.0 FIDO2/WebAuthn Authenticator Daemon (Hardened)
After=graphical-session.target default.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=2
Environment=PATH=%%h/.local/bin:/usr/local/bin:/usr/bin
Environment=GDK_BACKEND=wayland,x11
Environment=TMPDIR=%%t

# --- Sandboxing & Restrizioni di Sicurezza ---
# Isola /tmp e /var/tmp in un namespace privato
PrivateTmp=true

# Protegge il filesystem di sistema (/usr, /boot, /etc) e l'intera $HOME in sola lettura
ProtectSystem=full
ProtectHome=read-only

# Rende scrivibili solo il runtime directory (socket IPC/D-Bus/Wayland) e la cartella credenziali
ReadWritePaths=%%t %%h/.config/tpm-fido

# Limita l'accesso hardware esclusivamente al TPM e a UHID
DevicePolicy=closed
DeviceAllow=/dev/tpmrm0 rw
DeviceAllow=/dev/uhid rw

# Protegge i parametri del kernel e i cgroups
ProtectKernelTunables=true
ProtectControlGroups=true

# Restringe i socket a quelli locali offline e netlink per PAM audit (nessun accesso a internet/rete esterna)
RestrictAddressFamilies=AF_UNIX AF_NETLINK

[Install]
WantedBy=graphical-session.target default.target
`, binPath)

		serviceDir := filepath.Dir(userServicePath)
		if err := os.MkdirAll(serviceDir, 0o755); err != nil {
			log.Printf("failed to create systemd user dir %s: %v", serviceDir, err)
			return
		}

		if err := os.WriteFile(userServicePath, []byte(serviceContent), 0o644); err != nil {
			log.Printf("failed to write user systemd unit %s: %v", userServicePath, err)
			return
		}

		log.Printf("Created systemd user autostart service: %s", userServicePath)
		_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
	} else if userServiceExists {
		// If existing user unit needs upgrading to graphical-session.target or hardening sandbox, upgrade it
		data, err := os.ReadFile(userServicePath)
		if err == nil && (!strings.Contains(string(data), "WantedBy=graphical-session.target") || !strings.Contains(string(data), "Environment=PATH=") || strings.Contains(string(data), "PartOf=graphical-session.target") || !strings.Contains(string(data), "TMPDIR=") || !strings.Contains(string(data), "ProtectSystem=full")) {
			binPath, err := os.Executable()
			if err != nil {
				binPath = filepath.Join(home, ".local", "bin", "tpm-fido")
			}
			newContent := fmt.Sprintf(`[Unit]
Description=TPM 2.0 FIDO2/WebAuthn Authenticator Daemon (Hardened)
After=graphical-session.target default.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=2
Environment=PATH=%%h/.local/bin:/usr/local/bin:/usr/bin
Environment=GDK_BACKEND=wayland,x11
Environment=TMPDIR=%%t

# --- Sandboxing & Restrizioni di Sicurezza ---
# Isola /tmp e /var/tmp in un namespace privato
PrivateTmp=true

# Protegge il filesystem di sistema (/usr, /boot, /etc) e l'intera $HOME in sola lettura
ProtectSystem=full
ProtectHome=read-only

# Rende scrivibili solo il runtime directory (socket IPC/D-Bus/Wayland) e la cartella credenziali
ReadWritePaths=%%t %%h/.config/tpm-fido

# Limita l'accesso hardware esclusivamente al TPM e a UHID
DevicePolicy=closed
DeviceAllow=/dev/tpmrm0 rw
DeviceAllow=/dev/uhid rw

# Protegge i parametri del kernel e i cgroups
ProtectKernelTunables=true
ProtectControlGroups=true

# Restringe i socket a quelli locali offline e netlink per PAM audit (nessun accesso a internet/rete esterna)
RestrictAddressFamilies=AF_UNIX AF_NETLINK

[Install]
WantedBy=graphical-session.target default.target
`, binPath)
			if err := os.WriteFile(userServicePath, []byte(newContent), 0o644); err == nil {
				_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
			}
		}
	}

	// 2. Ensure the service is enabled for autostart
	checkEnabled := exec.Command("systemctl", "--user", "is-enabled", "tpm-fido.service")
	out, err := checkEnabled.CombinedOutput()
	status := strings.TrimSpace(string(out))
	if err != nil || status != "enabled" {
		enableCmd := exec.Command("systemctl", "--user", "enable", "tpm-fido.service")
		if err := enableCmd.Run(); err != nil {
			log.Printf("warning: could not automatically enable systemd user service: %v", err)
		} else {
			log.Printf("Enabled systemd user service tpm-fido.service for autostart")
		}
	}
}

// acquireSingleInstanceLock ensures only one instance of tpm-fido runs per user session,
// preventing conflicts if a user manually runs tpm-fido while the systemd service is active.
func acquireSingleInstanceLock() (*os.File, error) {
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		runtimeDir = os.TempDir()
	}
	lockPath := filepath.Join(runtimeDir, "tpm-fido.lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("already running")
	}
	return f, nil
}

