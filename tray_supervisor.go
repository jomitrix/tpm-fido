package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// findTrayBinary locates the tpm-fido-tray executable across standard system and user locations.
func findTrayBinary() string {
	if p := os.Getenv("TPM_FIDO_TRAY"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		p := filepath.Join(dir, "tpm-fido-tray")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	if home, err := os.UserHomeDir(); err == nil {
		p := filepath.Join(home, ".local", "bin", "tpm-fido-tray")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	for _, p := range []string{"/usr/local/bin/tpm-fido-tray", "/usr/bin/tpm-fido-tray"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	if p, err := exec.LookPath("tpm-fido-tray"); err == nil {
		return p
	}

	return ""
}

// buildDesktopEnv returns the current environment enriched with desktop/display variables
// dynamically detected if missing (especially when run from systemd --user at boot).
func buildDesktopEnv() []string {
	envMap := make(map[string]string)
	for _, kv := range os.Environ() {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}

	uid := os.Getuid()
	runtimeDir := envMap["XDG_RUNTIME_DIR"]
	if runtimeDir == "" {
		runtimeDir = fmt.Sprintf("/run/user/%d", uid)
		envMap["XDG_RUNTIME_DIR"] = runtimeDir
	}

	// Dynamic detection of DBus session socket
	if envMap["DBUS_SESSION_BUS_ADDRESS"] == "" {
		busPath := filepath.Join(runtimeDir, "bus")
		if _, err := os.Stat(busPath); err == nil {
			envMap["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=" + busPath
		}
	}

	// Dynamic detection of active Wayland socket
	if envMap["WAYLAND_DISPLAY"] == "" {
		if entries, err := os.ReadDir(runtimeDir); err == nil {
			var waylandSockets []string
			for _, entry := range entries {
				name := entry.Name()
				if strings.HasPrefix(name, "wayland-") && !strings.HasSuffix(name, ".lock") {
					waylandSockets = append(waylandSockets, name)
				}
			}
			if len(waylandSockets) > 0 {
				sort.Strings(waylandSockets)
				envMap["WAYLAND_DISPLAY"] = waylandSockets[len(waylandSockets)-1]
			}
		}
	}

	// Dynamic detection of X11 DISPLAY
	if envMap["DISPLAY"] == "" {
		if xEntries, err := os.ReadDir("/tmp/.X11-unix"); err == nil && len(xEntries) > 0 {
			for _, xEntry := range xEntries {
				if strings.HasPrefix(xEntry.Name(), "X") {
					dispNum := strings.TrimPrefix(xEntry.Name(), "X")
					envMap["DISPLAY"] = ":" + dispNum
					break
				}
			}
		}
		if envMap["DISPLAY"] == "" && envMap["WAYLAND_DISPLAY"] == "" {
			envMap["DISPLAY"] = ":0"
		}
	}

	if envMap["GDK_BACKEND"] == "" {
		envMap["GDK_BACKEND"] = "wayland,x11"
	}

	var res []string
	for k, v := range envMap {
		res = append(res, k+"="+v)
	}
	return res
}

// launchTraySupervisor manages the lifecycle of the system tray companion applet.
// If the desktop session or tray watcher isn't ready at startup (e.g. at boot time),
// it automatically retries and keeps the tray process alive.
func launchTraySupervisor(ctlSocketReady <-chan struct{}) {
	<-ctlSocketReady

	for {
		trayPath := findTrayBinary()
		if trayPath == "" {
			log.Printf("[tray] tpm-fido-tray not found in standard paths; will retry in 5s")
			time.Sleep(5 * time.Second)
			continue
		}

		env := buildDesktopEnv()
		cmd := exec.Command(trayPath)
		cmd.Env = env
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Start(); err != nil {
			log.Printf("[tray] failed to start %s: %v; retrying in 3s...", trayPath, err)
			time.Sleep(3 * time.Second)
			continue
		}

		pid := cmd.Process.Pid
		log.Printf("[tray] started tpm-fido-tray (PID %d)", pid)

		// Wait for the tray process to exit (e.g., desktop session crash/reload)
		err := cmd.Wait()
		log.Printf("[tray] tpm-fido-tray (PID %d) exited (%v); restarting in 3s...", pid, err)
		time.Sleep(3 * time.Second)
	}
}
