# tpm-fido

`tpm-fido` is a local hardware-bound FIDO2/WebAuthn authenticator for Linux (Wayland & X11) that protects Passkey credentials using your machine's **TPM 2.0**. It uses Linux's `/dev/uhid` to emulate a virtual USB HID token so that modern browsers (Chromium, Chrome, Firefox, Brave) detect it natively.

User verification is fully hardware-bound and unified into a modern **GTK4 / Libadwaita** prompt that authenticates against the Linux **PAM** system password stack — providing an experience similar to Windows Hello, without secondary popups or custom PINs.

---

## Features

- **TPM 2.0 Hardware Security & PCR Binding**: Private keys (P-256) are generated and sealed directly under the TPM 2.0 Owner Hierarchy (`/dev/tpmrm0`). Keys are cryptographically sealed to system PCR registers (default PCR 0, 2, 7 for firmware, option ROMs, and Secure Boot state). If an attacker tampers with the firmware or boots from a live USB, the TPM hardware refuses authorization.
- **CTAP 2.1 & Passkeys**: Implements discoverable/resident credentials (`authenticatorMakeCredential`, `authenticatorGetAssertion`, `authenticatorCredentialManagement`), compatible with WebAuthn.io, GitHub, Google, Microsoft, and others.
- **Unified PAM Verification with Privilege Separation**: A modern **GTK4 / Libadwaita** modal prompts for the system password and authenticates through a dedicated memory-scrubbing C helper (`tpm-fido-pam-helper`) and PAM configuration (`/etc/pam.d/tpm-fido`), isolating secrets from the Python interpreter heap.
- **Wayland Input Grab & Layer-Shell**: Modal dialog supports `gtk4-layer-shell` (Wayland `OVERLAY` level with `EXCLUSIVE` keyboard grab) and anti-focus-stealing controllers, preventing background apps from intercepting keystrokes.
- **Systemd User Sandboxing**: Isolated user daemon (`ProtectSystem=full`, `ProtectHome=read-only`, `PrivateTmp=true`, `DevicePolicy=closed`, network access blocked offline).
- **GTK4 / Libadwaita Passkey Manager**: Modern management UI (`tpm-fido-manager`) to inspect registered relying parties (websites), review credential IDs and usage sign counts, and delete hardware passkeys.
- **System Tray Companion (`tpm-fido-tray`)**: Lightweight background tray applet (supporting Waybar, KDE Plasma, GNOME via AppIndicator) with auto-reconnect supervisor.
- **Systemd User Service with Auto-Setup**: Automatic creation, installation, and enabling of `tpm-fido.service` upon first execution.

---

## Arch Linux / EndeavourOS Installation (PKGBUILD)

You can build and install the complete package natively using `makepkg`:

```bash
git clone https://github.com/idkreally001/tpm-fido
cd tpm-fido
makepkg -si
```

This installs:
- `/usr/bin/tpm-fido` (Daemon with PCR sealing)
- `/usr/bin/tpm-fido-manager` (GTK4 Passkey Manager)
- `/usr/bin/tpm-fido-prompt` (GTK4 modal prompt)
- `/usr/bin/tpm-fido-pam-helper` (Privilege-separated C PAM verifier)
- `/usr/bin/tpm-fido-tray` (System tray applet)
- `/etc/pam.d/tpm-fido` (Dedicated PAM configuration)
- `/usr/lib/systemd/user/tpm-fido.service` (Hardened systemd user service)
- `/usr/lib/udev/rules.d/70-tpm-fido-uhid.rules` (Udev rule for `/dev/uhid` access)
- Desktop entries and high-resolution application icons

---

## Manual Installation (Makefile)

### Prerequisites

* **Go** (1.21+)
* **TPM 2.0 tools & headers**: `tpm2-tss`
* **Python 3**: with `python-pam` and `python-gobject`
* **GTK4 & Libadwaita**: `gtk4`, `libadwaita`
* **Tray dependency** (optional): `libayatana-appindicator`

### Building & Installing to `~/.local`

```bash
git clone https://github.com/idkreally001/tpm-fido
cd tpm-fido
make install
```

Make sure `~/.local/bin` is in your `$PATH`.

---

## Permissions & System Configuration

1. **User Groups**:
   Your user must belong to the `tss` group (for `/dev/tpmrm0`) and the `uhid` group (for `/dev/uhid`):
   ```bash
   sudo usermod -aG tss,uhid $USER
   ```

2. **Kernel Module `uhid`**:
   Load the module and ensure it loads on boot:
   ```bash
   sudo modprobe uhid
   echo "uhid" | sudo tee /etc/modules-load.d/uhid.conf
   ```

3. **Udev Rule**:
   If not using the Arch package, install the udev rule manually:
   ```bash
   sudo cp packaging/70-tpm-fido-uhid.rules /etc/udev/rules.d/
   sudo udevadm control --reload-rules && sudo udevadm trigger
   ```

---

## Running & Managing the Service

The daemon is managed as a systemd user service (`tpm-fido.service`):

```bash
# Check status
systemctl --user status tpm-fido.service

# View live logs
journalctl --user -u tpm-fido.service -f

# Start / Restart
systemctl --user restart tpm-fido.service
```

When the daemon starts, it automatically supervisors the companion tray applet and listens on the local control socket (`$XDG_RUNTIME_DIR/tpm-fido.sock`).

---

## Passkey Manager

Launch the modern GTK4/Libadwaita manager anytime from your application menu or terminal:
```bash
tpm-fido-manager
```
From here you can view all websites for which hardware passkeys exist on your TPM, inspect usage statistics (`Sign Count`), and securely delete credentials.
