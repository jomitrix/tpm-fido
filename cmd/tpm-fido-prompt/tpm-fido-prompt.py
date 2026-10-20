#!/usr/bin/env python3
import sys
import os
import signal
import pwd
import argparse

# 1. Setup Wayland/X11 and D-Bus environment
uid = os.getuid()
if "XDG_RUNTIME_DIR" not in os.environ:
    os.environ["XDG_RUNTIME_DIR"] = f"/run/user/{uid}"

if "DBUS_SESSION_BUS_ADDRESS" not in os.environ:
    os.environ["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path=/run/user/{uid}/bus"

runtime_dir = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{uid}")
current_wl = os.environ.get("WAYLAND_DISPLAY")
if not current_wl or not os.path.exists(os.path.join(runtime_dir, current_wl)):
    try:
        wayland_sockets = [
            f for f in os.listdir(runtime_dir)
            if f.startswith("wayland-") and not f.endswith(".lock")
        ]
        if wayland_sockets:
            os.environ["WAYLAND_DISPLAY"] = sorted(wayland_sockets)[-1]
        else:
            os.environ["WAYLAND_DISPLAY"] = "wayland-1"
    except Exception:
        os.environ["WAYLAND_DISPLAY"] = "wayland-1"

if "GDK_BACKEND" not in os.environ:
    os.environ["GDK_BACKEND"] = "wayland,x11"

import subprocess
import shutil
import pam

# Try dynamically loading gtk4-layer-shell for Wayland exclusive overlay & keyboard grab
HAS_LAYER_SHELL = False
try:
    import ctypes
    ctypes.CDLL("libgtk4-layer-shell.so")
    import gi
    gi.require_version('Gtk4LayerShell', '1.0')
    from gi.repository import Gtk4LayerShell
    HAS_LAYER_SHELL = True
except Exception:
    HAS_LAYER_SHELL = False

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, GLib, Gdk, Pango

# Parse arguments (supports positional and flags)
parser = argparse.ArgumentParser(description="TPM Fido Passkey User Verification Prompt")
parser.add_argument("site", nargs="?", default="", help="Relying party ID / website")
parser.add_argument("user", nargs="?", default="", help="User account name")
parser.add_argument("mode", nargs="?", default="authenticate", help="Operation mode: register | authenticate | manage")
parser.add_argument("--site", dest="flag_site", help="Relying party ID / website")
parser.add_argument("--user", dest="flag_user", help="User account name")
parser.add_argument("--mode", dest="flag_mode", help="Operation mode")

args, _ = parser.parse_known_args()

site = args.flag_site or args.site or "webauthn"
current_sys_user = os.getenv("USER") or pwd.getpwuid(uid).pw_name
user_account = args.flag_user or args.user or current_sys_user
mode = (args.flag_mode or args.mode or "authenticate").lower()

def find_pam_helper():
    env_helper = os.environ.get("TPM_FIDO_PAM_HELPER")
    if env_helper and os.path.exists(env_helper):
        return env_helper

    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(script_dir, "tpm-fido-pam-helper"),
        os.path.join(script_dir, "..", "tpm-fido-pam-helper"),
        os.path.join(os.path.expanduser("~/.local/bin"), "tpm-fido-pam-helper"),
        "/usr/lib/tpm-fido/tpm-fido-pam-helper",
        "/usr/local/bin/tpm-fido-pam-helper",
        "/usr/bin/tpm-fido-pam-helper",
    ]
    for c in candidates:
        if os.path.exists(c) and os.access(c, os.X_OK):
            return c

    which = shutil.which("tpm-fido-pam-helper")
    if which:
        return which

    return None

def verify_user_password(username, password):
    helper = find_pam_helper()
    if helper:
        try:
            proc = subprocess.Popen(
                [helper, username],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True
            )
            _, err = proc.communicate(input=password + "\n", timeout=10)
            return proc.returncode == 0
        except Exception as e:
            sys.stderr.write(f"tpm-fido-pam-helper error: {e}\n")

    # Fallback to python-pam if helper binary is not yet available
    try:
        p = pam.pam()
        for s in ("tpm-fido", "vlock", "sudo", "system-auth", "login"):
            if not os.path.exists(f"/etc/pam.d/{s}"):
                continue
            p.service = s
            if p.authenticate(username, password):
                return True
            break
    except Exception as e:
        sys.stderr.write(f"PAM error: {e}\n")

    return False

if not Gtk.init_check():
    sys.stderr.write("Error: Unable to connect to Wayland/X11 display manager.\n")
    sys.exit(2)

Adw.init()

is_register = "register" in mode
is_manage = "manage" in mode

if is_register:
    title_text = "Register a passkey"
    action_btn_text = "Register"
elif is_manage:
    title_text = "Manage passkeys"
    action_btn_text = "Unlock"
else:
    title_text = "Sign in with a passkey"
    action_btn_text = "Authenticate"

result_code = 1
loop = GLib.MainLoop()

def on_action(btn, entry, err_lbl, win, loop):
    global result_code
    password = entry.get_text()
    if not password:
        err_lbl.set_text("Please enter your password")
        return

    authenticated = verify_user_password(current_sys_user, password)
    if not authenticated and user_account and user_account != current_sys_user:
        authenticated = verify_user_password(user_account, password)

    password = None

    if authenticated:
        result_code = 0
        loop.quit()
        win.close()
    else:
        err_lbl.set_text("Incorrect password")
        entry.set_text("")
        entry.grab_focus()

def on_cancel(btn, win, loop):
    global result_code
    result_code = 1
    loop.quit()
    win.close()

css = b"""
window {
    background-color: #1c1c1e;
    color: #ffffff;
    border-radius: 14px;
}
.app-header {
    font-size: 11px;
    font-weight: 600;
    color: #9a9a9e;
}
.title-text {
    font-size: 21px;
    font-weight: 800;
    color: #ffffff;
}
.account-name {
    font-weight: 700;
    font-size: 15px;
    color: #ffffff;
}
.site-name {
    font-size: 12px;
    color: #9a9a9e;
}
.action-btn {
    background-color: #e66b0a;
    color: #ffffff;
    font-weight: 700;
    font-size: 14px;
    border-radius: 8px;
    min-height: 44px;
}
.action-btn:hover {
    background-color: #ff8522;
}
.cancel-btn {
    background-color: #2c2c2e;
    color: #ffffff;
    border: 1px solid #3a3a3c;
    border-radius: 8px;
    font-weight: 700;
    font-size: 14px;
    min-height: 44px;
}
.cancel-btn:hover {
    background-color: #3a3a3c;
}
entry {
    background-color: #121214;
    color: #ffffff;
    border: 1px solid #3a3a3c;
    border-radius: 8px;
    min-height: 40px;
    font-size: 14px;
    padding: 0 12px;
}
.error {
    color: #ff453a;
    font-size: 12px;
    font-weight: 600;
}
"""

css_provider = Gtk.CssProvider()
css_provider.load_from_data(css)
Gtk.StyleContext.add_provider_for_display(
    Gdk.Display.get_default(),
    css_provider,
    Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
)

win = Adw.Window(title="TPM Fido")
win.set_default_size(360, 310)
win.set_resizable(False)
win.set_modal(True)

# Wayland Layer-Shell Protection:
# When gtk4-layer-shell is available and supported by the compositor (e.g. KWin Wayland),
# promote the modal window to the OVERLAY layer with an EXCLUSIVE keyboard grab.
# This prevents background windows from stealing focus or intercepting keystrokes.
if HAS_LAYER_SHELL and Gtk4LayerShell.is_supported():
    try:
        Gtk4LayerShell.init_for_window(win)
        Gtk4LayerShell.set_layer(win, Gtk4LayerShell.Layer.OVERLAY)
        Gtk4LayerShell.set_keyboard_mode(win, Gtk4LayerShell.KeyboardMode.EXCLUSIVE)
        for edge in (Gtk4LayerShell.Edge.TOP, Gtk4LayerShell.Edge.BOTTOM,
                     Gtk4LayerShell.Edge.LEFT, Gtk4LayerShell.Edge.RIGHT):
            Gtk4LayerShell.set_anchor(win, edge, False)
    except Exception as e:
        sys.stderr.write(f"Layer shell warning: {e}\n")

main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
main_box.set_margin_top(16)
main_box.set_margin_bottom(16)
main_box.set_margin_start(20)
main_box.set_margin_end(20)

top_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
header_lbl = Gtk.Label(label="TPM Fido", halign=Gtk.Align.START)
header_lbl.add_css_class("app-header")
top_box.append(header_lbl)

title_lbl = Gtk.Label(label=title_text, halign=Gtk.Align.START)
title_lbl.add_css_class("title-text")
top_box.append(title_lbl)
main_box.append(top_box)

center_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
center_box.set_valign(Gtk.Align.CENTER)
center_box.set_vexpand(True)

acc_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
icon = Gtk.Image.new_from_icon_name("dialog-password-symbolic")
icon.set_pixel_size(28)
acc_box.append(icon)

text_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
acc_lbl = Gtk.Label(label=user_account, halign=Gtk.Align.START)
acc_lbl.add_css_class("account-name")
acc_lbl.set_ellipsize(Pango.EllipsizeMode.END)
acc_lbl.set_max_width_chars(28)

site_lbl = Gtk.Label(label=f"Passkey for {site}", halign=Gtk.Align.START)
site_lbl.add_css_class("site-name")
site_lbl.set_ellipsize(Pango.EllipsizeMode.END)
site_lbl.set_max_width_chars(28)

text_box.append(acc_lbl)
text_box.append(site_lbl)
acc_box.append(text_box)
center_box.append(acc_box)

entry = Gtk.PasswordEntry()
entry.set_property("placeholder-text", "Enter your password...")
entry.set_show_peek_icon(True)
center_box.append(entry)

err_lbl = Gtk.Label(label="", halign=Gtk.Align.CENTER)
err_lbl.add_css_class("error")
center_box.append(err_lbl)

main_box.append(center_box)

btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
btn_box.set_valign(Gtk.Align.END)
btn_box.set_homogeneous(True)

action_btn = Gtk.Button(label=action_btn_text)
action_btn.add_css_class("action-btn")
action_btn.connect("clicked", on_action, entry, err_lbl, win, loop)
entry.connect("activate", lambda e: on_action(None, entry, err_lbl, win, loop))

cancel_btn = Gtk.Button(label="Cancel")
cancel_btn.add_css_class("cancel-btn")
cancel_btn.connect("clicked", on_cancel, win, loop)

btn_box.append(action_btn)
btn_box.append(cancel_btn)
main_box.append(btn_box)

win.set_content(main_box)

# Close and Escape handlers — only trigger a real cancel if we haven't
# already authenticated (loop.quit already called by on_action/on_cancel).
def on_close_request(w):
    if result_code != 0:
        on_cancel(None, win, loop)
    return False

win.connect("close-request", on_close_request)

key_controller = Gtk.EventControllerKey.new()
def on_key_pressed(controller, keyval, keycode, state):
    if keyval == Gdk.KEY_Escape:
        on_cancel(None, win, loop)
        return True
    return False

key_controller.connect("key-pressed", on_key_pressed)
win.add_controller(key_controller)

# Anti-focus stealing: ensure entry regains focus if focus drifts away
focus_controller = Gtk.EventControllerFocus.new()
def on_focus_leave(c):
    GLib.idle_add(entry.grab_focus)
focus_controller.connect("leave", on_focus_leave)
win.add_controller(focus_controller)

# Signal handlers for termination
def sig_handler(sig, frame):
    global result_code
    result_code = 1
    loop.quit()

signal.signal(signal.SIGINT, sig_handler)
signal.signal(signal.SIGTERM, sig_handler)

win.present()

def do_focus():
    entry.grab_focus()
    return False

GLib.idle_add(do_focus)

loop.run()
sys.exit(result_code)
