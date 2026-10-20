#!/usr/bin/env python3
import sys
import os
import time
import json
import socket
import argparse
import subprocess

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

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, GLib, Gdk, Pango

parser = argparse.ArgumentParser(description="TPM Fido Passkey Manager")
parser.add_argument("--socket", dest="socket_path", default="", help="Path to tpm-fido.sock")
args, _ = parser.parse_known_args()

def get_socket_path():
    if args.socket_path:
        return args.socket_path
    rt = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    return os.path.join(rt, "tpm-fido.sock")

def ensure_daemon_started():
    sock_path = get_socket_path()
    if os.path.exists(sock_path):
        return
    try:
        res = subprocess.run(["systemctl", "--user", "start", "tpm-fido.service"], capture_output=True, timeout=2)
        if res.returncode == 0:
            for _ in range(15):
                if os.path.exists(sock_path):
                    return
                time.sleep(0.1)
    except Exception:
        pass

def ctl_call(method, params=None):
    ensure_daemon_started()
    sock_path = get_socket_path()
    if not os.path.exists(sock_path):
        raise FileNotFoundError(f"Control socket not found at {sock_path}. Is tpm-fido running?")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(3.0)
    try:
        s.connect(sock_path)
        req = {"method": method}
        if params is not None:
            req["params"] = params
        payload = json.dumps(req) + "\n"
        s.sendall(payload.encode('utf-8'))
        
        data = b""
        while not data.endswith(b"\n"):
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        
        if not data:
            raise RuntimeError("Empty response from tpm-fido daemon")
        resp = json.loads(data.decode('utf-8'))
        if resp.get("error"):
            raise RuntimeError(resp["error"])
        return resp.get("result")
    finally:
        s.close()

css = b"""
window {
    background-color: #1c1c1e;
    color: #ffffff;
}

headerbar {
    background-color: #242426;
    border-bottom: 1px solid #323234;
    color: #ffffff;
    min-height: 52px;
    padding: 0 8px;
}

headerbar .title {
    font-weight: 700;
}

.app-header {
    font-size: 11px;
    font-weight: 700;
    color: #9a9a9e;
    letter-spacing: 0.5px;
}

.title-text {
    font-size: 18px;
    font-weight: 800;
    color: #ffffff;
}

.banner-card {
    background-color: #242426;
    border: 1px solid #323234;
    border-radius: 12px;
    padding: 16px 20px;
}

.status-title {
    font-size: 14px;
    font-weight: 700;
    color: #ffffff;
    margin-bottom: 2px;
}

.status-subtitle {
    font-size: 12px;
    color: #9a9a9e;
}

.badge-tag {
    background-color: rgba(230, 107, 10, 0.18);
    color: #e66b0a;
    font-size: 11px;
    font-weight: 700;
    padding: 5px 12px;
    border-radius: 12px;
    border: 1px solid rgba(230, 107, 10, 0.35);
}

.badge-count {
    background-color: #323234;
    color: #9a9a9e;
    font-size: 11px;
    font-weight: 700;
    padding: 2px 8px;
    border-radius: 10px;
}

.sidebar-box {
    background-color: #242426;
    border: 1px solid #323234;
    border-radius: 12px;
}

.content-box {
    background-color: #242426;
    border: 1px solid #323234;
    border-radius: 12px;
}

.section-title {
    font-size: 13px;
    font-weight: 700;
    color: #9a9a9e;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.rp-row {
    padding: 10px 14px;
    border-radius: 8px;
    margin: 2px 4px;
}

.rp-row:hover {
    background-color: #2c2c2e;
}

.rp-row:selected {
    background-color: #38383a;
}

.rp-name {
    font-size: 14px;
    font-weight: 600;
    color: #ffffff;
}

.card-item {
    background-color: #1c1c1e;
    border: 1px solid #323234;
    border-radius: 10px;
    padding: 14px;
    margin-bottom: 10px;
}

.user-name {
    font-size: 15px;
    font-weight: 700;
    color: #ffffff;
}

.meta-label {
    font-size: 12px;
    color: #9a9a9e;
}

.meta-val {
    font-size: 12px;
    color: #d1d1d6;
    font-family: monospace;
}

.btn-primary {
    background-color: #e66b0a;
    color: #ffffff;
    font-weight: 700;
    font-size: 13px;
    border-radius: 8px;
    padding: 8px 16px;
}

.btn-primary:hover {
    background-color: #ff8522;
}

.btn-secondary {
    background-color: #2c2c2e;
    color: #ffffff;
    border: 1px solid #3a3a3c;
    border-radius: 8px;
    font-weight: 600;
    font-size: 13px;
    padding: 8px 14px;
}

.btn-secondary:hover {
    background-color: #3a3a3c;
}

.btn-danger {
    background-color: rgba(255, 69, 58, 0.15);
    color: #ff453a;
    border: 1px solid rgba(255, 69, 58, 0.3);
    border-radius: 8px;
    font-weight: 700;
    font-size: 12px;
    padding: 6px 12px;
}

.btn-danger:hover {
    background-color: #ff453a;
    color: #ffffff;
}

.error-banner {
    background-color: rgba(255, 69, 58, 0.15);
    border: 1px solid rgba(255, 69, 58, 0.3);
    border-radius: 8px;
    padding: 10px 14px;
    color: #ff453a;
    font-size: 13px;
    font-weight: 600;
}
"""

class ManagerWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="TPM Fido Manager")
        self.set_default_size(720, 540)

        self.rp_list = []
        self.selected_rp = None
        self.creds_map = {}  # rp -> list of creds

        # ── Adw.ToolbarView gives us a proper OS-native titlebar/drag area ──
        toolbar_view = Adw.ToolbarView()

        # HeaderBar: drag region + window controls
        header_bar = Adw.HeaderBar()
        header_bar.set_show_end_title_buttons(True)

        # Custom title widget: small "subtitle / title" stack
        title_widget_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
        title_widget_box.set_valign(Gtk.Align.CENTER)
        sub_lbl = Gtk.Label(label="TPM FIDO2 / WEBAUTHN")
        sub_lbl.add_css_class("app-header")
        main_title_lbl = Gtk.Label(label="Hardware Passkey Manager")
        main_title_lbl.add_css_class("title-text")
        title_widget_box.append(sub_lbl)
        title_widget_box.append(main_title_lbl)
        header_bar.set_title_widget(title_widget_box)

        toolbar_view.add_top_bar(header_bar)

        # ── Scrollable content area below the header ──
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        main_box.set_margin_top(12)
        main_box.set_margin_bottom(16)
        main_box.set_margin_start(18)
        main_box.set_margin_end(18)

        toolbar_view.set_content(main_box)
        self.set_content(toolbar_view)

        # Security Status Card
        banner = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
        banner.add_css_class("banner-card")
        banner.set_valign(Gtk.Align.CENTER)

        shield_icon = Gtk.Image.new_from_icon_name("security-high-symbolic")
        shield_icon.set_pixel_size(28)
        shield_icon.set_valign(Gtk.Align.CENTER)
        banner.append(shield_icon)

        status_text_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        status_text_box.set_valign(Gtk.Align.CENTER)
        status_h = Gtk.Label(label="TPM 2.0 Hardware Bound  •  CTAP 2.1 Passkeys", halign=Gtk.Align.START)
        status_h.add_css_class("status-title")
        status_sub = Gtk.Label(label="Protected by Linux PAM system password & hardware security module", halign=Gtk.Align.START)
        status_sub.add_css_class("status-subtitle")
        status_text_box.append(status_h)
        status_text_box.append(status_sub)
        banner.append(status_text_box)

        banner_spacer = Gtk.Box()
        banner_spacer.set_hexpand(True)
        banner.append(banner_spacer)

        refresh_btn = Gtk.Button(label="Refresh")
        refresh_btn.add_css_class("btn-secondary")
        refresh_btn.set_valign(Gtk.Align.CENTER)
        refresh_btn.connect("clicked", lambda _: self.refresh_data())
        banner.append(refresh_btn)

        pam_badge = Gtk.Label(label="PAM AUTH ACTIVE")
        pam_badge.add_css_class("badge-tag")
        pam_badge.set_valign(Gtk.Align.CENTER)
        banner.append(pam_badge)

        main_box.append(banner)

        # Error notification banner (hidden by default)
        self.error_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.error_box.add_css_class("error-banner")
        self.error_lbl = Gtk.Label(label="", halign=Gtk.Align.START)
        self.error_lbl.set_hexpand(True)
        self.error_box.append(self.error_lbl)
        self.error_box.set_visible(False)
        main_box.append(self.error_box)

        # Main columns: Left (RP List) and Right (Credentials Details)
        cols_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        cols_box.set_vexpand(True)

        # Left Column
        left_col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        left_col.set_size_request(240, -1)
        left_col.add_css_class("sidebar-box")
        left_col.set_margin_top(2)
        left_col.set_margin_bottom(2)

        left_header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        left_header.set_margin_top(12)
        left_header.set_margin_start(14)
        left_header.set_margin_end(14)
        rp_title = Gtk.Label(label="Registered Sites", halign=Gtk.Align.START)
        rp_title.add_css_class("section-title")
        left_header.append(rp_title)
        
        self.rp_count_badge = Gtk.Label(label="0")
        self.rp_count_badge.add_css_class("badge-count")
        left_header.append(self.rp_count_badge)
        left_col.append(left_header)

        rp_scroll = Gtk.ScrolledWindow()
        rp_scroll.set_vexpand(True)
        rp_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        self.rp_listbox = Gtk.ListBox()
        self.rp_listbox.set_selection_mode(Gtk.SelectionMode.SINGLE)
        self.rp_listbox.connect("row-selected", self.on_rp_selected)
        rp_scroll.set_child(self.rp_listbox)
        left_col.append(rp_scroll)

        cols_box.append(left_col)

        # Right Column
        right_col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        right_col.set_hexpand(True)
        right_col.add_css_class("content-box")
        right_col.set_margin_top(2)
        right_col.set_margin_bottom(2)

        right_header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        right_header.set_margin_top(12)
        right_header.set_margin_start(16)
        right_header.set_margin_end(16)
        self.right_title = Gtk.Label(label="Passkeys", halign=Gtk.Align.START)
        self.right_title.add_css_class("section-title")
        right_header.append(self.right_title)

        self.cred_count_badge = Gtk.Label(label="0")
        self.cred_count_badge.add_css_class("badge-count")
        right_header.append(self.cred_count_badge)
        right_col.append(right_header)

        cred_scroll = Gtk.ScrolledWindow()
        cred_scroll.set_vexpand(True)
        cred_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        self.creds_container = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.creds_container.set_margin_top(8)
        self.creds_container.set_margin_start(16)
        self.creds_container.set_margin_end(16)
        self.creds_container.set_margin_bottom(16)
        cred_scroll.set_child(self.creds_container)
        right_col.append(cred_scroll)

        cols_box.append(right_col)
        main_box.append(cols_box)

        GLib.idle_add(self.refresh_data)

    def show_error(self, message):
        self.error_lbl.set_text(message)
        self.error_box.set_visible(True)

    def clear_error(self):
        self.error_box.set_visible(False)

    def refresh_data(self):
        self.clear_error()
        try:
            rps = ctl_call("ListRPs") or []
        except Exception as e:
            self.show_error(f"Failed to connect to tpm-fido daemon: {e}")
            rps = []

        self.rp_list = sorted(rps)
        self.rp_count_badge.set_text(str(len(self.rp_list)))

        # Clear existing listbox items
        while True:
            row = self.rp_listbox.get_row_at_index(0)
            if row is None:
                break
            self.rp_listbox.remove(row)

        for rp in self.rp_list:
            row = Gtk.ListBoxRow()
            row.add_css_class("rp-row")
            lbl = Gtk.Label(label=rp, halign=Gtk.Align.START)
            lbl.add_css_class("rp-name")
            lbl.set_ellipsize(Pango.EllipsizeMode.END)
            row.set_child(lbl)
            self.rp_listbox.append(row)

        if self.rp_list:
            if self.selected_rp in self.rp_list:
                idx = self.rp_list.index(self.selected_rp)
                row = self.rp_listbox.get_row_at_index(idx)
                self.rp_listbox.select_row(row)
            else:
                row = self.rp_listbox.get_row_at_index(0)
                self.rp_listbox.select_row(row)
        else:
            self.selected_rp = None
            self.render_empty_creds("No relying party websites registered yet.")

    def on_rp_selected(self, listbox, row):
        if row is None:
            return
        idx = row.get_index()
        if 0 <= idx < len(self.rp_list):
            self.selected_rp = self.rp_list[idx]
            self.refresh_creds_for_selected()

    def refresh_creds_for_selected(self):
        if not self.selected_rp:
            return
        self.right_title.set_text(f"Passkeys for {self.selected_rp}")
        try:
            creds = ctl_call("ListCreds", {"rp_id": self.selected_rp}) or []
        except Exception as e:
            self.show_error(f"Failed to fetch credentials: {e}")
            creds = []

        self.cred_count_badge.set_text(str(len(creds)))
        self.render_creds(creds)

    def clear_container(self, container):
        child = container.get_first_child()
        while child:
            next_child = child.get_next_sibling()
            container.remove(child)
            child = next_child

    def render_empty_creds(self, message):
        self.clear_container(self.creds_container)
        self.right_title.set_text("Passkeys")
        self.cred_count_badge.set_text("0")
        empty_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        empty_box.set_valign(Gtk.Align.CENTER)
        empty_box.set_vexpand(True)
        icon = Gtk.Image.new_from_icon_name("dialog-information-symbolic")
        icon.set_pixel_size(32)
        lbl = Gtk.Label(label=message)
        lbl.add_css_class("meta-label")
        empty_box.append(icon)
        empty_box.append(lbl)
        self.creds_container.append(empty_box)

    def render_creds(self, creds):
        self.clear_container(self.creds_container)
        if not creds:
            self.render_empty_creds("No credentials found for this site.")
            return

        for cred in creds:
            card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            card.add_css_class("card-item")

            top_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            u_icon = Gtk.Image.new_from_icon_name("avatar-default-symbolic")
            u_icon.set_pixel_size(22)
            top_row.append(u_icon)

            uname = cred.get("user_name") or "(unnamed resident key)"
            u_lbl = Gtk.Label(label=uname, halign=Gtk.Align.START)
            u_lbl.add_css_class("user-name")
            top_row.append(u_lbl)

            card_spacer = Gtk.Box()
            card_spacer.set_hexpand(True)
            top_row.append(card_spacer)

            del_btn = Gtk.Button(label="Delete")
            del_btn.add_css_class("btn-danger")
            del_btn.connect("clicked", self.confirm_delete, cred)
            top_row.append(del_btn)

            card.append(top_row)

            # Metadata grid
            grid = Gtk.Grid()
            grid.set_column_spacing(12)
            grid.set_row_spacing(4)

            lbl1 = Gtk.Label(label="Sign Count:", halign=Gtk.Align.START)
            lbl1.add_css_class("meta-label")
            val1 = Gtk.Label(label=str(cred.get("sign_count", 0)), halign=Gtk.Align.START)
            val1.add_css_class("meta-val")
            grid.attach(lbl1, 0, 0, 1, 1)
            grid.attach(val1, 1, 0, 1, 1)

            cred_id = cred.get("credential_id", "")
            preview_id = (cred_id[:16] + "..." + cred_id[-8:]) if len(cred_id) > 28 else cred_id
            lbl2 = Gtk.Label(label="Credential ID:", halign=Gtk.Align.START)
            lbl2.add_css_class("meta-label")
            val2 = Gtk.Label(label=preview_id, halign=Gtk.Align.START)
            val2.add_css_class("meta-val")
            val2.set_tooltip_text(cred_id)
            grid.attach(lbl2, 0, 1, 1, 1)
            grid.attach(val2, 1, 1, 1, 1)

            card.append(grid)
            self.creds_container.append(card)

    def confirm_delete(self, btn, cred):
        uname = cred.get("user_name") or "this passkey"
        dialog = Adw.MessageDialog(
            transient_for=self,
            heading="Delete Passkey?",
            body=f"Are you sure you want to permanently delete the passkey for '{uname}' on {self.selected_rp}? This will remove the resident credential from the TPM hardware store."
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("delete", "Delete Passkey")
        dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")

        def on_response(d, response_id):
            if response_id == "delete":
                try:
                    ctl_call("DeleteCred", {
                        "rp_id": self.selected_rp,
                        "credential_id": cred.get("credential_id")
                    })
                    self.refresh_data()
                except Exception as e:
                    self.show_error(f"Failed to delete credential: {e}")

        dialog.connect("response", on_response)
        dialog.present()


class ManagerApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id="io.github.tpm_fido.Manager")

    def do_activate(self):
        win = self.props.active_window
        if not win:
            win = ManagerWindow(self)
        win.present()

if __name__ == "__main__":
    if not Gtk.init_check():
        sys.stderr.write("Error: Unable to connect to Wayland/X11 display manager.\n")
        sys.exit(1)

    Adw.init()

    css_provider = Gtk.CssProvider()
    css_provider.load_from_data(css)
    Gtk.StyleContext.add_provider_for_display(
        Gdk.Display.get_default(),
        css_provider,
        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
    )

    app = ManagerApp()
    app.run(sys.argv)
