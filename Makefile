PREFIX ?= $(HOME)/.local
DESTDIR ?=
BINDIR := $(PREFIX)/bin
DATADIR := $(PREFIX)/share
APPDIR := $(DATADIR)/applications
ICONSRC := cmd/tpm-fido-tray/icon/icon.png

CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -pedantic
PAMDIR ?= /etc/pam.d

ifeq ($(PREFIX),/usr)
    SYSTEMD_USER_DIR := /usr/lib/systemd/user
    UDEV_RULES_DIR := /usr/lib/udev/rules.d
else
    SYSTEMD_USER_DIR := $(HOME)/.config/systemd/user
    UDEV_RULES_DIR :=
endif

.PHONY: build install uninstall clean

build:
	go build -trimpath -ldflags="-s -w" -o tpm-fido .
	go build -trimpath -ldflags="-s -w" -o tpm-fido-tray ./cmd/tpm-fido-tray
	$(CC) $(CFLAGS) cmd/tpm-fido-pam-helper/main.c -lpam -o tpm-fido-pam-helper
	install -Dm755 cmd/tpm-fido-manager/tpm-fido-manager.py tpm-fido-manager
	install -Dm755 cmd/tpm-fido-prompt/tpm-fido-prompt.py tpm-fido-prompt

install: build
	install -Dm755 tpm-fido "$(DESTDIR)$(BINDIR)/tpm-fido"
	install -Dm755 tpm-fido-tray "$(DESTDIR)$(BINDIR)/tpm-fido-tray"
	install -Dm755 tpm-fido-pam-helper "$(DESTDIR)$(BINDIR)/tpm-fido-pam-helper"
	install -Dm755 cmd/tpm-fido-manager/tpm-fido-manager.py "$(DESTDIR)$(BINDIR)/tpm-fido-manager"
	install -Dm755 cmd/tpm-fido-prompt/tpm-fido-prompt.py "$(DESTDIR)$(BINDIR)/tpm-fido-prompt"
	install -Dm644 $(ICONSRC) "$(DESTDIR)$(DATADIR)/icons/hicolor/512x512/apps/tpm-fido.png"
	install -Dm644 $(ICONSRC) "$(DESTDIR)$(DATADIR)/icons/tpm-fido.png"
	@mkdir -p "$(DESTDIR)$(APPDIR)" "$(DESTDIR)$(SYSTEMD_USER_DIR)"
	@sed \
		-e 's|@BINDIR@|$(BINDIR)|g' \
		-e 's|@ICON@|tpm-fido|g' \
		packaging/tpm-fido-tray.desktop.in > "$(DESTDIR)$(APPDIR)/tpm-fido-manager.desktop"
	@sed \
		-e 's|/usr/bin/tpm-fido|$(BINDIR)/tpm-fido|g' \
		packaging/tpm-fido.service > "$(DESTDIR)$(SYSTEMD_USER_DIR)/tpm-fido.service"
	@if [ -z "$(DESTDIR)" ] && [ "$(PREFIX)" = "$(HOME)/.local" ]; then \
		mkdir -p "$(HOME)/.config/autostart"; \
		sed -e 's|@ICON@|tpm-fido|g' packaging/tpm-fido.desktop.in > "$(HOME)/.config/autostart/tpm-fido.desktop"; \
	fi
	@if [ -n "$(UDEV_RULES_DIR)" ]; then \
		mkdir -p "$(DESTDIR)$(UDEV_RULES_DIR)"; \
		install -Dm644 packaging/70-tpm-fido-uhid.rules "$(DESTDIR)$(UDEV_RULES_DIR)/70-tpm-fido-uhid.rules"; \
	fi
	@if [ -n "$(DESTDIR)" ] || [ "$$(id -u)" = "0" ]; then \
		mkdir -p "$(DESTDIR)$(PAMDIR)"; \
		install -Dm644 packaging/tpm-fido.pam "$(DESTDIR)$(PAMDIR)/tpm-fido"; \
	fi
	@echo "Installation complete."
	@echo "Binary directory: $(BINDIR)"
	@echo "Systemd user service installed to: $(SYSTEMD_USER_DIR)/tpm-fido.service"

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/tpm-fido"
	rm -f "$(DESTDIR)$(BINDIR)/tpm-fido-tray"
	rm -f "$(DESTDIR)$(BINDIR)/tpm-fido-pam-helper"
	rm -f "$(DESTDIR)$(BINDIR)/tpm-fido-manager"
	rm -f "$(DESTDIR)$(BINDIR)/tpm-fido-prompt"
	rm -f "$(DESTDIR)$(DATADIR)/icons/hicolor/512x512/apps/tpm-fido.png"
	rm -f "$(DESTDIR)$(DATADIR)/icons/tpm-fido.png"
	rm -f "$(DESTDIR)$(APPDIR)/tpm-fido-manager.desktop"
	rm -f "$(DESTDIR)$(SYSTEMD_USER_DIR)/tpm-fido.service"
	@if [ -n "$(UDEV_RULES_DIR)" ]; then \
		rm -f "$(DESTDIR)$(UDEV_RULES_DIR)/70-tpm-fido-uhid.rules"; \
	fi
	@if [ -n "$(DESTDIR)" ] || [ "$$(id -u)" = "0" ]; then \
		rm -f "$(DESTDIR)$(PAMDIR)/tpm-fido"; \
	fi

clean:
	rm -f tpm-fido tpm-fido-tray tpm-fido-manager tpm-fido-prompt tpm-fido-pam-helper
