# Maintainer: jomi
pkgname=tpm-fido-git
pkgver=r34.5a449cd
pkgrel=1
pkgdesc="TPM 2.0 Hardware-Bound Passkey/FIDO2 Authenticator for Linux with Modern GTK4/Libadwaita UI and PAM verification"
arch=('x86_64' 'aarch64')
url="https://github.com/idkreally001/tpm-fido"
license=('BSD-3-Clause')
depends=(
    'tpm2-tss'
    'libadwaita'
    'gtk4'
    'python'
    'python-gobject'
    'python-pam'
    'pam'
)
makedepends=('go' 'git' 'gcc')
optdepends=(
    'libayatana-appindicator: for system tray icon integration'
    'gtk4-layer-shell: for Wayland exclusive overlay layer and input grab'
)
provides=('tpm-fido' 'tpm-fido-tray' 'tpm-fido-manager' 'tpm-fido-pam-helper')
conflicts=('tpm-fido')
install=tpm-fido.install

# Support building directly inside the cloned working tree or via git clone
if [ -f "$startdir/tpmfido.go" ]; then
    source=()
    md5sums=()
else
    source=("git+https://github.com/idkreally001/tpm-fido.git")
    md5sums=('SKIP')
fi

pkgver() {
    if [ -f "$startdir/tpmfido.go" ]; then
        cd "$startdir"
    else
        cd "$srcdir/tpm-fido"
    fi
    printf "r%s.%s" "$(git rev-list --count HEAD 2>/dev/null || echo 1)" "$(git rev-parse --short HEAD 2>/dev/null || echo dev)"
}

build() {
    if [ -f "$startdir/tpmfido.go" ]; then
        cd "$startdir"
    else
        cd "$srcdir/tpm-fido"
    fi
    make build
}

package() {
    if [ -f "$startdir/tpmfido.go" ]; then
        cd "$startdir"
    else
        cd "$srcdir/tpm-fido"
    fi
    make PREFIX=/usr DESTDIR="$pkgdir" install
}
