#!/bin/bash
# Author: Futhark1393
# Description: Automated installer for ForenXtract (FX) v3.2.0
# Installs system dependencies, compiles libewf (E01 optional),
# creates a Python virtual environment, installs the package,
# and symlinks fx / fx-acquire / fx-verify to /usr/local/bin.
#
# Usage:
#   sudo bash FX_install.sh            # full install (recommended)
#   sudo bash FX_install.sh --no-ewf   # skip libewf compilation
#   sudo bash FX_install.sh --with-aff4 # also install pyaff4

set -euo pipefail

# ── Determine real user (works with or without sudo) ─────────────────────────
if [ -n "${SUDO_USER:-}" ]; then
    REAL_USER="$SUDO_USER"
    REAL_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
    REAL_USER="$USER"
    REAL_HOME="$HOME"
fi

# Run a command as the real (non-root) user
as_user() { sudo -u "$REAL_USER" "$@"; }

# ── Parse flags ───────────────────────────────────────────────────────────────
SKIP_EWF=false
WITH_AFF4=false
for arg in "$@"; do
    case "$arg" in
        --no-ewf)    SKIP_EWF=true ;;
        --with-aff4) WITH_AFF4=true ;;
        --help|-h)
            echo "Usage: sudo bash FX_install.sh [--no-ewf] [--with-aff4]"
            echo ""
            echo "  --no-ewf     Skip libewf compilation (skip E01 format support)"
            echo "  --with-aff4  Install pyaff4 for AFF4 format support"
            exit 0 ;;
    esac
done

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$APP_DIR/.venv"
DESKTOP_FILE="$REAL_HOME/.local/share/applications/fx.desktop"

C_CYAN='\033[1;36m'
C_GREEN='\033[1;32m'
C_YELLOW='\033[1;33m'
C_RED='\033[1;31m'
C_RESET='\033[0m'

info()    { echo -e "${C_CYAN}[*]${C_RESET} $*"; }
success() { echo -e "${C_GREEN}[+]${C_RESET} $*"; }
warn()    { echo -e "${C_YELLOW}[!]${C_RESET} $*"; }
error()   { echo -e "${C_RED}[✗]${C_RESET} $*"; exit 1; }

echo ""
echo -e "${C_CYAN}╔════════════════════════════════════╗${C_RESET}"
echo -e "${C_CYAN}║ ███████╗  ██╗  ██╗                 ║${C_RESET}"
echo -e "${C_CYAN}║ ██╔════╝  ╚██╗██╔╝   ForenXtract   ║${C_RESET}"
echo -e "${C_CYAN}║ █████╗     ╚███╔╝    v3.2.0        ║${C_RESET}"
echo -e "${C_CYAN}║ ██╔══╝     ██╔██╗    Installer     ║${C_RESET}"
echo -e "${C_CYAN}║ ██║       ██╔╝ ██╗                 ║${C_RESET}"
echo -e "${C_CYAN}║ ╚═╝       ╚═╝  ╚═╝                 ║${C_RESET}"
echo -e "${C_CYAN}╚════════════════════════════════════╝${C_RESET}"
echo ""

# ── 1. Detect OS and install system packages ──────────────────────────────────
info "Detecting OS and installing system dependencies..."

if [ -f /etc/fedora-release ] || [ -f /etc/redhat-release ]; then
    OS="fedora"
    info "Fedora / RHEL detected."
    dnf install -y \
        gcc gcc-c++ make python3-devel python3-pip \
        zlib-devel openssl-devel wget \
        qt6-qtbase qt6-qtbase-gui mesa-libEGL mesa-libGL \
        > /dev/null 2>&1

elif [ -f /etc/lsb-release ] || [ -f /etc/debian_version ]; then
    OS="debian"
    info "Ubuntu / Debian / Kali detected."
    apt-get update -qq
    apt-get install -y \
        gcc g++ make python3-dev python3-pip python3-venv \
        zlib1g-dev libssl-dev wget \
        libegl1 libgl1 libglib2.0-0 libxkbcommon0 libxkbcommon-x11-0 \
        libxcb1 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-randr0 \
        libxcb-render0 libxcb-render-util0 libxcb-shape0 libxcb-shm0 libxcb-sync1 \
        libxcb-xfixes0 libxcb-xinerama0 libxcb-xkb1 libxrender1 libxi6 \
        libsm6 libice6 libfontconfig1 libfreetype6 \
        > /dev/null 2>&1
else
    warn "Unrecognised distribution. Attempting to continue — install deps manually if something fails."
    OS="unknown"
fi

success "System dependencies installed."

# ── 2. Optional: compile libewf (E01 support) ─────────────────────────────────
if [ "$SKIP_EWF" = false ]; then
    info "Downloading and compiling libewf (E01 support)..."
    EWF_VER="20240506"
    EWF_TARBALL="libewf-experimental-${EWF_VER}.tar.gz"
    EWF_DIR="libewf-${EWF_VER}"

    cd /tmp
    wget -q -nc "https://github.com/libyal/libewf/releases/download/${EWF_VER}/${EWF_TARBALL}" || \
        { warn "libewf download failed — skipping E01 support."; SKIP_EWF=true; }

    if [ "$SKIP_EWF" = false ]; then
        tar -zxf "$EWF_TARBALL"
        cd "$EWF_DIR"
        ./configure --prefix=/usr --enable-shared --enable-python > /dev/null 2>&1
        make > /dev/null 2>&1
        make install > /dev/null 2>&1

        # Inject shared libraries
        if [ -d "/usr/lib64" ]; then
            cp -a libewf/.libs/libewf.so* /usr/lib64/ 2>/dev/null || true
        else
            cp -a libewf/.libs/libewf.so* /usr/lib/ 2>/dev/null || true
        fi
        ldconfig

        cd /tmp
        rm -rf "$EWF_TARBALL" "$EWF_DIR"
        success "libewf compiled and installed — E01 format available."
    fi
else
    info "Skipping libewf compilation (--no-ewf). E01 format will not be available."
fi

# ── 3. Create Python virtual environment (as real user) ───────────────────────
cd "$APP_DIR"
info "Creating Python virtual environment at $VENV_DIR ..."

# Remove stale root-owned venv if it exists
if [ -d "$VENV_DIR" ] && [ "$(stat -c '%U' "$VENV_DIR")" = "root" ]; then
    warn "Removing existing root-owned venv..."
    rm -rf "$VENV_DIR"
fi

as_user python3 -m venv "$VENV_DIR"

info "Upgrading pip..."
as_user "$VENV_DIR/bin/pip" install --upgrade pip > /dev/null 2>&1

# ── 4. Install ForenXtract (FX) package ────────────────────────────────────
info "Installing ForenXtract (FX) package..."
as_user "$VENV_DIR/bin/pip" install -e . > /dev/null 2>&1
success "FX package installed."

# ── 5. Optional: AFF4 support ────────────────────────────────────────────────
if [ "$WITH_AFF4" = true ]; then
    info "Installing pyaff4 (AFF4 format support)..."
    as_user "$VENV_DIR/bin/pip" install pyaff4 > /dev/null 2>&1 && \
        success "pyaff4 installed — AFF4 format available." || \
        warn "pyaff4 installation failed — AFF4 format will not be available."
else
    info "Skipping AFF4 (use --with-aff4 to enable)."
fi

# ── 6. Symlink binaries to /usr/local/bin ────────────────────────────────────
info "Creating system-wide CLI commands (fx, fx-acquire, fx-verify)..."

for CMD in fx fx-acquire fx-verify; do
    SRC="$VENV_DIR/bin/$CMD"
    DST="/usr/local/bin/$CMD"
    if [ -f "$SRC" ]; then
        ln -sf "$SRC" "$DST"
        success "  $CMD → $DST"
    else
        warn "  $CMD binary not found in venv, skipping."
    fi
done

# ── 7. Desktop entry (as real user) ──────────────────────────────────────────
info "Creating application menu shortcut..."
as_user mkdir -p "$REAL_HOME/.local/share/applications"
# Remove any stale root-owned desktop file before writing as real user
rm -f "$DESKTOP_FILE"
# Write as real user (tee) so the file is owned by REAL_USER, not root
as_user tee "$DESKTOP_FILE" > /dev/null << EOL
[Desktop Entry]
Version=3.2
Type=Application
Name=ForenXtract (FX)
GenericName=Forensic Disk Imager
Comment=Remote live disk acquisition with tamper-evident audit trail
Exec=$VENV_DIR/bin/python $APP_DIR/main_qt6.py
Path=$APP_DIR
Icon=utilities-terminal
Terminal=false
Categories=System;Security;Utility;
Keywords=forensic;disk;imaging;acquisition;evidence;
EOL
success "Desktop entry created."

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${C_GREEN}╔══════════════════════════════════════════════════╗${C_RESET}"
echo -e "${C_GREEN}║   ForenXtract (FX) v3.2.0 — INSTALLED           ║${C_RESET}"
echo -e "${C_GREEN}╚══════════════════════════════════════════════════╝${C_RESET}"
echo ""
echo -e "  ${C_CYAN}GUI mode:${C_RESET}        fx"
echo -e "  ${C_CYAN}CLI acquire:${C_RESET}     fx-acquire --help"
echo -e "  ${C_CYAN}CLI verify:${C_RESET}      fx-verify <AuditTrail.jsonl>"
echo ""
echo -e "  ${C_YELLOW}Note:${C_RESET} Open a new terminal or run 'hash -r' if commands are not found yet."
echo ""
