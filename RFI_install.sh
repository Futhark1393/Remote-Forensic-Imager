#!/bin/bash
# Author: Futhark1393
# Description: Automated installer for Remote Forensic Imager v2.0
# Installs system dependencies, compiles libewf (E01), installs Python packages,
# and creates desktop/CLI shortcuts for system-wide integration.

APP_DIR=$(pwd)
DESKTOP_FILE="$HOME/.local/share/applications/rfi-v2.desktop"
BIN_WRAPPER="/usr/local/bin/rfi"

echo "[*] Starting automated installation for Remote Forensic Imager v2.0..."

# 1. Detect OS and install base dependencies
if [ -f /etc/fedora-release ]; then
    echo "[*] Fedora Linux detected. Installing build tools..."
    sudo dnf install -y gcc gcc-c++ make python3-devel zlib-devel openssl-devel wget python3-pip
elif [ -f /etc/lsb-release ]; then
    echo "[*] Ubuntu/Debian Linux detected. Installing build tools..."
    sudo apt-get update
    sudo apt-get install -y gcc g++ make python3-dev zlib1g-dev libssl-dev wget python3-pip
else
    echo "[!] Unsupported distribution. Please install dependencies manually."
    exit 1
fi

# 2. Download and compile libewf
echo "[*] Downloading libewf-experimental-20240506..."
wget -q -nc https://github.com/libyal/libewf/releases/download/20240506/libewf-experimental-20240506.tar.gz
tar -zxf libewf-experimental-20240506.tar.gz
cd libewf-20240506/

echo "[*] Compiling libewf with Python support (This may take a few minutes)..."
./configure --prefix=/usr --enable-shared --enable-python > /dev/null 2>&1
make > /dev/null 2>&1
sudo make install > /dev/null 2>&1

# 3. Inject shared libraries into system paths
echo "[*] Injecting shared libraries into system paths..."
cd libewf/.libs/

if [ -d "/usr/lib64" ]; then
    sudo cp -a libewf.so* /usr/lib64/ 2>/dev/null
else
    sudo cp -a libewf.so* /usr/lib/ 2>/dev/null
fi

sudo ldconfig

# 4. Install Python requirements
echo "[*] Installing Python requirements (PyQt6, paramiko, fpdf2)..."
cd ../../
pip install PyQt6 paramiko fpdf2 --user > /dev/null 2>&1

# 5. Create CLI wrapper
echo "[*] Creating CLI command 'rfi'..."
sudo bash -c "cat > $BIN_WRAPPER" << EOL
#!/bin/bash
# CLI wrapper for Remote Forensic Imager
cd "$APP_DIR"
python3 main_qt6.py "\$@"
EOL
sudo chmod +x $BIN_WRAPPER

# 6. Create Desktop Entry for Application Menus
echo "[*] Creating Application Menu shortcut..."
mkdir -p "$HOME/.local/share/applications"
cat > "$DESKTOP_FILE" << EOL
[Desktop Entry]
Version=2.0
Type=Application
Name=Remote Forensic Imager
Comment=Remote live disk and memory acquisition tool
Exec=python3 $APP_DIR/main_qt6.py
Path=$APP_DIR
Icon=utilities-terminal
Terminal=false
Categories=System;Security;Utility;
EOL
chmod +x "$DESKTOP_FILE"

# Clean up downloaded archive
rm -f libewf-experimental-20240506.tar.gz

echo "[+] Installation complete!"
echo "[+] You can now launch the application by typing 'rfi' in the terminal,"
echo "[+] or by searching for 'Remote Forensic Imager' in your application menu."
