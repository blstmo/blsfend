#!/bin/bash
set -e

# Detect architecture
case $(uname -m) in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    *)
        echo "Unsupported architecture: $(uname -m)"
        exit 1
        ;;
esac

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run as root"
    exit 1
fi

# Install dependencies
echo "Installing dependencies..."
if command -v apt-get >/dev/null; then
    apt-get update
    apt-get install -y sqlite3 qrencode curl
elif command -v yum >/dev/null; then
    yum install -y sqlite qrencode curl
elif command -v pacman >/dev/null; then
    pacman -Sy sqlite qrencode curl
else
    echo "Warning: Please install sqlite3, qrencode, and curl manually"
    exit 1
fi

# Download and install binary
echo "Downloading BLSfend..."
LATEST=$(curl -s https://api.github.com/repos/blstmo/blsfend/releases/latest | grep "tag_name" | cut -d '"' -f 4)
curl -L -o /usr/local/bin/blsfend "https://github.com/blstmo/blsfend/releases/download/${LATEST}/blsfend-linux-${ARCH}"
chmod +x /usr/local/bin/blsfend

# Initialize
echo -e "\nBLSfend Configuration"
echo "====================="
read -p "Enter Discord webhook URL (press Enter to skip): " discord_webhook

if [ -n "$discord_webhook" ]; then
    blsfend -init "$discord_webhook"
else
    blsfend -init "none"
fi

# Setup admin
echo -e "\nAdmin User Setup"
echo "==============="
read -p "Enter admin username: " admin_user
blsfend -add "$admin_user" -admin

echo -e "\nInstallation complete!"
echo "Use 'blsfend -help' to see available commands"