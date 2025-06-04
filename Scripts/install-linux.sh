#!/bin/bash

# RevEngAI reai-r2 Plugin Installer for Linux
# This script installs the plugins and fixes rpath to point to the correct library locations

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARTIFACT_DIR="$SCRIPT_DIR"

echo "=== RevEngAI reai-r2 Plugin Installer for Linux ==="
echo "Script directory: $SCRIPT_DIR"
echo "Artifact directory: $ARTIFACT_DIR"

# Check if we have required tools
if ! command -v patchelf &> /dev/null; then
    echo "❌ Error: patchelf not found. Please install it first."
    echo "Ubuntu/Debian: sudo apt-get install patchelf"
    echo "Fedora/RHEL: sudo dnf install patchelf"
    echo "Arch: sudo pacman -S patchelf"
    exit 1
fi

# Detect user's local library directory
USER_LIB_DIR="$HOME/.local/lib"
mkdir -p "$USER_LIB_DIR"

# Install exact shared libraries from CI artifacts
echo "=== Installing shared libraries ==="

# Install libreai.so (from creait)
LIBREAI_PATH="$ARTIFACT_DIR/libreai.so"
if [ -f "$LIBREAI_PATH" ]; then
    echo "Installing: libreai.so -> $USER_LIB_DIR/"
    cp "$LIBREAI_PATH" "$USER_LIB_DIR/"
    chmod 755 "$USER_LIB_DIR/libreai.so"
    echo "✅ libreai.so installed"
else
    echo "❌ Error: libreai.so not found in artifacts"
    exit 1
fi

# Find and install Radare2 plugin
echo "=== Installing Radare2 plugin ==="
RADARE_PLUGIN="$ARTIFACT_DIR/libreai_radare.so"
if [ -f "$RADARE_PLUGIN" ]; then
    # Get radare2 plugin directory
    RADARE_PLUGIN_DIR=$(radare2 -H R2_USER_PLUGINS 2>/dev/null) || {
        echo "❌ Error: Could not get radare2 plugin directory. Is radare2 installed?"
        exit 1
    }
    
    mkdir -p "$RADARE_PLUGIN_DIR"
    
    echo "Installing Radare2 plugin: libreai_radare.so -> $RADARE_PLUGIN_DIR/"
    cp "$RADARE_PLUGIN" "$RADARE_PLUGIN_DIR/"
    chmod 755 "$RADARE_PLUGIN_DIR/libreai_radare.so"
    
    # Fix rpath for Radare2 plugin
    echo "Fixing rpath for Radare2 plugin..."
    RADARE_INSTALLED_PLUGIN="$RADARE_PLUGIN_DIR/libreai_radare.so"
    
    # Clear existing rpaths
    patchelf --remove-rpath "$RADARE_INSTALLED_PLUGIN" 2>/dev/null || true
    
    # Add correct rpath - Calculate relative path from plugin directory to lib directory
    RELATIVE_PATH=$(python3 -c "import os; print(os.path.relpath('$USER_LIB_DIR', '$RADARE_PLUGIN_DIR'))")
    patchelf --set-rpath "\$ORIGIN/$RELATIVE_PATH:$USER_LIB_DIR" "$RADARE_INSTALLED_PLUGIN" 2>/dev/null || true
    
    echo "✅ Radare2 plugin installed and rpath fixed"
else
    echo "❌ Error: libreai_radare.so not found in artifacts"
    exit 1
fi

# Create environment setup script
echo "=== Creating environment setup ==="
ENV_SCRIPT="$HOME/.local/bin/reai-env.sh"
mkdir -p "$(dirname "$ENV_SCRIPT")"

cat > "$ENV_SCRIPT" << 'EOF'
#!/bin/bash
# RevEngAI reai-r2 Environment Setup
# Source this script to set up environment for using RevEngAI plugins

# Add library path for plugin discovery
export LD_LIBRARY_PATH="$HOME/.local/lib:$LD_LIBRARY_PATH"

# Add binary path
export PATH="$HOME/.local/bin:$PATH"

echo "RevEngAI reai-r2 environment configured"
echo "Library path: $LD_LIBRARY_PATH"
EOF

chmod +x "$ENV_SCRIPT"

echo ""
echo "🎉 Installation complete!"
echo ""
echo "📋 Summary:"
echo "  • Shared libraries installed to: $USER_LIB_DIR"
echo "    - libreai.so"
echo "  • Radare2 plugin installed to: $RADARE_PLUGIN_DIR"
echo "    - libreai_radare.so"
echo "  • Environment script created: $ENV_SCRIPT"
echo ""
echo "🚀 To use the plugins:"
echo "  1. For command line radare2: plugins should work automatically"
echo "  2. Or add to your ~/.bashrc or ~/.zshrc:"
echo "     echo 'source $ENV_SCRIPT' >> ~/.bashrc"
echo ""
echo "🔧 To test the installation:"
echo "  radare2 /bin/ls -c 'reai help'"
echo "" 