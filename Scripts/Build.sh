#!/bin/bash
set -euo pipefail

branchName=${1:-master}  # Default to 'master' stable branch if no argument provided
echo "📍 Using branch: $branchName"

InstallPath="$HOME/.local"
echo "📦 Dependencies will be installed at prefix: $InstallPath"

# Cleanup old builds
echo "🧹 Cleaning up /tmp..."
rm -rf /tmp/reai-r2 /tmp/creait

echo "🌐 Cloning repositories..."
git clone -b "$branchName" https://github.com/revengai/reai-r2
git clone https://github.com/revengai/creait

# Build and install creait
echo "🔧 Building creait..."
cmake -S "/tmp/creait" \
      -B "/tmp/creait/Build" \
      -D CMAKE_BUILD_TYPE=Release \
      -D CMAKE_PREFIX_PATH="$InstallPath" \
      -D CMAKE_INSTALL_PREFIX="$InstallPath"

cmake --build "/tmp/creait/Build" --config Release
cmake --install "/tmp/creait/Build" --prefix "$InstallPath" --config Release

# Build and install reai-r2
echo "🔧 Building reai-r2..."
cmake -S "/tmp/reai-r2" \
      -B "/tmp/reai-r2/Build" \
      -D CMAKE_BUILD_TYPE=Release \
      -D CMAKE_PREFIX_PATH="$InstallPath" \
      -D CMAKE_INSTALL_PREFIX="$InstallPath"

cmake --build "/tmp/reai-r2/Build" --config Release
cmake --install "/tmp/reai-r2/Build" --prefix "$InstallPath" --config Release

echo "✅ Build and install complete!"
