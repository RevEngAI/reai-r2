# RevEngAI reai-r2 Installation Scripts

This directory contains platform-specific installation scripts for the RevEngAI reai-r2 plugin suite. These scripts automatically install the compiled libraries and plugins to the correct locations and fix any rpath/library path issues.

## Quick Start

1. Download the appropriate binary package for your platform from the releases page
2. Extract the package to a directory
3. Run the appropriate install script for your platform:
   - **Windows**: `.\Scripts\install-windows.ps1`
   - **macOS**: `./Scripts/install-macos.sh`
   - **Linux**: `./Scripts/install-linux.sh`

## Scripts Overview

### `install-windows.ps1`
Installs the reai-r2 plugin for Windows systems.

**What it installs:**
- `libcurl.dll` → `%USERPROFILE%\.local\bin\` (runtime)
- `reai.dll` → `%USERPROFILE%\.local\bin\` (runtime)
- `libcurl_imp.lib` → `%USERPROFILE%\.local\lib\` (linking)
- `reai.lib` → `%USERPROFILE%\.local\lib\` (linking)
- `reai_radare.dll` → Radare2 user plugin directory
- `reai_radare.lib` → Radare2 user plugin directory

**Requirements:**
- PowerShell 5.0+ (usually pre-installed)
- Radare2 installed and accessible from command line

### `install-macos.sh`
Installs the reai-r2 plugin for macOS systems and fixes rpath issues.

**What it installs:**
- `libreai.dylib` → `~/.local/lib/`
- `libreai_radare.so` → Radare2 user plugin directory

**Requirements:**
- Xcode Command Line Tools (`xcode-select --install`)
- Radare2 installed (via Homebrew: `brew install radare2`)

### `install-linux.sh`
Installs the reai-r2 plugin for Linux systems and fixes rpath issues.

**What it installs:**
- `libreai.so` → `~/.local/lib/`
- `libreai_radare.so` → Radare2 user plugin directory

**Requirements:**
- `patchelf` utility for fixing rpath
- Radare2 installed from package manager or source

## Installation Details

### What These Scripts Do

1. **Verify Required Files**: Check that all expected binary files are present
2. **Create Directories**: Set up `~/.local/lib` and plugin directories as needed
3. **Copy Files**: Install libraries and plugins to correct locations
4. **Fix Library Paths**: Resolve rpath/library loading issues that occur when binaries are built on CI systems
5. **Set Up Environment**: Create environment scripts for easy setup

### Why Install Scripts Are Needed

The binary artifacts are built on CI systems (GitHub Actions) with hardcoded paths like `/Users/runner/.local/lib` (macOS) or `/home/runner/.local/lib` (Linux). These paths don't exist on user systems, causing library loading failures.

The install scripts fix this by:
- **macOS**: Using `install_name_tool` to update rpath in binaries
- **Linux**: Using `patchelf` to update rpath in binaries  
- **Windows**: Managing PATH environment variables (no rpath needed)

### File Organization

**Windows:**
- **Runtime DLLs** (`*.dll`) → `%USERPROFILE%\.local\bin\` (added to PATH)
- **Import libraries** (`*.lib`) → `%USERPROFILE%\.local\lib\` (for development)
- **Plugin files** → Radare2 plugin directory

**macOS/Linux:**
- **Shared libraries** (`*.dylib`/`*.so`) → `~/.local/lib/`
- **Plugin files** → Radare2 plugin directory

### Manual Installation (Advanced Users)

If you prefer not to use the install scripts, you can manually install:

**Windows:**
1. Copy `*.dll` files to `%USERPROFILE%\.local\bin\`
2. Copy `*.lib` files to `%USERPROFILE%\.local\lib\`
3. Copy plugin files to Radare2 plugin directory (use `radare2 -H R2_USER_PLUGINS`)
4. Add `%USERPROFILE%\.local\bin` to your PATH

**macOS/Linux:**
1. Copy `libreai.*` files to `~/.local/lib/`
2. Copy plugin files to Radare2 plugin directory (use `radare2 -H R2_USER_PLUGINS`)
3. Fix library paths:
   - **macOS**: Use `install_name_tool` to add rpath pointing to `~/.local/lib`
   - **Linux**: Use `patchelf --set-rpath` to add `$ORIGIN` relative paths

## Troubleshooting

### Plugin Not Loading
```bash
# Test if radare2 can find the plugin
radare2 -c "reai help" /bin/ls

# Check if libraries can be found
# macOS:
otool -L ~/.local/lib/libreai.dylib
# Linux:
ldd ~/.local/lib/libreai.so
# Windows:
# Check if DLLs are in PATH
where reai.dll
```

### Library Loading Errors

**On macOS:**
- Ensure `~/.local/lib` is in `DYLD_LIBRARY_PATH`
- Run: `export DYLD_LIBRARY_PATH="$HOME/.local/lib:$DYLD_LIBRARY_PATH"`

**On Linux:**
- Ensure `~/.local/lib` is in `LD_LIBRARY_PATH`  
- Run: `export LD_LIBRARY_PATH="$HOME/.local/lib:$LD_LIBRARY_PATH"`

**On Windows:**
- Ensure `%USERPROFILE%\.local\bin` is in your `PATH`
- Or run the generated environment script: `& "$env:USERPROFILE\.local\bin\reai-env.ps1"`

### Permission Errors
- Ensure you have write permissions to `~/.local/` directory
- On some systems, you may need to create the directory first: `mkdir -p ~/.local/lib`

### Tool Requirements

**macOS:**
```bash
# Install Xcode Command Line Tools if not present
xcode-select --install

# Install Radare2
brew install radare2
```

**Linux:**
```bash
# Ubuntu/Debian
sudo apt-get install patchelf radare2

# Fedora/RHEL
sudo dnf install patchelf radare2

# Arch Linux
sudo pacman -S patchelf radare2
```

**Windows:**
- Install Radare2 from the official releases
- PowerShell should be available by default 