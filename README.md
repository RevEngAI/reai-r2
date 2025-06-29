# RevEng.AI Radare2 Plugin

[![Build Linux](https://github.com/RevEngAI/reai-r2/workflows/Build%20Linux/badge.svg)](https://github.com/RevEngAI/reai-r2/actions/workflows/build-linux.yml)
[![Build macOS](https://github.com/RevEngAI/reai-r2/workflows/Build%20macOS/badge.svg)](https://github.com/RevEngAI/reai-r2/actions/workflows/build-macos.yml)
[![Build Windows](https://github.com/RevEngAI/reai-r2/workflows/Build%20Windows/badge.svg)](https://github.com/RevEngAI/reai-r2/actions/workflows/build-windows.yml)
[![Docker ARM64 Build and Test](https://github.com/RevEngAI/reai-r2/workflows/Docker%20ARM64%20Build%20and%20Test/badge.svg)](https://github.com/RevEngAI/reai-r2/actions/workflows/docker-test.yml)

RevEng.AI plugin for Radare2 that provides AI-powered reverse engineering capabilities including decompilation, function analysis, binary similarity, and more.

## Support

Need help? Join our Discord server: [![Discord](https://img.shields.io/badge/Discord-Join%20Us-7289da?logo=discord&logoColor=white)](https://discord.com/invite/ZwQTvzfSbA)

## Quick Installation (Recommended)

### Prerequisites

- **Radare2** installed and available in PATH

### Platform-Specific Installation (Easiest)

Download the latest release for your platform and run the automated install script:

#### Linux

**x86_64:**
```bash
# Download and extract
wget https://github.com/RevEngAI/reai-r2/releases/latest/download/reai-r2-linux-x86_64.tar.gz
tar -xzf reai-r2-linux-x86_64.tar.gz
cd reai-r2-linux-x86_64

# Install dependencies
sudo apt install patchelf  # Ubuntu/Debian
# sudo dnf install patchelf    # Fedora/RHEL
# sudo pacman -S patchelf      # Arch

# Run installer
chmod +x install-linux.sh
./install-linux.sh
```

**ARM64:**
```bash
# Download and extract
wget https://github.com/RevEngAI/reai-r2/releases/latest/download/reai-r2-linux-aarch64.tar.gz
tar -xzf reai-r2-linux-aarch64.tar.gz
cd reai-r2-linux-aarch64

# Install dependencies
sudo apt install patchelf  # Ubuntu/Debian
# sudo dnf install patchelf    # Fedora/RHEL
# sudo pacman -S patchelf      # Arch

# Run installer
chmod +x install-linux.sh
./install-linux.sh
```

#### macOS
```bash
# Download and extract
curl -L -O https://github.com/RevEngAI/reai-r2/releases/latest/download/reai-r2-macos.tar.gz
tar -xzf reai-r2-macos.tar.gz
cd reai-r2-macos

# Install dependencies
xcode-select --install

# Run installer
chmod +x install-macos.sh
./install-macos.sh
```

#### Windows
```powershell
# Download and extract
Invoke-WebRequest "https://github.com/RevEngAI/reai-r2/releases/latest/download/reai-r2-windows.zip" -OutFile "reai-r2-windows.zip"
Expand-Archive "reai-r2-windows.zip" -Force
cd reai-r2-windows

# Run installer
Set-ExecutionPolicy Bypass -Scope Process -Force; .\install-windows.ps1
```

### What the Install Scripts Do

The automated installation scripts handle all the complex setup:

- **Install libraries** to user directories (`~/.local/lib/` on Unix, `%USERPROFILE%\.local\bin\` on Windows)
- **Install Radare2 plugin** to `$(r2 -H R2_USER_PLUGINS)`
- **Fix library paths** so plugins can find radare2 libraries and dependencies
- **Set up environment variables** for library discovery (Windows: updates system PATH; Unix: creates environment script)
- **Verify installation** and provide status messages

## Configuration

Before using the plugin, create a configuration file in your home directory:

**Unix (Linux/macOS):** `~/.creait`
**Windows:** `%USERPROFILE%\.creait`

```ini
api_key = YOUR_REVENGAI_API_KEY
host = https://api.reveng.ai
```

### Generate Config with Plugin

You can also generate the config file using the plugin itself:

```bash
# In radare2
REi YOUR_API_KEY_HERE
```

Get your API key from [RevEng.AI Portal Settings](https://portal.reveng.ai/settings).

## Usage

### Radare2 Command Line

After installation, the plugin commands are available in radare2:

```bash
r2 -AA your_binary
> RE?          # Show all RevEng.AI commands
```

## Docker Installation

For isolated environments or when you want a pre-configured setup. The Docker image builds everything from source and supports multiple architectures (x86_64, ARM64).

### Quick Start (Recommended)

```bash
# Build Docker image with your API key
docker build --build-arg REVENG_APIKEY=your-api-key-here -t reai-r2 \
    https://github.com/RevEngAI/reai-r2.git

# Run radare2 with your binary
docker run -it --rm \
    -v /path/to/your/binary:/home/revengai/binary \
    reai-r2 r2 binary
```

### Advanced Usage

```bash
# Clone and build locally (if you want to modify the Dockerfile)
git clone https://github.com/RevEngAI/reai-r2
cd reai-r2

# Build with custom configuration
docker build \
    --build-arg REVENG_APIKEY=your-api-key-here \
    --build-arg REVENG_HOST=https://api.reveng.ai \
    -t reai-r2 .

# Run with your binary mounted
docker run -it --rm \
    -v ~/Desktop/your_binary:/home/revengai/binary \
    reai-r2 r2 binary

# Run radare2 with auto-analysis
docker run -it --rm \
    -v /path/to/your/binary:/home/revengai/binary \
    reai-r2 r2 -AA binary

# Run interactively for multiple analyses
docker run -it --rm \
    -v $(pwd):/home/revengai/workspace \
    reai-r2
```

### Using RevEng.AI Commands in Docker

Once radare2 is running inside the container, use the RevEng.AI commands:

```bash
# Start radare2 with your binary
docker run -it --rm \
    -v ~/Desktop/your_binary:/home/revengai/binary \
    reai-r2 r2 -AA binary

# Inside radare2, use RevEng.AI commands:
[0x00000000]> RE?                    # Show all RevEng.AI commands
```

### Build Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `REVENG_APIKEY` | `CHANGEME` | Your RevEng.AI API key from [portal.reveng.ai](https://portal.reveng.ai/settings) |
| `REVENG_HOST` | `https://api.reveng.ai` | RevEng.AI API endpoint |
| `BRANCH_NAME` | `master` | Git branch to build from |

### Docker Features

- **Built from source**: Compiles radare2 and plugins from source for multi-architecture support
- **Multi-architecture**: Supports x86_64 and ARM64 builds
- **Pre-configured**: API key and host are set during build
- **User-local installation**: Everything installed in `/home/revengai/.local`
- **Lightweight runtime**: Multi-stage build keeps final image small
- **Verified setup**: Checks plugin installation during build
- **Usage help**: Shows commands and examples when container starts

## Manual Build (For Developers)

If you want to build from source or contribute to development:

### Prerequisites

Before building, install:
- **cmake**, **make**, **ninja**, **pkg-config**
- **gcc/g++** (Linux) or **Xcode command line tools** (macOS) or **MSVC build tools** (Windows)
- **libcurl development headers**
- **radare2** with development headers
- **Python 3** with **PyYAML**

### Build Commands

#### Linux/macOS
```bash
# Automated build script
curl -fsSL https://raw.githubusercontent.com/RevEngAI/reai-r2/refs/heads/master/Scripts/Build.sh | bash

# Or manual build
git clone https://github.com/RevEngAI/reai-r2
cd reai-r2
git submodule update --init --recursive

# Build
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
cmake --install build --prefix ~/.local
```

#### Windows
```powershell
# Automated build script (from Developer PowerShell)
Set-ExecutionPolicy Bypass -Scope Process -Force; iex (iwr -UseBasicParsing 'https://raw.githubusercontent.com/RevEngAI/reai-r2/refs/heads/master/Scripts/Build.ps1')

# Manual build requires Visual Studio build tools and more setup
```

### Build Options

- `CMAKE_INSTALL_PREFIX`: Installation prefix (default: system-specific)

## Troubleshooting

### Plugin Not Loading

1. **Check radare2 installation**:
   ```bash
   r2 -v
   r2 -H R2_USER_PLUGINS
   ```

2. **Verify plugin installation**:
   ```bash
   ls "$(r2 -H R2_USER_PLUGINS)" | grep reai
   ```

3. **Check environment**:
   ```bash
   # Linux/macOS
   source ~/.local/bin/reai-env.sh
   echo $LD_LIBRARY_PATH    # Linux
   echo $DYLD_LIBRARY_PATH  # macOS
   
   # Windows (if automatic setup failed)
   %USERPROFILE%\.local\bin\reai-env.ps1
   echo $env:PATH
   ```

### Library Not Found Errors

1. **Verify library installation**:
   ```bash
   ls ~/.local/lib/libreai.*  # Unix
   ls "%USERPROFILE%\.local\bin\reai.dll"  # Windows
   ```

2. **Check library paths** (Unix):
   ```bash
   # Linux
   patchelf --print-rpath "$(r2 -H R2_USER_PLUGINS)/reai_radare.so"
   
   # macOS
   otool -l "$(r2 -H R2_USER_PLUGINS)/reai_radare.dylib" | grep -A2 LC_RPATH
   ```

### Windows Environment Issues

If plugins don't work after installation:

1. **Restart your terminal/PowerShell** - Windows needs to reload the updated PATH
2. **Check if PATH was updated**:
   ```powershell
   echo $env:PATH | findstr ".local"
   ```
3. **Manually run environment script**:
   ```powershell
   %USERPROFILE%\.local\bin\reai-env.ps1
   ```
4. **Manually add to PATH** if script fails:
   - Open System Properties → Environment Variables
   - Add `%USERPROFILE%\.local\bin` to your user PATH

### Permission Errors

Ensure your user has write permissions to:
- `~/.local/` directory (Unix)
- `%USERPROFILE%\.local\` directory (Windows)
- Current working directory (for temporary files)

## Uninstall

```bash
# Linux/macOS
curl -fsSL https://raw.githubusercontent.com/RevEngAI/reai-r2/refs/heads/master/Scripts/Uninstall.sh | bash

# Windows (from Developer PowerShell)
Set-ExecutionPolicy Bypass -Scope Process -Force; iex (iwr -UseBasicParsing 'https://raw.githubusercontent.com/RevEngAI/reai-r2/refs/heads/master/Scripts/Uninstall.ps1')
```
