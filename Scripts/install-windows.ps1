# RevEngAI reai-r2 Plugin Installer for Windows
# This script installs the plugins to the correct locations and sets up the environment

param(
    [switch]$Force,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

Write-Host "=== RevEngAI reai-r2 Plugin Installer for Windows ===" -ForegroundColor Cyan
Write-Host "Script directory: $PSScriptRoot" -ForegroundColor Blue

# Expected files for Windows (exact files from CI)
$ExpectedFiles = @(
    "libcurl.dll",
    "libcurl_imp.lib",
    "reai.dll",
    "reai.lib",
    "reai_radare.dll",
    "reai_radare.lib"
)

# Check if all expected files exist
Write-Host "`n=== Checking for required files ===" -ForegroundColor Yellow
foreach ($file in $ExpectedFiles) {
    $filePath = Join-Path $PSScriptRoot $file
    if (-not (Test-Path $filePath)) {
        Write-Host "❌ Error: Required file missing: $file" -ForegroundColor Red
        Write-Host "Expected files: $($ExpectedFiles -join ', ')" -ForegroundColor Red
        exit 1
    }
    Write-Host "✅ Found: $file" -ForegroundColor Green
}

# Install shared libraries
Write-Host "`n=== Installing shared libraries ===" -ForegroundColor Yellow

$UserLibDir = "$env:USERPROFILE\.local\lib"
$UserBinDir = "$env:USERPROFILE\.local\bin"

# Create directories
New-Item -ItemType Directory -Force -Path $UserLibDir | Out-Null
New-Item -ItemType Directory -Force -Path $UserBinDir | Out-Null

# Install DLL files to bin directory (so they're in PATH for runtime)
$DllFiles = @("libcurl.dll", "reai.dll")
foreach ($dll in $DllFiles) {
    $srcPath = Join-Path $PSScriptRoot $dll
    if (Test-Path $srcPath) {
        Copy-Item $srcPath $UserBinDir -Force
        Write-Host "✅ Installed: $dll -> $UserBinDir" -ForegroundColor Green
    } else {
        Write-Host "❌ Error: $dll not found" -ForegroundColor Red
        exit 1
    }
}

# Install LIB files to lib directory (for linking)
$LibFiles = @("libcurl_imp.lib", "reai.lib")
foreach ($lib in $LibFiles) {
    $srcPath = Join-Path $PSScriptRoot $lib
    if (Test-Path $srcPath) {
        Copy-Item $srcPath $UserLibDir -Force
        Write-Host "✅ Installed: $lib -> $UserLibDir" -ForegroundColor Green
    } else {
        Write-Host "❌ Error: $lib not found" -ForegroundColor Red
        exit 1
    }
}

# Install Radare2 plugin
Write-Host "`n=== Installing Radare2 plugin ===" -ForegroundColor Yellow

# Check if radare2 is installed
try {
    $radarePluginDir = & radare2.exe -H R2_USER_PLUGINS 2>$null
    if (-not $radarePluginDir) {
        throw "Empty plugin directory"
    }
    $radarePluginDir = $radarePluginDir.Trim()
    Write-Host "Radare2 plugin directory: $radarePluginDir" -ForegroundColor Blue
} catch {
    Write-Host "❌ Error: Could not get radare2 plugin directory. Is radare2 installed?" -ForegroundColor Red
    Write-Host "Install radare2 from: https://github.com/radareorg/radare2" -ForegroundColor Yellow
    exit 1
}

# Create plugin directory
New-Item -ItemType Directory -Force -Path $radarePluginDir | Out-Null

# Install Radare2 plugin files
$PluginFiles = @("reai_radare.dll", "reai_radare.lib")
foreach ($plugin in $PluginFiles) {
    $srcPath = Join-Path $PSScriptRoot $plugin
    if (Test-Path $srcPath) {
        Copy-Item $srcPath $radarePluginDir -Force
        Write-Host "✅ Installed: $plugin -> $radarePluginDir" -ForegroundColor Green
    } else {
        Write-Host "❌ Error: $plugin not found" -ForegroundColor Red
        exit 1
    }
}

# Create environment setup script
Write-Host "`n=== Creating environment setup ===" -ForegroundColor Yellow

$envScript = Join-Path $UserBinDir "reai-env.ps1"

$envContent = @"
# RevEngAI reai-r2 Environment Setup
# Source this script to set up environment for using RevEngAI plugins

# Add library and binary paths to PATH
`$env:PATH = "$UserBinDir;$UserLibDir;" + `$env:PATH

Write-Host "RevEngAI reai-r2 environment configured" -ForegroundColor Green
Write-Host "Binary path added to PATH: $UserBinDir" -ForegroundColor Blue
Write-Host "Library path added to PATH: $UserLibDir" -ForegroundColor Blue
"@

Set-Content -Path $envScript -Value $envContent -Encoding UTF8
Write-Host "✅ Environment script created: $envScript" -ForegroundColor Green

# Update current session PATH
$env:PATH = "$UserBinDir;$UserLibDir;" + $env:PATH

Write-Host "`n🎉 Installation complete!" -ForegroundColor Green
Write-Host "`n📋 Summary:" -ForegroundColor Cyan
Write-Host "  • DLL files installed to: $UserBinDir" -ForegroundColor White
Write-Host "    - libcurl.dll" -ForegroundColor Gray
Write-Host "    - reai.dll" -ForegroundColor Gray
Write-Host "  • LIB files installed to: $UserLibDir" -ForegroundColor White
Write-Host "    - libcurl_imp.lib" -ForegroundColor Gray
Write-Host "    - reai.lib" -ForegroundColor Gray
Write-Host "  • Radare2 plugin installed to: $radarePluginDir" -ForegroundColor White
Write-Host "    - reai_radare.dll" -ForegroundColor Gray
Write-Host "    - reai_radare.lib" -ForegroundColor Gray
Write-Host "  • Environment script created: $envScript" -ForegroundColor White

Write-Host "`n🚀 To use the plugins:" -ForegroundColor Cyan
Write-Host "  1. For command line radare2: plugins should work automatically" -ForegroundColor White
Write-Host "  2. Or run the environment script in new PowerShell sessions:" -ForegroundColor White
Write-Host "     & `"$envScript`"" -ForegroundColor Gray

Write-Host "`n🔧 To test the installation:" -ForegroundColor Cyan
Write-Host "  radare2.exe -c 'reai help' C:\Windows\System32\notepad.exe" -ForegroundColor Gray

Write-Host "`n💡 Tip: Add the environment script to your PowerShell profile for automatic setup" -ForegroundColor Yellow 