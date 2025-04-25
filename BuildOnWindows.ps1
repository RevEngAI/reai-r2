# File : Installer.ps1
# Description : Powershell script to automatically build and install radare2 
# Date : 24th April 2025
# Author : Siddharth Mishra (admin@brightprogrammer.in)
# Copyright : Copyright (c) 2025 RevEngAI
#
# To execute this script, in a powershell environment run
# Set-ExecutionPolicy Bypass -Scope Process -Force; iex ".\\BuildOnWindows.ps1"
#
# Dependencies
# - MSVC Compiler Toolchain

# Escape backslashes becuase Windows is idiot af
$CWD = $PWD.Path -replace '\\', '\\'

$BuildDir = "Build\\WindowsBuild"
$DownPath = "$CWD\\$BuildDir\\Artifacts"
$DepsPath = "$CWD\\$BuildDir\\Dependencies"
$InstallPath = "$CWD\\Build\\WindowsInstall"

# Remove install directory if already exists to avoid clashes
if ((Test-Path "$InstallPath")) {
    Remove-Item -LiteralPath "$InstallPath" -Force -Recurse
}

# Setup build directory structure
if ((Test-Path "$BuildDir")) {
    Remove-Item -LiteralPath "$BuildDir" -Force -Recurse
}

md "$BuildDir"
md "$DownPath"
md "$DepsPath"
md "$InstallPath"

# Set environment variable for this powershell session
$env:Path = $env:Path + ";$InstallPath;$InstallPath\\bin;$InstallPath\\lib;$DownPath\\aria2c;$DownPath\\7zip"

# x64 Architecture Builds
cmd /c 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'

# Download aria2c for faster download of dependencies
# Invoke-WebRequest performs single threaded downloads and that too at slow speed
Invoke-WebRequest -Uri "https://github.com/aria2/aria2/releases/download/release-1.37.0/aria2-1.37.0-win-64bit-build1.zip" -OutFile "$DownPath\\aria2c.zip"
Expand-Archive -LiteralPath "$DownPath\\aria2c.zip" -DestinationPath "$DownPath\\aria2c"
Move-Item "$DownPath\\aria2c\\aria2-1.37.0-win-64bit-build1\\*" -Destination "$DownPath\\aria2c" -Force
Remove-Item -LiteralPath "$DownPath\\aria2c\\aria2-1.37.0-win-64bit-build1" -Force -Recurse

# Download 7z for faster decompression time. Windows is lightyears behind in their tech.
# Download dependency
aria2c "https://7-zip.org/a/7zr.exe" -j8 -d "$DownPath"
aria2c "https://7-zip.org/a/7z2409-extra.7z" -j8 -d "$DownPath"

# Installing dependency
& "$DownPath\\7zr.exe" x "$DownPath\\7z2409-extra.7z" -o"$DownPath\\7zip"

# Make available a preinstalled dependency for direct use
function Make-Available () {
    param (
        [string]$pkgCmdName,
        [string]$pkgUrl,
        [string]$pkgName,
        [string]$pkgSubfolderName
    )
    
    # Download dependency
    aria2c "$pkgUrl" -j8 -d "$DownPath"
        
    # Installing dependency
    7za x "$DownPath\\$pkgName" -o"$DepsPath\\$pkgCmdName"
    Copy-Item "$DepsPath\\$pkgCmdName\\$pkgSubfolderName\\*" -Destination "$InstallPath\\" -Force -Recurse
    Remove-Item -LiteralPath "$DepsPath\\$pkgCmdName" -Force -Recurse
}

# WARN: Order of execution of these Make-Available commands is really important

Make-Available -pkgCmdName "r2" `
    -pkgUrl "https://github.com/radareorg/radare2/releases/download/5.9.8/radare2-5.9.8-w64.zip" `
    -pkgName "radare2-5.9.8-w64.zip" `
    -pkgSubfolderName "radare2-5.9.8-w64"

# Make pkg-config available for use
Make-Available -pkgCmdName "pkg-config" `
    -pkgUrl "https://cyfuture.dl.sourceforge.net/project/pkgconfiglite/0.28-1/pkg-config-lite-0.28-1_bin-win32.zip?viasf=1" `
    -pkgName "pkg-config-lite-0.28-1_bin-win32.zip" `
    -pkgSubfolderName "pkg-config-lite-0.28-1"

# Make available cmake for use
Make-Available -pkgCmdName "cmake" `
    -pkgUrl "https://github.com/Kitware/CMake/releases/download/v4.0.0-rc5/cmake-4.0.0-rc5-windows-x86_64.zip" `
    -pkgName "cmake-4.0.0-rc5-windows-x86_64.zip" `
    -pkgSubfolderName "cmake-4.0.0-rc5-windows-x86_64"
    
# Make available ninja for use
Make-Available -pkgCmdName "ninja" `
    -pkgUrl "https://github.com/ninja-build/ninja/releases/download/v1.12.1/ninja-win.zip" `
    -pkgName "ninja-win.zip" `
    -pkgSubfolderName "\\"

Write-Host "All system dependencies are satisfied."    
Write-Host "Now fetching plugin dependencies, and then building and installing these..."
    
# Setup a list of files to be downloaded
$DepsList = @"

https://curl.se/download/curl-8.13.0.zip
https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.18.zip
https://github.com/brightprogrammer/tomlc99/archive/refs/tags/v1.zip
https://github.com/RevEngAI/creait/archive/refs/heads/master.zip
https://github.com/RevEngAI/reai-r2/archive/refs/heads/master.zip
"@

# Dump URL List to a text file for aria2c to use
$DepsList | Out-File -FilePath "$BuildDir\\DependenciesList.txt" -Encoding utf8 -Force

# Download artifacts
# List of files to download with URLs and destination paths
aria2c -i "$BuildDir\\DependenciesList.txt" -j8 -d "$DownPath"

# These dependencies need to be built on the host machine, unlike installing the pre-compiled binaries above
$pkgs = @(
    # Final Destination         Downloaded archive name                Subfolder name where actually extracted
    @{name = "curl";    path = "$DownPath\\curl-8.13.0.zip";           subfolderName="curl-8.13.0"},
    @{name = "reai-r2"; path = "$DownPath\\reai-r2-master.zip";        subfolderName="reai-r2-master"},
    @{name = "tomlc99"; path = "$DownPath\\tomlc99-1.zip";             subfolderName="tomlc99-1"},
    @{name = "creait";  path = "$DownPath\\creait-master.zip";         subfolderName="creait-master"},
    @{name = "cjson";   path = "$DownPath\\cJSON-1.7.18.zip";          subfolderName="cJSON-1.7.18"}
)
# Unpack a dependency to be built later on
# These temporarily go into dependencies directory
function Unpack-Dependency {
      param ([string]$packageName, [string]$packagePath, [string]$subfolderName)
      $packageInstallDir = "$DepsPath\\$packageName"  # -------------------------------------------------------> Path where package is expanded
      Write-Host "Installing dependency $packagePath to $packageInstallDir..."
      7za x "$packagePath" -o"$packageInstallDir" # -----------------------------------------------------------> Expand archive to this path
      Copy-Item "$packageInstallDir\\$subfolderName\\*" -Destination "$packageInstallDir\\" -Force -Recurse # -> Copy contents of subfolder to expanded path
      Remove-Item -LiteralPath "$packageInstallDir\\$subfolderName" -Force -Recurse # -------------------------> Remove subfolder where archive was originally extracted
}

foreach ($pkg in $pkgs) {
    Write-Host "Extracting $($pkg.name)"        
    Unpack-Dependency -packageName $pkg.name -packagePath $pkg.path -subfolderName $pkg.subfolderName
}

# Build and install libCURL
Write-Host Build" & INSTALL libCURL..."
cmake -S "$DepsPath\\curl" -A x64 `
    -B "$DepsPath\\curl\\Build" `
    -G "Visual Studio 17 2022" `
    -D CURL_ZLIB=OFF `
    -D CURL_ZSTD=OFF `
    -D USE_NGHTTP2=OFF `
    -D USE_LIBIDN2=OFF `
    -D CURL_BROTLI=OFF `
    -D CURL_USE_LIBPSL=OFF `
    -D CMAKE_PREFIX_PATH="$InstallPath" `
    -D CMAKE_INSTALL_PREFIX="$InstallPath" `
    -D BUILD_SHARED_LIBS=OFF `
    -D CURL_USE_SCHANNEL=ON
cmake --build "$DepsPath\\curl\\Build" --config Release
cmake --install "$DepsPath\\curl\\Build" --prefix "$InstallPath" --config Release
Write-Host Build" & INSTALL libCURL... DONE"

# Prepare creait 
# Build and install cjson
Write-Host Build" & INSTALL cJSON..."
cmake -S "$DepsPath\\cjson" -A x64 `
    -B "$DepsPath\\cjson\\Build" `
    -G "Visual Studio 17 2022" `
    -D CMAKE_C_STANDARD=99 `
    -D ENABLE_CUSTOM_COMPILER_FLAGS=OFF `
    -D CMAKE_PREFIX_PATH="$InstallPath" `
    -D CMAKE_INSTALL_PREFIX="$InstallPath" `
    -DCMAKE_POLICY_VERSION_MINIMUM="3.5"
cmake --build "$DepsPath\\cjson\\Build" --config Release
cmake --install "$DepsPath\\cjson\\Build" --prefix "$InstallPath" --config Release
Write-Host Build" & INSTALL cJSON... DONE"

# Build and install tomlc99 
Write-Host Build" & INSTALL tomlc99..."
cmake -S "$DepsPath\\tomlc99" -A x64 `
    -B "$DepsPath\\tomlc99\\Build" `
    -G "Visual Studio 17 2022" `
    -D CMAKE_C_STANDARD=23 `
    -D CMAKE_PREFIX_PATH="$InstallPath" `
    -D CMAKE_INSTALL_PREFIX="$InstallPath" `
    -DCMAKE_POLICY_VERSION_MINIMUM="3.5"
cmake --build "$DepsPath\\tomlc99\\Build" --config Release
cmake --install "$DepsPath\\tomlc99\\Build" --prefix "$InstallPath" --config Release
Write-Host Build" & INSTALL tomlc99... DONE"

# Build and install creait
Write-Host Build" & INSTALL creait..."
cmake -S "$DepsPath\\creait" -A x64 `
    -B "$DepsPath\\creait\\Build" `
    -G "Visual Studio 17 2022" `
    -D CMAKE_PREFIX_PATH="$InstallPath" `
    -D CMAKE_INSTALL_PREFIX="$InstallPath" `
    -D BUILD_SHARED_LIBS=OFF `
    -DCMAKE_POLICY_VERSION_MINIMUM="3.5"
cmake --build "$DepsPath\\creait\\Build" --config Release
cmake --install "$DepsPath\\creait\\Build" --prefix "$InstallPath" --config Release
Write-Host Build" & INSTALL creait... DONE"

# Build reai-r2
cmake -S "$DepsPath\\reai-r2" -A x64 `
    -B "$DepsPath\\reai-r2\\Build" `
    -G "Visual Studio 17 2022" `
    -D CMAKE_PREFIX_PATH="$InstallPath" `
    -D CMAKE_INSTALL_PREFIX="$InstallPath" `
    -D CMAKE_C_FLAGS="/TC" `
    -D CMAKE_CXX_FLAGS="/TC" `
    -D CMAKE_POLICY_VERSION_MINIMUM="3.5"
cmake --build "$DepsPath\\reai-r2\\Build" --config Release
cmake --install "$DepsPath\\reai-r2\\Build" --prefix "$InstallPath" --config Release
Write-Host Build" & INSTALL reai-r2... DONE"

# Set environment variables permanently across machine for all users
Write-Host "Installation complete! Enjoy using the plugins ;-)"
Write-Host "Contact the developers through issues or discussions in https://github.com/revengai/reai-r2"

Write-Host "`rUpdate your environment variable by adding these paths to your `$env:Path : `n$InstallPath;`n$InstallPath\\bin;`n$InstallPath\\lib;"
