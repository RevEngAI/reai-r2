# File : Installer.ps1
# Description : Powershell script to automatically build and install radare2 
# Date : 24th April 2025
# Author : Siddharth Mishra (admin@brightprogrammer.in)
# Copyright : Copyright (c) 2025 RevEngAI
#
# To execute this script, in a powershell environment run
# Set-ExecutionPolicy Bypass -Scope Process -Force; iex ".\\Scripts\\Build.ps1"
#
# Dependencies
# - MSVC Compiler Toolchain

param(
    [string]$branchName = "master"
)

Write-Host "\n🛠️  Starting Radare2 Installer Script..."
Write-Host "📦 Using branch: $branchName"

$BaseDir = "$($HOME -replace '\\', '\\')\\.local\\RevEngAI\\Radare2"
$BuildDir = "$BaseDir\\Build"
$InstallPath = "$BaseDir\\Install"
$DownPath = "$BuildDir\\Artifacts"
$DepsPath = "$BuildDir\\Dependencies"

Write-Host "📁 Setting up directory structure under $BaseDir..."
if (Test-Path -LiteralPath "$BaseDir") {
    Write-Host "🧹 Removing previous installation..."
    Remove-Item -LiteralPath "$BaseDir" -Force -Recurse
}

md "$BaseDir" | Out-Null
md "$BuildDir" | Out-Null
md "$InstallPath" | Out-Null
md "$DownPath" | Out-Null
md "$DepsPath" | Out-Null

$env:Path = $env:Path + ";$InstallPath;$InstallPath\\bin;$InstallPath\\lib;$DownPath\\aria2c;$DownPath\\7zip"

Write-Host "🔧 Initializing MSVC environment..."
cmd /c 'C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Auxiliary\\Build\\vcvars64.bat'

Write-Host "🌐 Downloading aria2c and 7z utilities..."
Invoke-WebRequest -Uri "https://github.com/aria2/aria2/releases/download/release-1.37.0/aria2-1.37.0-win-64bit-build1.zip" -OutFile "$DownPath\\aria2c.zip"
Expand-Archive -LiteralPath "$DownPath\\aria2c.zip" -DestinationPath "$DownPath\\aria2c"
Move-Item "$DownPath\\aria2c\\aria2-1.37.0-win-64bit-build1\\*" -Destination "$DownPath\\aria2c" -Force
Remove-Item -LiteralPath "$DownPath\\aria2c\\aria2-1.37.0-win-64bit-build1" -Force -Recurse

aria2c "https://7-zip.org/a/7zr.exe" -j8 -d "$DownPath"
aria2c "https://7-zip.org/a/7z2409-extra.7z" -j8 -d "$DownPath"

& "$DownPath\\7zr.exe" x "$DownPath\\7z2409-extra.7z" -o"$DownPath\\7zip"

function Make-Available () {
    param (
        [string]$pkgCmdName,
        [string]$pkgUrl,
        [string]$pkgName,
        [string]$pkgSubfolderName
    )
    Write-Host "📦 Installing $pkgCmdName from $pkgUrl"
    aria2c "$pkgUrl" -j8 -d "$DownPath"
    7za x "$DownPath\\$pkgName" -o"$DepsPath\\$pkgCmdName"
    Copy-Item "$DepsPath\\$pkgCmdName\\$pkgSubfolderName\\*" -Destination "$InstallPath\\" -Force -Recurse
    Remove-Item -LiteralPath "$DepsPath\\$pkgCmdName" -Force -Recurse
    Write-Host "✅ $pkgCmdName installed"
}

Make-Available -pkgCmdName "r2" `
    -pkgUrl "https://github.com/radareorg/radare2/releases/download/5.9.8/radare2-5.9.8-w64.zip" `
    -pkgName "radare2-5.9.8-w64.zip" `
    -pkgSubfolderName "radare2-5.9.8-w64"

Make-Available -pkgCmdName "pkg-config" `
    -pkgUrl "https://cyfuture.dl.sourceforge.net/project/pkgconfiglite/0.28-1/pkg-config-lite-0.28-1_bin-win32.zip?viasf=1" `
    -pkgName "pkg-config-lite-0.28-1_bin-win32.zip" `
    -pkgSubfolderName "pkg-config-lite-0.28-1"

Make-Available -pkgCmdName "cmake" `
    -pkgUrl "https://github.com/Kitware/CMake/releases/download/v4.0.0-rc5/cmake-4.0.0-rc5-windows-x86_64.zip" `
    -pkgName "cmake-4.0.0-rc5-windows-x86_64.zip" `
    -pkgSubfolderName "cmake-4.0.0-rc5-windows-x86_64"

Make-Available -pkgCmdName "ninja" `
    -pkgUrl "https://github.com/ninja-build/ninja/releases/download/v1.12.1/ninja-win.zip" `
    -pkgName "ninja-win.zip" `
    -pkgSubfolderName "\\"

Write-Host "🧩 All system dependencies installed. Proceeding to download plugin dependencies..."

$DepsList = @"

https://curl.se/download/curl-8.13.0.zip
https://github.com/RevEngAI/creait/archive/refs/heads/master.zip
https://github.com/RevEngAI/reai-r2/archive/refs/heads/${branchName}.zip
"@
$DepsList | Out-File -FilePath "$BuildDir\\DependenciesList.txt" -Encoding utf8 -Force
aria2c -i "$BuildDir\\DependenciesList.txt" -j8 -d "$DownPath"

$pkgs = @(
    @{name = "curl";    path = "$DownPath\\curl-8.13.0.zip";                 subfolderName="curl-8.13.0"},
    @{name = "reai-r2"; path = "$DownPath\\reai-r2-${branchName}.zip";       subfolderName="reai-r2-${branchName}"},
    @{name = "creait";  path = "$DownPath\\creait-master.zip";               subfolderName="creait-master"}
)

function Unpack-Dependency {
    param ([string]$packageName, [string]$packagePath, [string]$subfolderName)
    $packageInstallDir = "$DepsPath\\$packageName"
    Write-Host "📦 Extracting $packageName to $packageInstallDir..."
    7za x "$packagePath" -o"$packageInstallDir"
    Copy-Item "$packageInstallDir\\$subfolderName\\*" -Destination "$packageInstallDir\\" -Force -Recurse
    Remove-Item -LiteralPath "$packageInstallDir\\$subfolderName" -Force -Recurse
    Write-Host "✅ $packageName unpacked"
}

foreach ($pkg in $pkgs) {
    Unpack-Dependency -packageName $pkg.name -packagePath $pkg.path -subfolderName $pkg.subfolderName
}

Write-Host "🔨 Building and installing libCURL..."
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
    -D CURL_USE_SCHANNEL=ON
cmake --build "$DepsPath\\curl\\Build" --config Release
cmake --install "$DepsPath\\curl\\Build" --prefix "$InstallPath" --config Release
Write-Host "✅ libCURL installed"

Write-Host "🔨 Building and installing creait..."
cmake -S "$DepsPath\\creait" -A x64 `
    -B "$DepsPath\\creait\\Build" `
    -G "Visual Studio 17 2022" `
    -D CMAKE_PREFIX_PATH="$InstallPath" `
    -D CMAKE_INSTALL_PREFIX="$InstallPath"
cmake --build "$DepsPath\\creait\\Build" --config Release
cmake --install "$DepsPath\\creait\\Build" --prefix "$InstallPath" --config Release
Write-Host "✅ creait installed"

Write-Host "🔨 Building and installing reai-r2..."
cmake -S "$DepsPath\\reai-r2" -A x64 `
    -B "$DepsPath\\reai-r2\\Build" `
    -G "Visual Studio 17 2022" `
    -D CMAKE_MODULE_PATH="$InstallPath\\lib\\cmake\\Modules" `
    -D CMAKE_PREFIX_PATH="$InstallPath" `
    -D CMAKE_INSTALL_PREFIX="$InstallPath" `
    -D CMAKE_C_FLAGS="/TC" `
    -D CMAKE_CXX_FLAGS="/TC"
cmake --build "$DepsPath\\reai-r2\\Build" --config Release
cmake --install "$DepsPath\\reai-r2\\Build" --prefix "$InstallPath" --config Release
Write-Host "✅ reai-r2 installed"

Remove-Item -Recurse -Force "$BuildDir"

Write-Host "\n🎉 Installation complete!"
Write-Host "👉 Contact developers: https://github.com/revengai/reai-r2"
Write-Host "📌 Add to your PATH:"
Write-Host "$InstallPath"
Write-Host "$InstallPath\\bin"
Write-Host "$InstallPath\\lib"
