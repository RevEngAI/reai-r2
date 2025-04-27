#!/bin/bash

InstallPath="$HOME/.local"
echo "Dependencies will be installed at prefix $InstallPath"

cd /tmp

rm -rf /tmp/reai-r2
rm -rf /tmp/creait
rm -rf /tmp/tomlc99
rm -rf /tmp/cJSON

git clone https://github.com/revengai/reai-r2
git clone https://github.com/revengai/creait
git clone https://github.com/brightprogrammer/tomlc99
git clone https://github.com/DaveGamble/cJSON

# Build and install cjson
cmake -S "/tmp/cJSON" \
    -B "/tmp/cJSON/Build" \
    -D ENABLE_CUSTOM_COMPILER_FLAGS=OFF \
    -D CMAKE_PREFIX_PATH="$InstallPath" \
    -D CMAKE_INSTALL_PREFIX="$InstallPath" \
    -DCMAKE_POLICY_VERSION_MINIMUM="3.5"
cmake --build "/tmp/cJSON/Build" --config Release
sudo cmake --install "/tmp/cJSON/Build" --prefix "$InstallPath" --config Release

# Build and install tomlc99 
cmake -S "/tmp/tomlc99" \
    -B "/tmp/tomlc99/Build" \
    -D CMAKE_PREFIX_PATH="$InstallPath" \
    -D CMAKE_INSTALL_PREFIX="$InstallPath" \
    -DCMAKE_POLICY_VERSION_MINIMUM="3.5"
cmake --build "/tmp/tomlc99/Build" --config Release
sudo cmake --install "/tmp/tomlc99/Build" --prefix "$InstallPath" --config Release

# Build and install creait
cmake -S "/tmp/creait" \
    -B "/tmp/creait/Build" \
    -D CMAKE_PREFIX_PATH="$InstallPath" \
    -D CMAKE_INSTALL_PREFIX="$InstallPath" \
    -D BUILD_SHARED_LIBS=OFF \
    -DCMAKE_POLICY_VERSION_MINIMUM="3.5"
cmake --build "/tmp/creait/Build" --config Release
sudo cmake --install "/tmp/creait/Build" --prefix "$InstallPath" --config Release

# Build reai-r2
cmake -S "/tmp/reai-r2" \
    -B "/tmp/reai-r2/Build" \
    -D CMAKE_PREFIX_PATH="$InstallPath" \
    -D CMAKE_INSTALL_PREFIX="$InstallPath" \
    -D CMAKE_POLICY_VERSION_MINIMUM="3.5"
cmake --build "/tmp/reai-r2/Build" --config Release
sudo cmake --install "/tmp/reai-r2/Build" --prefix "$InstallPath" --config Release

sudo chown -R $USER "$(r2 -H R2_USER_PLUGINS)/libreai_radare.dylib" 
