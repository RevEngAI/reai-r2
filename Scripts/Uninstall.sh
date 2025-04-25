#!/bin/bash

InstallPath="~/.local"
echo "Assuming install path $InstallPath"

# Remove installed headers
sudo rm -rf "$InstallPath/include/Reai"
sudo rm -rf "$InstallPath/include/cjson"
sudo rm "$InstallPath/include/toml.h"

# Remove installed libraries
sudo rm -rf "$InstallPath/lib/libreai*"
sudo rm -rf "$InstallPath/lib/libcjson*"
sudo rm -rf "$InstallPath/lib/libtoml*"
sudo rm -rf "$InstallPath/lib/cmake/cJSON"

# Remove plugin
sudo rm "$(r2 -H R2_USER_PLUGINS)/libreai_radare.dylib"
