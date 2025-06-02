#!/bin/bash

InstallPath="$HOME/.local"
echo "Assuming install path $InstallPath"

# Remove installed headers
rm -rf "$InstallPath/include/Reai"

# Remove installed libraries
rm -rf "$InstallPath/lib/libreai*"

# Remove plugin
OS="$(uname)"
EXTENSION=""
if [[ "$OS" == "Darwin" ]]; then
    EXTENSION="dylib"
elif [[ "$OS" == "Linux" ]]; then
    EXTENSION="so"
fi
rm "$(radare2 -H R2_USER_PLUGINS)/libreai_radare.$EXTENSION"
