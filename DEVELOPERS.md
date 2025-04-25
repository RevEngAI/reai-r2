# Developers Documentation

# Developing Plugin In Windows

- The `BuildOnWindows.ps1` script not only builds the whole plugin, it also sets up all required dependencies for
  future builds. You just run the script once and then later use parts of it to setup your development environment,
  everytime you want to build either `creait` or `reai-r2`
- My current workflow is :
  - Clone the `reai-r2` repo, or do a git pull to get latest changes.
  - Change into `reai-r2` directory using `cd reai-r2`.
  - Build the plugin using `BuildOnWindows.ps1` script
  - Update development environment by executing the following in current shell (where you want to subsequent builds)
  ```ps1
  $InstallPath = "~\\.local\\RevEngAI\\Radare2\\Install"
  $env:Path = $env:Path + ";$InstallPath;$InstallPath\\bin;$InstallPath\\lib"
  ```
  - Go to cloned `reai-r2` repo, and then use the cmake configure, build and install commands from `BuildOnWindows.ps1` script to build the plugin with your latest changes
  - Configure
  ```ps1
  # Build reai-r2
  cmake -A x64 -B "Build" `
  -G "Visual Studio 17 2022" `
  -D CMAKE_PREFIX_PATH="$InstallPath" `
  -D CMAKE_INSTALL_PREFIX="$InstallPath" `
  -D CMAKE_C_FLAGS="/TC" `
  -D CMAKE_CXX_FLAGS="/TC" `
  -D CMAKE_POLICY_VERSION_MINIMUM="3.5"
  ```
  - Build
  ```ps1
  cmake --build Build --config Release
  ```
  - Clean
  ```ps1
  cmake --build Build --config Release --target clean
  ```
  - Install
  ```ps1
  cmake --install Build --prefix "$InstallPath" --config Release
  ```

Make sure when you update `creait` code, you build and install it in the same way.
