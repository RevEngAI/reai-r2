# RevEngAI Iaito Plugin
# Author    : Siddharth Mishra (admin@brightprogrammer.in)
# Date      : 02/11/2024
# Copyright : Copyright (c) RevEngAI. All Rights Reserved.

cmake_minimum_required(VERSION 3.25)
project(reai-r2 VERSION 0 LANGUAGES C CXX)

include(FetchContent)
find_package(PkgConfig REQUIRED)

option(BUILD_SHARED_LIBS "Build using shared libraries" OFF)
option(BUILD_RADARE_PLUGIN_ONLY "Whether to build rizin plugin only" ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ----------------------------------------
# ---- LGPL-3.0 LICENSED REGION BEGIN ----
# ----------------------------------------

# Minimal required version
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build parameters.
if(MSVC) # Windows
    # Disable warnings (there are too many of them, including warnings from
    # third-party libraries, which cannot be selectively disabled when using MSVC).
    string(REGEX REPLACE "/W[0-4]" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W0")

    # Disable the min() and max() macros to prevent errors when using e.g.
    # std::numeric_limits<...>::max()
    # (http://stackoverflow.com/questions/1904635/warning-c4003-and-errors-c2589-and-c2059-on-x-stdnumeric-limitsintmax).
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /DNOMINMAX")
elseif(UNIX) # Linux or macOS
    # Set C flags
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
    else()
        # Compile flags
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -Wall -Wextra")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -Wall -Wextra -Wno-error")
    endif()
else()
    message(FATAL_ERROR "Unsupported system type: ${CMAKE_SYSTEM_NAME}")
endif()

# On Linux and macOS, set RPATH relative to the origin of the installed
# executables (i.e. relative to the bin directory). This allows us to move the
# installation directory into a different location after installation, which is
# useful e.g. when the installation is performed on one machine but we want to
# run the executables on a different machine.
#
# On Windows, there is no need to set anything as DLLs are installed into the
# bin directory, where they are automatically picked up by executables.
#
# For more details, see
#  - https://github.com/avast/retdec/issues/77
#  - https://cmake.org/Wiki/CMake_RPATH_handling
if(APPLE)
        set(CMAKE_INSTALL_RPATH "@executable_path/../lib")
        list(APPEND CMAKE_MODULE_PATH "/Applications/Iaito.app/Contents/Resources/lib/cmake")
elseif(UNIX)
        set(CMAKE_INSTALL_RPATH "$ORIGIN/../lib")
endif()
message(STATUS "CMake module path: ${CMAKE_MODULE_PATH}")
# --------------------------------------
# ---- LGPL-3.0 LICENSED REGION END ----
# --------------------------------------


# This will give us path where plugins are installed on this sytem, also libraries to be linked.
pkg_check_modules(Radare REQUIRED r_core)

# Get user plugin storage path 
execute_process(
    COMMAND r2 -H R2_USER_PLUGINS
    OUTPUT_VARIABLE RADARE_INSTALL_PLUGDIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

# TODO:
# if(NOT BUILD_RADARE_PLUGIN_ONLY)
#     pkg_check_modules(Iaito REQUIRED) 
#     set(IAITO_INSTALL_PLUGDIR "${Iaito_USER_PLUGINDIR}" CACHE STRING "Directory to install Iaito plugin into")
# endif()

add_subdirectory(Source)
