# RevEngAI Iaito Plugin Sources
# Author    : Siddharth Mishra (admin@brightprogrammer.in)
# Date      : 02/11/2024
# Copyright : Copyright (c) RevEngAI. All Rights Reserved.

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

find_package(CURL REQUIRED)

set(CREAIT_LIBRARIES ${CURL_LIBRAIRES} CURL::libcurl reai cjson toml)

add_subdirectory(Radare)

# if(NOT BUILD_RIZIN_PLUGIN_ONLY)
#   add_subdirectory(Iaito)
# endif()
