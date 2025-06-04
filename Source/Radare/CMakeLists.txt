# RevEngAI Radare Plugin Sources
# Author    : Siddharth Mishra (admin@brightprogrammer.in)
# Date      : 02/11/2024
# Copyright : Copyright (c) RevEngAI. All Rights Reserved.

# Generate command descriptors
# add_subdirectory(CmdGen)

# Get Git tag
execute_process(COMMAND git describe --tags --abbrev=0
                OUTPUT_VARIABLE GIT_TAG
                OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_QUIET)

# Get Git branch
execute_process(COMMAND git rev-parse --abbrev-ref HEAD
                OUTPUT_VARIABLE GIT_BRANCH
                OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_QUIET)

# Get Git commit hash (short)
execute_process(COMMAND git rev-parse --short HEAD
                OUTPUT_VARIABLE GIT_COMMIT
                OUTPUT_STRIP_TRAILING_WHITESPACE
                ERROR_QUIET)

# Compose version string
set(PLUGIN_VERSION "${GIT_TAG}-${GIT_BRANCH}-${GIT_COMMIT}")

# Optionally print
message(STATUS "Plugin version: ${PLUGIN_VERSION}")

# Generate a version header
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/PluginVersion.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/PluginVersion.h
    @ONLY
)

# Custom command to generate CmdDesc.h and CmdDesc.c during configure step
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/CmdDesc.h ${CMAKE_CURRENT_SOURCE_DIR}/CmdDesc.c
    COMMAND ${CMAKE_COMMAND} -E echo "Generating command descriptors..."
    COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_SOURCE_DIR}/Scripts/generate_cmd_desc.py
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Generating CmdDesc.h and CmdDesc.c from YAML command descriptions"
    VERBATIM
)

# Add a custom target that depends on the generated files
add_custom_target(generate_cmd_desc
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/CmdDesc.h ${CMAKE_CURRENT_SOURCE_DIR}/CmdDesc.c
)

# main plugin library and sources
set(ReaiR2PluginSources "Radare.c" "CmdHandlers.c" "../Plugin.c" "CmdDesc.c")

find_package(Creait REQUIRED)
message("CREAIT INCLUDE DIRS = ${CREAIT_INCLUDE_DIRS}")
message("CREAIT LIBS = ${CREAIT_LIBRARIES}")

# Radare only accepts shared libraries for plugins
add_library(reai_radare MODULE SHARED ${ReaiR2PluginSources})
add_dependencies(reai_radare generate_cmd_desc)
target_include_directories(reai_radare PUBLIC ${Radare_INCLUDE_DIRS} ${CREAIT_INCLUDE_DIRS})
target_link_directories(reai_radare PUBLIC ${Radare_LIBRARY_DIRS})
target_link_libraries(
  reai_radare 
  PUBLIC
  ${Radare_LIBRARIES}
  ${CREAIT_LIBRARIES}
)
set_target_properties(
    reai_radare PROPERTIES
    INSTALL_RPATH "$ENV{HOME}/.local/lib"
    BUILD_RPATH "${CMAKE_BINARY_DIR}/Source/Radare"
)

# Custom command to clean generated files when 'make clean' is called
set_property(DIRECTORY APPEND PROPERTY 
    ADDITIONAL_CLEAN_FILES 
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdDesc.h 
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdDesc.c
)

# install the built binaries to radare2's plugin directory
install(TARGETS reai_radare DESTINATION "${RADARE_INSTALL_PLUGDIR}")
