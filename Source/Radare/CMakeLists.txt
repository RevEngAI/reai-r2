# RevEngAI Radare Plugin Sources
# Author    : Siddharth Mishra (admin@brightprogrammer.in)
# Date      : 02/11/2024
# Copyright : Copyright (c) RevEngAI. All Rights Reserved.

# Generate command descriptors
# add_subdirectory(CmdGen)

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

# Libraries needs to be searched here to be linked properly
find_package(CURL REQUIRED)

# Radare only accepts shared libraries for plugins
add_library(reai_radare MODULE SHARED ${ReaiR2PluginSources})
add_dependencies(reai_radare generate_cmd_desc)
target_include_directories(reai_radare PUBLIC ${Radare_INCLUDE_DIRS})
target_link_directories(reai_radare PUBLIC ${Radare_LIBRARY_DIRS})
target_link_libraries(
  reai_radare 
  PUBLIC
  ${Radare_LIBRARIES}
  ${CURL_LIBRARIES}
  reai
)

# Custom command to clean generated files when 'make clean' is called
set_property(DIRECTORY APPEND PROPERTY 
    ADDITIONAL_CLEAN_FILES 
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdDesc.h 
    ${CMAKE_CURRENT_SOURCE_DIR}/CmdDesc.c
)

# install the built binaries to radare2's plugin directory
install(TARGETS reai_radare DESTINATION "${RADARE_INSTALL_PLUGDIR}")
