# RevEngAI Radare Plugin Sources
# Author    : Siddharth Mishra (admin@brightprogrammer.in)
# Date      : 02/11/2024
# Copyright : Copyright (c) RevEngAI. All Rights Reserved.

# Generate command descriptors
# add_subdirectory(CmdGen)

# main plugin library and sources
set(ReaiR2PluginSources "Radare.c" "CmdHandlers.c" "Table.c" "../Plugin.c")

# Radare only accepts shared libraries for plugins
add_library(reai_radare MODULE SHARED ${ReaiR2PluginSources})
target_include_directories(reai_radare PUBLIC ${Radare_INCLUDE_DIRS})
target_link_directories(reai_radare PUBLIC ${Radare_LIBRARY_DIRS})
target_link_libraries(reai_radare PUBLIC ${Radare_LIBRARIES} ${CREAIT_LIBRARIES})

# install the built binaries to cutter's plugin directory
install(TARGETS reai_radare DESTINATION "${RADARE_INSTALL_PLUGDIR}")
