/**
 * @file : CmdHandlers.h
 * @date : 3rd December 2024
 * @author : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright: Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

#ifndef REAI_RADARE_CMD_HANDLERS_H
#define REAI_RADARE_CMD_HANDLERS_H

#include <Reai/Types.h>
#include <r_core.h>

// RE
// RE?
R_IPI RCmdStatus reai_show_help_handler (RCore* core, int argc, const char** argv);
// "REi"
R_IPI RCmdStatus reai_plugin_initialize_handler (RCore* core, int argc, const char** argv);
// "REm"
R_IPI RCmdStatus reai_list_available_ai_models_handler (RCore* core, int argc, const char** argv);
// "REh"
R_IPI RCmdStatus reai_health_check_handler (RCore* core, int argc, const char** argv);
// "REu"
R_IPI RCmdStatus reai_upload_bin_handler (RCore* core, int argc, const char** argv);
// "REa"
R_IPI RCmdStatus reai_create_analysis_handler (RCore* core, int argc, const char** argv);
// "REau"
R_IPI RCmdStatus reai_ann_auto_analyze_handler (RCore* core, int argc, const char** argv);
// "REap"
R_IPI RCmdStatus reai_apply_existing_analysis_handler (RCore* core, int argc, const char** argv);
// "REfl"
R_IPI RCmdStatus reai_get_basic_function_info_handler (RCore* core, int argc, const char** argv);
// "REfr"
R_IPI RCmdStatus reai_rename_function_handler (RCore* core, int argc, const char** argv);
// "REfs"
R_IPI RCmdStatus reai_function_similarity_search_handler (RCore* core, int argc, const char** argv);
// "REart"
R_IPI RCmdStatus reai_show_revengai_art_handler (RCore* core, int argc, const char** argv);

#endif // REAI_RADARE_CMD_HANDLERS_H
