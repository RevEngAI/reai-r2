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
// "REac"
R_IPI RCmdStatus reai_create_analysis_private_handler (RCore* core, int argc, const char** argv);
// "REacp"
R_IPI RCmdStatus reai_create_analysis_public_handler (RCore* core, int argc, const char** argv);
// "REau"
R_IPI RCmdStatus reai_ann_auto_analyze_handler (RCore* core, int argc, const char** argv);
// "REaud"
R_IPI RCmdStatus
    reai_ann_auto_analyze_restrict_debug_handler (RCore* core, int argc, const char** argv);
// "REap"
R_IPI RCmdStatus reai_apply_existing_analysis_handler (RCore* core, int argc, const char** argv);
// "REa"
R_IPI RCmdStatus reai_analysis_cmd_group_help_handler (RCore* core, int argc, const char** argv);
// "REbl"
R_IPI RCmdStatus reai_binary_link_handler (RCore* core, int argc, const char** argv);
// "REbsn"
R_IPI RCmdStatus reai_binary_search_by_name_handler (RCore* core, int argc, const char** argv);
// "REbsh"
R_IPI RCmdStatus reai_binary_search_handler (RCore* core, int argc, const char** argv);
// "REbs"
R_IPI RCmdStatus reai_binary_search_by_sha256_handler (RCore* core, int argc, const char** argv);
// "REb"
R_IPI RCmdStatus reai_binary_cmd_group_help_handler (RCore* core, int argc, const char** argv);
// "REcl"
R_IPI RCmdStatus reai_collection_link_handler (RCore* core, int argc, const char** argv);
// "REcat"
R_IPI RCmdStatus
    reai_collection_basic_info_asc_time_handler (RCore* core, int argc, const char** argv);
// "REcao"
R_IPI RCmdStatus
    reai_collection_basic_info_asc_owner_handler (RCore* core, int argc, const char** argv);
// "REcan"
R_IPI RCmdStatus
    reai_collection_basic_info_asc_name_handler (RCore* core, int argc, const char** argv);
// "REcam"
R_IPI RCmdStatus
    reai_collection_basic_info_asc_model_handler (RCore* core, int argc, const char** argv);
// "REcas"
R_IPI RCmdStatus
    reai_collection_basic_info_asc_size_handler (RCore* core, int argc, const char** argv);
// "REca"
R_IPI RCmdStatus reai_collection_basic_info_asc_cmd_group_help_handler (
    RCore*       core,
    int          argc,
    const char** argv
);
// "REcdt"
R_IPI RCmdStatus
    reai_collection_basic_info_desc_time_handler (RCore* core, int argc, const char** argv);
// "REcdo"
R_IPI RCmdStatus
    reai_collection_basic_info_desc_owner_handler (RCore* core, int argc, const char** argv);
// "REcdn"
R_IPI RCmdStatus
    reai_collection_basic_info_desc_name_handler (RCore* core, int argc, const char** argv);
// "REcdm"
R_IPI RCmdStatus
    reai_collection_basic_info_desc_model_handler (RCore* core, int argc, const char** argv);
// "REcds"
R_IPI RCmdStatus
    reai_collection_basic_info_desc_size_handler (RCore* core, int argc, const char** argv);
// "REcd"
R_IPI RCmdStatus reai_collection_basic_info_desc_cmd_group_help_handler (
    RCore*       core,
    int          argc,
    const char** argv
);
// "REcsc"
R_IPI RCmdStatus
    reai_collection_search_by_collection_name_handler (RCore* core, int argc, const char** argv);
// "REcsb"
R_IPI RCmdStatus
    reai_collection_search_by_binary_name_handler (RCore* core, int argc, const char** argv);
// "REcsh"
R_IPI RCmdStatus
    reai_collection_search_by_binary_sha256_handler (RCore* core, int argc, const char** argv);
// "REcs"
R_IPI RCmdStatus reai_collection_search_handler (RCore* core, int argc, const char** argv);
// "REc"
R_IPI RCmdStatus reai_collection_cmd_group_help_handler (RCore* core, int argc, const char** argv);
// "REd"
R_IPI RCmdStatus reai_ai_decompile_handler (RCore* core, int argc, const char** argv);
// "REfl"
R_IPI RCmdStatus reai_get_basic_function_info_handler (RCore* core, int argc, const char** argv);
// "REfr"
R_IPI RCmdStatus reai_rename_function_handler (RCore* core, int argc, const char** argv);
// "REfs"
R_IPI RCmdStatus reai_function_similarity_search_handler (RCore* core, int argc, const char** argv);
// "REfsd"
R_IPI RCmdStatus reai_function_similarity_search_restrict_debug_handler (
    RCore*       core,
    int          argc,
    const char** argv
);
// "REf"
R_IPI RCmdStatus reai_function_cmd_group_help_handler (RCore* core, int argc, const char** argv);
// "REart"
R_IPI RCmdStatus reai_show_revengai_art_handler (RCore* core, int argc, const char** argv);

#endif // REAI_RADARE_CMD_HANDLERS_H
