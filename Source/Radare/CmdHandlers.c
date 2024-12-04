/**
 * @file : CmdHandlers.c
 * @date : 3rd December 2024
 * @author : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright: Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

#include <Radare/CmdHandlers.h>
#include <Reai/Common.h>

#include <Reai/AnalysisInfo.h>
#include <Reai/AnnFnMatch.h>
#include <Reai/Api/Api.h>
#include <Reai/Api/Reai.h>
#include <Reai/Api/Request.h>
#include <Reai/Api/Response.h>
#include <Reai/Common.h>
#include <Reai/Config.h>
#include <Reai/FnInfo.h>
#include <Reai/Log.h>
#include <Reai/Types.h>

/* radare */
#include <r_anal.h>
#include <r_cmd.h>
#include <r_cons.h>
#include <r_list.h>
#include <r_util/r_assert.h>
#include <r_util/r_file.h>
#include <r_util/r_num.h>
#include <r_util/r_table.h>
#include <r_vector.h>

/* local includes */
#include <Plugin.h>

R_IPI RCmdStatus reai_show_help_handler (RCore* core, int argc, const char** argv) {
    UNUSED (core && argc);

    // TODO: colorize output
    if (!r_str_startswith (argv[0], "RE?")) {
        DISPLAY_ERROR ("ERROR: Unknown command %s.", argv[0]);
        DISPLAY_ERROR ("ERROR: Showing help for command group \"RE\"");
    }

    r_cons_println (
        "Usage: RE<imhua?>   # RevEngAI Plugin Commands\n"
        "| REi <host> <api_key>    # Initialize plugin config.\n"
        "| REm                     # Get all available models for analysis.\n"
        "| REh                     # Check connection status with RevEngAI servers.\n"
        "| REu                     # Upload currently loaded binary to RevEngAI servers.\n"
        "| REa <prog_name> <cmd_line_args> <ai_model> # Upload and analyse currently loaded "
        "binary.\n"
        "| REau[?] <min_confidence> # Auto analyze binary functions using ANN and perform batch "
        "rename.\n"
        "| REap <bin_id>           # Apply already existing RevEng.AI analysis to this binary.\n"
        "| REfl[?]                 # Get & show basic function info for selected binary.\n"
        "| REfr <fn_addr> <new_name> # Rename function with given function id to given name.\n"
        "| REfs <function_name> <min_confidence> # RevEng.AI ANN functions similarity search.\n"
        "| REart                   # Show RevEng.AI ASCII art.\n"
    );

    return R_CMD_STATUS_OK;
}

#define ASK_QUESTION(res, default, msg)                                                            \
    do {                                                                                           \
        Char input = 0;                                                                            \
        r_cons_printf ("%s [%c/%c] : ", msg, (default ? 'Y' : 'y'), (!default ? 'N' : 'n'));       \
        r_cons_flush();                                                                            \
        while (input != 'n' && input != 'N' && input != 'Y' && input != 'y') {                     \
            input = r_cons_readchar();                                                             \
        }                                                                                          \
        res = (input == 'y' || input == 'Y');                                                      \
        r_cons_newline();                                                                          \
    } while (0)

/**
 * REi
 *
 * @b To be used on first setup of radare plugin.
 *
 * This will create a new config file everytime it's called with correct arguments.
 * Requires a restart of radare plugin after issue.
 * */
R_IPI RCmdStatus reai_plugin_initialize_handler (RCore* core, int argc, const char** argv) {
    REAI_LOG_TRACE ("[CMD] config initialize");
    if (argc < 3 || r_str_startswith (argv[0], "REi?")) {
        DISPLAY_ERROR (
            "USAGE : REi <host> <api_key>\n"
            "A valid host and api-key is required.\n"
            "Example: REi https://api.reveng.ai/v1 XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
        );
        return R_CMD_STATUS_ERROR;
    }

    CString host    = argv[1];
    CString api_key = argv[2];

    /* attempt saving config */
    if (reai_plugin_save_config (host, api_key)) {
        /* try to reinit config after creating config */
        if (!reai_plugin_init (core)) {
            DISPLAY_ERROR ("Failed to init plugin after creating a new config.");
            return R_CMD_STATUS_ERROR;
        }
    } else {
        DISPLAY_ERROR ("Failed to save config.");
        return R_CMD_STATUS_ERROR;
    }

    return R_CMD_STATUS_OK;
}

/**
 * "REm"
 * */
R_IPI RCmdStatus reai_list_available_ai_models_handler (RCore* core, int argc, const char** argv) {
    REAI_LOG_TRACE ("[CMD] list available ai models");
    UNUSED (core);
    if (argc < 1 || r_str_startswith (argv[0], "REm?")) {
        DISPLAY_ERROR (
            "USAGE: REm\nList names of available AI models that can be used to create analysis"
        );
        return R_CMD_STATUS_ERROR;
    }

    if (reai_ai_models()) {
        REAI_VEC_FOREACH (reai_ai_models(), model, { r_cons_println (*model); });
        return R_CMD_STATUS_OK;
    } else {
        DISPLAY_ERROR ("Seems like background worker failed to get available AI models.");
        return R_CMD_STATUS_ERROR;
    }
}

/**
 * "REh"
 *
 * @b Perform an auth-check api call to check connection.
 * */
R_IPI RCmdStatus reai_health_check_handler (RCore* core, int argc, const char** argv) {
    REAI_LOG_TRACE ("[CMD] health check");
    UNUSED (core);
    if (argc < 1 || r_str_startswith (argv[0], "REh?")) {
        DISPLAY_ERROR (
            "USAGE: REh\nPerform health check by validating host API endpoint and API key."
        );
        return R_CMD_STATUS_ERROR;
    }

    if (!reai_auth_check (reai(), reai_response(), reai_config()->host, reai_config()->apikey)) {
        DISPLAY_ERROR ("Authentication failed.");
        return R_CMD_STATUS_ERROR;
    }

    r_cons_println ("OK");
    return R_CMD_STATUS_OK;
}

/**
 * "REa"
 *
 * NOTE: The default way to get ai model would be to use "REm" command.
 *       Get list of all available AI models and then use one to create a new analysis.
 * */
R_IPI RCmdStatus reai_create_analysis_handler (RCore* core, int argc, const char** argv) {
    REAI_LOG_TRACE ("[CMD] create analysis");
    if (argc < 4 || r_str_startswith (argv[0], "REa?")) {
        DISPLAY_ERROR (
            "USAGE : REa <prog_name> <cmd_line_args> <ai_model>\n"
            "Example : REa ffmpeg \"-i input.mp4 -vf -c:v gif output.gif\" binnet-0.4-x86-linux\n"
            "Example : REa emacs \"\" binnet-0.4-x86-linux"
        );
        return R_CMD_STATUS_ERROR;
    }
    REAI_LOG_TRACE ("[CMD] create analysis");

    Bool is_private;
    ASK_QUESTION (is_private, true, "Create private analysis?");

    CString prog_name    = argv[1];
    CString cmdline_args = argv[2];
    CString ai_model     = argv[3];

    // prog name and ai model must not be null atleast
    if (!prog_name || !ai_model) {
        // print usage
        return reai_create_analysis_handler (NULL, 0, NULL);
    }

    if (reai_plugin_create_analysis_for_opened_binary_file (
            core,
            prog_name,
            cmdline_args,
            ai_model,
            is_private
        )) {
        DISPLAY_INFO ("Analysis created sucessfully");
        return R_CMD_STATUS_OK;
    }

    DISPLAY_ERROR ("Failed to create analysis");

    return R_CMD_STATUS_ERROR;
}

/**
 * "REap"
 * */
R_IPI RCmdStatus reai_apply_existing_analysis_handler (RCore* core, int argc, const char** argv) {
    REAI_LOG_TRACE ("[CMD] apply existing analysis");
    if (argc < 2 || r_str_startswith (argv[0], "REap?")) {
        DISPLAY_ERROR ("USAGE : REap <bin_id>");
        return R_CMD_STATUS_ERROR;
    }

    Bool rename_unknown_only;
    ASK_QUESTION (rename_unknown_only, true, "Apply analysis only to unknown functions?");

    if (reai_plugin_apply_existing_analysis (
            core,
            r_num_get (core->num, argv[1]), // binary id
            !rename_unknown_only            // apply analysis to all?
        )) {
        DISPLAY_INFO ("Existing analysis applied sucessfully");
        return R_CMD_STATUS_OK;
    }

    DISPLAY_INFO ("Failed to apply existing analysis");
    return R_CMD_STATUS_ERROR;
}

/**
 * REau
 *
 * @b Perform a Batch Symbol ANN request with current binary ID and
 *    automatically rename all methods.
 * */
R_IPI RCmdStatus reai_ann_auto_analyze_handler (RCore* core, int argc, const char** argv) {
    REAI_LOG_TRACE ("[CMD] ANN Auto Analyze Binary");
    if (argc < 2 || r_str_startswith (argv[0], "REau?")) {
        DISPLAY_ERROR ("USAGE : REau <min_confidence>");
        return R_CMD_STATUS_ERROR;
    }

    // NOTE: this is static here. I don't think it's a good command line option to have
    // Since user won't know about this when issuing the auto-analysis command.
    // Just set it to a large enough value to get good suggestions
    const Size max_results_per_function = 10;

    Uint32 min_confidence = r_num_get (core->num, argv[1]);
    min_confidence        = min_confidence > 100 ? 100 : min_confidence;

    Bool debug_mode, rename_unknown_only;
    ASK_QUESTION (debug_mode, true, "Enable debug symbol suggestions?");
    ASK_QUESTION (rename_unknown_only, true, "Rename unknown functions only?");

    if (reai_plugin_auto_analyze_opened_binary_file (
            core,
            max_results_per_function,
            min_confidence / 100.f,
            debug_mode,
            !rename_unknown_only // apply_to_all = !rename_unknown
        )) {
        DISPLAY_INFO ("Auto-analysis completed successfully.");
        return R_CMD_STATUS_OK;
    } else {
        DISPLAY_ERROR (
            "Failed to perform RevEng.AI auto-analysis (apply analysis results in radare/cutter)"
        );
        return R_CMD_STATUS_ERROR;
    }
}

/* R_IPI RCmdStatus reai_upload_bin_handler (RCore* core, int argc, const char** argv) { */
/*     UNUSED (argc && argv); */
/*     REAI_LOG_TRACE ("[CMD] upload binary"); */
/**/
/*     if (reai_plugin_upload_opened_binary_file (core)) { */
/*         DISPLAY_ERROR ("File upload successful."); */
/*         return R_CMD_STATUS_OK; */
/*     } else { */
/*         DISPLAY_ERROR ("File upload failed."); */
/*         return R_CMD_STATUS_ERROR; */
/*     } */
/* } */

/**
 * "REfl"
 *
 * @b Get information about all functions detected by the AI model from
 *    RevEng.AI servers.
 *
 * NOTE: This works just for currently opened binary file. If binary
 *       file is not opened, this will return with `R_CMD_STATUS_ERROR`.
 *       If analysis for binary file does not exist then this will again return
 *       with an error.
 * */
R_IPI RCmdStatus reai_get_basic_function_info_handler (RCore* core, int argc, const char** argv) {
    REAI_LOG_TRACE ("[CMD] get basic function info");
    if (argc < 2 || r_str_startswith (argv[0], "REfl?")) {
        DISPLAY_ERROR (
            "USAGE : REfl\nList all functions detected/provided to/by RevEngAI analysis.\nExisting "
            "attached analysis is required. Either create a new analysis or apply an existing one."
        );
        return R_CMD_STATUS_ERROR;
    }

    /* get file path of opened binary file */
    CString opened_file = reai_plugin_get_opened_binary_file_path (core);
    if (!opened_file) {
        DISPLAY_ERROR ("No binary file opened.");
        return R_CMD_STATUS_ERROR;
    }

    /* get binary id of opened file */
    ReaiBinaryId binary_id = reai_binary_id();
    if (!binary_id) {
        DISPLAY_ERROR (
            "Please apply existing analysis or create a new one. Cannot get function info from "
            "RevEng.AI without an existing analysis."
        );
        return R_CMD_STATUS_ERROR;
    }

    /* get analysis status from db after an update and check for completion */
    ReaiAnalysisStatus analysis_status = reai_plugin_get_analysis_status_for_binary_id (binary_id);
    if (analysis_status != REAI_ANALYSIS_STATUS_COMPLETE) {
        DISPLAY_ERROR (
            "Analysis not yet complete. Current status = \"%s\"\n",
            reai_analysis_status_to_cstr (analysis_status)
        );
        return R_CMD_STATUS_OK; // It's ok, check again after sometime
    }

    /* make request to get function infos */
    ReaiFnInfoVec* fn_infos = reai_get_basic_function_info (reai(), reai_response(), binary_id);
    if (!fn_infos) {
        DISPLAY_ERROR ("Failed to get function info from RevEng.AI servers.");
        return R_CMD_STATUS_ERROR;
    }

    // prepare table and print info
    RTable* table = r_table_new ("Function List");
    if (!table) {
        DISPLAY_ERROR ("Failed to create the table.");
        return R_CMD_STATUS_ERROR;
    }

    r_table_set_columnsf (table, "nsxx", "function_id", "name", "vaddr", "size");
    REAI_VEC_FOREACH (fn_infos, fn, {
        r_table_add_rowf (table, "nsxx", fn->id, fn->name, fn->vaddr, fn->size);
    });

    CString table_str = r_table_tofancystring (table);
    if (!table_str) {
        DISPLAY_ERROR ("Failed to convert table to string.");
        r_table_free (table);
        return R_CMD_STATUS_ERROR;
    }

    r_cons_println (table_str);

    FREE (table_str);
    r_table_free (table);

    return R_CMD_STATUS_OK;
}

/**
 * "REfr"
 *
 * @b Rename function with given function id to given new name.
 * */
R_IPI RCmdStatus reai_rename_function_handler (RCore* core, int argc, const char** argv) {
    REAI_LOG_TRACE ("[CMD] rename function");
    if (argc < 3 || r_str_startswith (argv[0], "REfr?")) {
        DISPLAY_ERROR ("USAGE : REfr <fn_addr> <new_name>");
        return R_CMD_STATUS_ERROR;
    }

    if (!core->anal) {
        DISPLAY_ERROR (
            "Seems like radare analysis is not performed yet. Cannot get function at given "
            "address. "
            "Cannot rename function at given address."
        );
        return R_CMD_STATUS_ERROR;
    }

    Uint64  fn_addr  = r_num_get (core->num, argv[1]);
    CString new_name = argv[2];

    // get function at given address
    RAnalFunction* fn = r_anal_get_function_at (core->anal, fn_addr);
    if (!fn) {
        DISPLAY_ERROR ("Function with given name not found.");
        return R_CMD_STATUS_ERROR;
    }

    ReaiFunctionId fn_id = reai_plugin_get_function_id_for_radare_function (core, fn);
    if (!fn_id) {
        DISPLAY_ERROR ("Failed to get function id of function with given name.");
        return R_CMD_STATUS_ERROR;
    }

    /* perform rename operation */
    if (reai_rename_function (reai(), reai_response(), fn_id, new_name)) {
        r_anal_function_rename (fn, new_name);
    } else {
        DISPLAY_ERROR ("Failed to rename the function. Please check the function ID and new name.");
        return R_CMD_STATUS_ERROR;
    }

    return R_CMD_STATUS_OK;
}

/**
 * "REfs"
 *
 * @b Similar function name search 
 * */
R_IPI RCmdStatus
    reai_function_similarity_search_handler (RCore* core, int argc, const char** argv) {
    REAI_LOG_TRACE ("[CMD] Function similarity search");
    if (argc < 3 || r_str_startswith (argv[0], "REfs?")) {
        DISPLAY_ERROR ("USAGE : REfs <function_name> <min_confidence>");
        return R_CMD_STATUS_ERROR;
    }

    // NOTE: hardcoded because it does not look good in command arguments
    // just to increase simplicity of command
    Uint32 max_results_count = 20;

    // Parse command line arguments
    CString function_name  = argv[1];
    Float32 min_confidence = r_num_math (core->num, argv[2]);

    Bool debug_mode;
    ASK_QUESTION (debug_mode, true, "Enable debug symbol suggestions?");

    if (!reai_plugin_search_and_show_similar_functions (
            core,
            function_name,
            max_results_count,
            min_confidence,
            debug_mode
        )) {
        DISPLAY_ERROR ("Failed to get similar functions search result.");
        return R_CMD_STATUS_ERROR;
    }

    return R_CMD_STATUS_OK;
}

R_IPI RCmdStatus reai_show_revengai_art_handler (RCore* core, int argc, const char** argv) {
    UNUSED (core && argc && argv);

    r_cons_println (
        "\n"
        "                             \n"
        "                             \n"
        "                             \n"
        "                             \n"
        "                             \n"
        "                             \n"
        "                             \n"
        "                             \n"
        ":::::::::::        :::::::::::                                                            "
        "      \n"
        "::    ::::::      ::::    ::::             %%%%%%%%%%%%%                                  "
        "      %%%%%%%%%%%%%%%                            \n"
        "::    :::::::    :::::    ::::            %%%%%%%%%%%%%%%                                 "
        "      %%%%%%%%%%%%%%%                                %%%%%@   \n"
        "::::::::::::::::::::::::::::::           %%%%%%%    %%%%%                                 "
        "      %%%%%                                          %%%%%%  \n"
        ":::::::::   ::::   :::::::::::           %%%%%%     %%%%%     @%%%%%%%%%%    %%%%%@    "
        "%%%%%    %%%%%             %%%%% %%%%%%%%      @%%%%%%%%%%%    \n"
        " :::::::    ::::    :::::::::            %%%%%%     %%%%%    %%%%%%%%%%%%%%  %%%%%%    "
        "%%%%%%   %%%%%%%%%%%%%%    %%%%%%%%%%%%%%%    %%%%%%%%%%%%%%  \n"
        "     ::::::::::::::::::::                %%%%%%%%%%%%%%%   %%%%%     @%%%%%  %%%%%%    "
        "%%%%%    %%%%%%%%%%%%%%    %%%%%%    %%%%%%  %%%%%@    %%%%%@\n"
        "       ::::::::::::::::                    %%%%%%%%%%%%%  @%%%%%%%%%%%%%%%%   %%%%%@  "
        "%%%%%     %%%%%%%%%%%%%%    %%%%%     %%%%%%  %%%%%%    %%%%%%               @@@@    "
        "@@@@@@@@\n"
        "     ::::   ::::    :::::                  @%%%%%@ %%%%%  %%%%%%%%%%%%%%%%%   %%%%%% "
        "%%%%%%     %%%%%             %%%%%     %%%%%%   %%%%%%%%%%%%%@               @@@@@@     "
        "@@@  \n"
        " ::::::::   ::::    :::::::::              %%%%%%@ %%%%%   %%%%%               "
        "%%%%%%%%%%%      %%%%%             %%%%%     %%%%%%     %%%%%%%%%%                @@@@ "
        "@@@    @@@ \n"
        "::::::::::::::::::::::::::::::          %%%%%%%%   %%%%%   %%%%%%@   %%%%%      %%%%%%%%% "
        "      %%%%%%%%%%%%%%%   %%%%%     %%%%%%   %%%%                        @@@@@@@@    @@@\n"
        "::    ::::::::::::::::    ::::          %%%%%%%    %%%%%    @%%%%%%%%%%%%%       %%%%%%%% "
        "      %%%%%%%%%%%%%%%   %%%%%     %%%%%%   %%%%%%%%%%%%%%%    @@@@    @@@@  @@@@ "
        "@@@@@@@@\n"
        "::    :::::::    :::::    ::::          %%%%%      %%%%%       %%%%%%%%%         %%%%%%%  "
        "      %%%%%%%%%%%%%%    %%%%%     %%%%%@   %%%%%%%%%%%%%%%%    @@@    @@@   @@@@ "
        "@@@@@@@@\n"
        "::::::::::::      ::::::::::::                                                            "
        "                                          %%%%        %%%%%                             \n"
        ":::::::::::        :::::::::::                                                            "
        "                                          %%%%%%%%%%%%%%%%%                             \n"
        "                                                                                          "
        "                                           %%%%%%%%%%%%%%                               \n"
        "\n"
    );
    return R_CMD_STATUS_OK;
}