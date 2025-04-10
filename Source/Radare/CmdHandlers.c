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

// TODO: restrict to debug symbols only

R_IPI RCmdStatus reai_show_help_handler (RCore* core, int argc, const char** argv) {
    UNUSED (core && argc);

    // TODO: colorize output
    if (!r_str_startswith (argv[0], "RE?")) {
        DISPLAY_ERROR (
            "ERROR: Command '%s' does not exist.\n"
            "ERROR: Displaying the help of command 'RE'.\n",
            argv[0]
        );
    }

    r_cons_println (
        "Usage: RE<?>   # RevEngAI Plugin Commands\n"
        "| REi <api_key>=XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX # Initialize plugin config.\n"
        "| REm                     # Get all available models for analysis.\n"
        "| REh                     # Check connection status with RevEngAI servers.\n"
        "| REa<cup?>               # RevEngAI commands for interacting with analyses\n"
        "| REd <function_name>     # Decompile given function using RevEngAI's AI Decompiler\n"
        "| REb<ls>                 # RevEngAI commands for interacting with binaries\n"
        "| REc<lads>               # RevEngAI commands for interacting with collections\n"
        "| REf<lrs?>               # RevEngAI commands for interacting with functions\n"
        "| REart                   # Show RevEng.AI ASCII art.\n"
    );

    return R_CMD_STATUS_OK;
}

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
    if (argc < 2 || r_str_startswith (argv[0], "REi?")) {
        DISPLAY_ERROR (
            "USAGE : REi <api_key>\n"
            "A valid api-key is required.\n"
            "Example: REi XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
        );
        return R_CMD_STATUS_ERROR;
    }

    CString host    = "https://api.reveng.ai"; // Hardcoded host value
    CString api_key = argv[2];

    /* attempt saving config */
    if (reai_plugin_save_config (host, api_key)) {
        /* try to reinit config after creating config */
        if (!reai_plugin_init (core)) {
            DISPLAY_ERROR (
                "Failed to init plugin after creating a new config.\n"
                "Please try restart radare2."
            );
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
            "USAGE: REm\n"
            "List names of available AI models that can be used to create analysis."
        );
        return R_CMD_STATUS_ERROR;
    }

    if (reai_ai_models()) {
        REAI_VEC_FOREACH (reai_ai_models(), model, { r_cons_println (*model); });
    } else {
        // HACK(brightprogrammer): For now
        // Somehow the background worker is failing to fetch latest AI models
        // So I'm just hardcoding this here for now. At the time of writing, this model
        // is very new and I hope it'll be for at least a few weeks.
        // In the mean time I can figure out why the background worker is not getting AI models.
        r_cons_printf (
            "binnet-0.5-x86-windows\n"
            "binnet-0.5-x86-linux\n"
            "binnet-0.5-x86-macos\n"
            "binnet-0.5-x86-android\n"
        );
        REAI_LOG_ERROR ("Seems like background worker failed to get available AI models.");
    }
    return R_CMD_STATUS_ERROR;
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
            "USAGE: REh\n"
            "Perform health check by validating host API endpoint and API key."
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
 * "REac"
 *
 * NOTE: The default way to get ai model would be to use "REm" command.
 *       Get list of all available AI models and then use one to create a new analysis.
 * */
R_IPI RCmdStatus reai_create_analysis_private_handler (RCore* core, int argc, const char** argv) {
    REAI_LOG_TRACE ("[CMD] create analysis (private)");
    if (argc < 3 || argc > 4 || r_str_startswith (argv[0], "REac?")) {
        DISPLAY_ERROR (
            "USAGE : REac <ai_model> <prog_name> <cmd_line_args>         # Create private"
            "RevEngAI analysis\n\n"
            "Examples:\n"
            "| REac binnet-0.4-x86-linux ffmpeg \"-i input.mp4 -vf -c:v gif output.gif\"           "
            "# With command line arguments\n"
            "| REac binnet-0.5-x86-linux emacs                                                     "
            "# Without command line arguments\n"
        );
        return R_CMD_STATUS_ERROR;
    }
    REAI_LOG_TRACE ("[CMD] create analysis");

    /* Make sure analysis functions exist in rizin as well, so we can get functions by their address values. */
    if (!reai_plugin_get_radare_analysis_function_count (core)) {
        r_core_cmd_call (core, "aaaaa");
    }

    CString ai_model     = argv[1];
    CString prog_name    = argv[2];
    CString cmdline_args = argv[3];

    // prog name and ai model must not be null atleast
    if (!prog_name || !strlen (prog_name) || !ai_model || !strlen (ai_model)) {
        DISPLAY_ERROR (
            "Invalid program name or AI model name provided\n"
            "Use REm to get a list of available AI models\n\n"
            "USAGE : REac <ai_model> <prog_name> <cmd_line_args>         # Create private"
            "RevEngAI analysis\n\n"
            "Examples:\n"
            "| REac binnet-0.4-x86-linux ffmpeg \"-i input.mp4 -vf -c:v gif output.gif\"           "
            "# With command line arguments\n"
            "| REac binnet-0.5-x86-linux emacs                                                     "
            "# Without command line arguments\n"
        );
        return R_CMD_STATUS_ERROR;
    }

    if (reai_plugin_create_analysis_for_opened_binary_file (
            core,
            prog_name,
            cmdline_args,
            ai_model,
            true // create private analysis
        )) {
        DISPLAY_INFO ("Analysis created sucessfully");
        return R_CMD_STATUS_OK;
    }

    DISPLAY_ERROR ("Failed to create analysis");

    return R_CMD_STATUS_ERROR;
}

/**
 * "REacp"
 *
 * NOTE: The default way to get ai model would be to use "REm" command.
 *       Get list of all available AI models and then use one to create a new analysis.
 * */
R_IPI RCmdStatus reai_create_analysis_public_handler (RCore* core, int argc, const char** argv) {
    REAI_LOG_TRACE ("[CMD] create analysis (public)");
    if (argc < 3 || argc > 4 || r_str_startswith (argv[0], "REacp?")) {
        DISPLAY_ERROR (
            "USAGE : REac <ai_model> <prog_name> <cmd_line_args>         # Create public"
            "RevEngAI analysis\n\n"
            "Examples:\n"
            "| REac binnet-0.4-x86-linux ffmpeg \"-i input.mp4 -vf -c:v gif output.gif\"           "
            "# With command line arguments\n"
            "| REac binnet-0.5-x86-linux emacs                                                     "
            "# Without command line arguments\n"
        );
        return R_CMD_STATUS_ERROR;
    }
    REAI_LOG_TRACE ("[CMD] create analysis");

    /* Make sure analysis functions exist in rizin as well, so we can get functions by their address values. */
    if (!reai_plugin_get_radare_analysis_function_count (core)) {
        r_core_cmd_call (core, "aaaaa");
    }

    CString prog_name    = argv[1];
    CString cmdline_args = argv[2];
    CString ai_model     = argv[3];

    // prog name and ai model must not be null atleast
    if (!prog_name || !ai_model) {
        DISPLAY_ERROR (
            "Invalid program name or AI model name provided\n"
            "Use REm to get a list of available AI models\n\n"
            "USAGE : REac <ai_model> <prog_name> <cmd_line_args>         # Create public"
            "RevEngAI analysis\n\n"
            "Examples:\n"
            "| REac binnet-0.4-x86-linux ffmpeg \"-i input.mp4 -vf -c:v gif output.gif\"           "
            "# With command line arguments\n"
            "| REac binnet-0.5-x86-linux emacs                                                     "
            "# Without command line arguments\n"
        );
        return R_CMD_STATUS_ERROR;
    }

    if (reai_plugin_create_analysis_for_opened_binary_file (
            core,
            prog_name,
            cmdline_args,
            ai_model,
            false // create public analysis
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
    if (argc != 2 || r_str_startswith (argv[0], "REap?")) {
        DISPLAY_ERROR ("USAGE : REap <bin_id>");
        return R_CMD_STATUS_ERROR;
    }

    /* Make sure analysis functions exist in rizin as well, so we can get functions by their address values. */
    if (!reai_plugin_get_radare_analysis_function_count (core)) {
        r_core_cmd_call (core, "aaaaa");
    }

    if (reai_plugin_apply_existing_analysis (
            core,
            r_num_get (core->num, argv[1]) // binary id
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
    if (argc > 2 || r_str_startswith (argv[0], "REau?")) {
        DISPLAY_ERROR (
            "Usage: REau <min_similarity>=90   # Auto analyze binary functions using ANN and "
            "perform batch rename.\n\n"
            "Examples:\n"
            "| REau    # Apply auto analysis to this binary with 90% min similarity\n"
            "| REau 85 # Min 85%% similairty\n"
        );
        return R_CMD_STATUS_ERROR;
    }

    /* Make sure analysis functions exist in rizin as well, so we can get functions by their address values. */
    if (!reai_plugin_get_radare_analysis_function_count (core)) {
        r_core_cmd_call (core, "aaaaa");
    }

    const Size max_results_per_function = 10;
    Uint32     min_similarity           = 90;

    if (argc == 2) {
        min_similarity = r_num_get (core->num, argv[1]);
        min_similarity = min_similarity > 100 ? 100 : min_similarity;
    }

    if (reai_plugin_auto_analyze_opened_binary_file (
            core,
            max_results_per_function,
            min_similarity / 100.f,
            false // DON'T restrict to debug symbols
        )) {
        DISPLAY_INFO ("Auto-analysis completed successfully.");
        return R_CMD_STATUS_OK;
    } else {
        DISPLAY_ERROR ("Failed to perform RevEng.AI auto-analysis");
        return R_CMD_STATUS_ERROR;
    }
}

/**
 * REaud
 *
 * @b Perform a Batch Symbol ANN request with current binary ID and
 *    automatically rename all methods.
 * */
R_IPI RCmdStatus
    reai_ann_auto_analyze_restrict_debug_handler (RCore* core, int argc, const char** argv) {
    REAI_LOG_TRACE ("[CMD] ANN Auto Analyze Binary (Restrict Debug)");
    if (argc > 2 || r_str_startswith (argv[0], "REaud?")) {
        DISPLAY_ERROR (
            "Usage: REaud <min_similarity>=90   # Auto analyze binary functions using ANN and "
            "perform batch rename.\n"
            "                                   # Restricts symbols to debug symbols only\n\n"
            "Examples:\n"
            "| REaud    # Apply auto analysis to this binary with 90% min similarity\n"
            "| REaud 85 # Min 85%% similairty\n"
        );
        return R_CMD_STATUS_ERROR;
    }

    /* Make sure analysis functions exist in rizin as well, so we can get functions by their address values. */
    if (!reai_plugin_get_radare_analysis_function_count (core)) {
        r_core_cmd_call (core, "aaaaa");
    }

    const Size max_results_per_function = 10;
    Uint32     min_similarity           = 90;

    if (argc == 2) {
        min_similarity = r_num_get (core->num, argv[1]);
        min_similarity = min_similarity > 100 ? 100 : min_similarity;
    }

    if (reai_plugin_auto_analyze_opened_binary_file (
            core,
            max_results_per_function,
            min_similarity / 100.f,
            true // restrict to debug symbols
        )) {
        DISPLAY_INFO ("Auto-analysis completed successfully.");
        return R_CMD_STATUS_OK;
    } else {
        DISPLAY_ERROR ("Failed to perform RevEng.AI auto-analysis");
        return R_CMD_STATUS_ERROR;
    }
}

/**
 * "REa"
 * */
R_IPI RCmdStatus reai_analysis_cmd_group_help_handler (RCore* core, int argc, const char** argv) {
    UNUSED (core && argc && argv);

    if (!r_str_startswith (argv[0], "REa?")) {
        DISPLAY_ERROR (
            "ERROR: Command '%s' does not exist.\n"
            "ERROR: Displaying the help of command 'REa'.\n\n",
            argv[0]
        );
    }

    DISPLAY_INFO (
        "Usage: REa<cup?>   # RevEngAI commands for interacting with analyses\n"
        "| REac <prog_name> <cmd_line_args> <ai_model>  # Create a PRIVATE RevEngAI analysis for "
        "currently opened binary\n"
        "| REacp <prog_name> <cmd_line_args> <ai_model> # Create a PUBLIC RevEngAI analysis for "
        "currently opened binary\n"
        "| REau <min_similarity>=90                     # Auto analyze binary functions using ANN "
        "and perform batch rename.\n"
        "| REaud <min_similarity>=90                    # Auto analyze binary functions using ANN "
        "and perform batch rename. Restrict renamed symbols to debug names only.\n"
        "| REap <bin_id> [<base_addr>]                  # Apply already existing RevEng.AI "
        "analysis to this binary.\n"
    );
    return R_CMD_STATUS_OK;
}

/**
 * "REbl"
 * */
R_IPI RCmdStatus reai_binary_link_handler (RCore* core, int argc, const char** argv) {
    UNUSED (core);
    REAI_LOG_TRACE ("[CMD] Binary Link");
    if (argc > 2 || r_str_startswith (argv[0], "REbl?")) {
        DISPLAY_ERROR (
            "Usage: REbl <binary_id>   # Provide link to show more binary information on RevEngAI "
            "portal"
        );
        return R_CMD_STATUS_ERROR;
    }

    ReaiBinaryId bid = 0;
    if (argc == 2) {
        bid = argv[1] && strlen (argv[1]) ? r_num_get (core->num, argv[1]) : 0;
        if (!bid) {
            DISPLAY_ERROR ("Invalid binary ID provided.");
            return R_CMD_STATUS_ERROR;
        }
    } else {
        bid = reai_binary_id();
    }

    // generate portal link
    char* host = strdup (reai_plugin()->reai_config->host);
    host       = r_str_replace (host, "api", "portal", 0 /* replace first only */);
    if (!host) {
        APPEND_ERROR ("Failed to generate portal link");
        return R_CMD_STATUS_ERROR;
    }

    // TODO: should we also get basic binary information and display it here?
    DISPLAY_INFO (
        "%s/analyses/%llu?analysis-id=%llu",
        host,
        bid,
        reai_analysis_id_from_binary_id (reai(), reai_response(), bid)
    );

    FREE (host);

    return R_CMD_STATUS_OK;
}

/**
 * REcl
 * */
R_IPI RCmdStatus reai_collection_link_handler (RCore* core, int argc, const char** argv) {
    REAI_LOG_TRACE ("[CMD] Collection Link");
    if (argc > 2 || r_str_startswith (argv[0], "REcl?")) {
        DISPLAY_ERROR (
            "Usage: REcl <collection_id>   # Provide a RevEngAI link to view more information "
            "about collection in browser."
        );
        return R_CMD_STATUS_ERROR;
    }

    ReaiCollectionId cid = argv[1] && strlen (argv[1]) ? r_num_get (core->num, argv[1]) : 0;

    // generate portal link
    char* host = strdup (reai_plugin()->reai_config->host);
    host       = r_str_replace (host, "api", "portal", 0 /* replace first only */);
    if (!host) {
        DISPLAY_ERROR ("Failed to generate portal link");
        return R_CMD_STATUS_ERROR;
    }

    // TODO: should we also get basic collection information and display it here?
    DISPLAY_INFO ("%s/collections/%llu", host, cid);

    FREE (host);

    return R_CMD_STATUS_OK;
}


/**
 * "REbsn"
 * */
R_IPI RCmdStatus reai_binary_search_by_name_handler (RCore* core, int argc, const char** argv) {
    REAI_LOG_TRACE ("[CMD] Binary Search (By Name)");
    if (argc < 2 || argc > 3 || r_str_startswith (argv[0], "REbsn?")) {
        DISPLAY_ERROR (
            "Usage: REbsn <partial_name> <model_name>=   # Search for binaries using partial name "
            "only."
        );
        return R_CMD_STATUS_ERROR;
    }

    CString partial_name = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString model_name   = argv[2] && strlen (argv[2]) ? argv[2] : NULL;

    if (reai_plugin_binary_search (core, partial_name, NULL, model_name, NULL)) {
        return R_CMD_STATUS_OK;
    }
    return R_CMD_STATUS_ERROR;
}

/**
 * "REbsh"
 * */
R_IPI RCmdStatus reai_binary_search_by_sha256_handler (RCore* core, int argc, const char** argv) {
    REAI_LOG_TRACE ("[CMD] Binary Search (By SHA-256 Hash)");
    if (argc < 2 || argc > 3 || r_str_startswith (argv[0], "REbsh?")) {
        DISPLAY_ERROR (
            "Usage: REbsh <partial_sha256> <model_name>=   # Search for binaries using partial "
            "sha256 hash only."
        );
        return R_CMD_STATUS_ERROR;
    }

    CString partial_sha256 = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString model_name     = argv[2] && strlen (argv[2]) ? argv[2] : NULL;

    if (reai_plugin_binary_search (core, NULL, partial_sha256, model_name, NULL)) {
        return R_CMD_STATUS_OK;
    }
    return R_CMD_STATUS_ERROR;
}

/**
 * "REbs"
 * */
R_IPI RCmdStatus reai_binary_search_handler (RCore* core, int argc, const char** argv) {
    REAI_LOG_TRACE ("[CMD] Binary Search");
    if (argc < 2 || argc > 4 || r_str_startswith (argv[0], "REbsh?")) {
        DISPLAY_ERROR (
            "Usage: REbs[nh]   # Commands for performing binary search in RevEngAI\n"
            "| REbs <partial_name> <partial_sha256> <model_name> <tags_csv> # Search for binaries "
            "using partial name, partial sha256 hash, etc...\n"
            "| REbsn <partial_name> <model_name>=                     # Search for binaries using "
            "partial name only.\n"
            "| REbsh <partial_sha256> <model_name>=                   # Search for binaries using "
            "partial sha256 hash only.\n"
        );
        return R_CMD_STATUS_ERROR;
    }

    CString partial_name   = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString partial_sha256 = argv[2] && strlen (argv[2]) ? argv[2] : NULL;
    CString model_name     = argv[3] && strlen (argv[3]) ? argv[3] : NULL;

    if (reai_plugin_binary_search (core, partial_name, partial_sha256, model_name, NULL)) {
        return R_CMD_STATUS_OK;
    }
    return R_CMD_STATUS_ERROR;
}

/**
 * "REb"
 * */
R_IPI RCmdStatus reai_binary_cmd_group_help_handler (RCore* core, int argc, const char** argv) {
    UNUSED (core && argc && argv);

    if (!r_str_startswith (argv[0], "REa?")) {
        DISPLAY_ERROR (
            "ERROR: Command '%s' does not exist.\n"
            "ERROR: Displaying the help of command 'REb'.\n\n",
            argv[0]
        );
    }

    DISPLAY_INFO (
        "Usage: REb<ls>   # RevEngAI commands for interacting with binaries\n"
        "| REbl <binary_id> # Provide link to show more binary information on RevEngAI portal\n"
        "| REbs[nh]         # Commands for performing binary search in RevEngAI\n"
    );

    return R_CMD_STATUS_OK;
}

/**
 * "REb"
 * */
R_IPI RCmdStatus reai_function_cmd_group_help_handler (RCore* core, int argc, const char** argv) {
    UNUSED (core && argc && argv);

    if (!r_str_startswith (argv[0], "REf?")) {
        DISPLAY_ERROR (
            "ERROR: Command '%s' does not exist.\n"
            "ERROR: Displaying the help of command 'REf'.\n\n",
            argv[0]
        );
    }

    DISPLAY_INFO (
        "Usage: REf<lrs?>   # RevEngAI commands for interacting with functions\n"
        "| REfl                     # Get & show basic function info for selected binary.\n"
        "| REfr <old_name> <new_name> # Rename function with given function id to given name.\n"
        "| REfs <function_name> <min_similarity>=95 <max_results>=20 <collection_ids>= "
        "<binary_ids>= # RevEng.AI ANN functions similarity search.\n"
        "| REfsd <function_name> <min_similarity>=95 <max_results>=20 <collections>= # RevEng.AI "
        "ANN functions similarity search. Suggestions restricted to debug symbols only.\n"
    );

    return R_CMD_STATUS_OK;
}

/**
 * "REd"
 * */
R_IPI RCmdStatus reai_ai_decompile_handler (RCore* core, int argc, const char** argv) {
    REAI_LOG_TRACE ("[CMD] AI Decompile");
    if (argc < 2 || r_str_startswith (argv[0], "REd?")) {
        DISPLAY_ERROR (
            "USAGE : REd <fn_name>\n"
            "Uses an already existing RevEngAI analysis to decompile functions\n"
            "With help of AI"
        );
        return R_CMD_STATUS_ERROR;
    }

    /* Make sure analysis functions exist in rizin as well, so we can get functions by their address values. */
    if (!reai_plugin_get_radare_analysis_function_count (core)) {
        r_core_cmd_call (core, "aaaaa");
    }

    /* get binary id of opened file */
    ReaiBinaryId binary_id = reai_binary_id();
    if (!binary_id) {
        DISPLAY_ERROR (
            "Please apply existing RevEngAI analysis (using REap command) or create a new one.\n"
            "Cannot get function info from RevEng.AI without an existing analysis."
        );
        return R_CMD_STATUS_ERROR;
    }

    /* an analysis must already exist in order to make function decompile work */
    ReaiAnalysisStatus analysis_status =
        reai_get_analysis_status (reai(), reai_response(), reai_binary_id());
    switch (analysis_status) {
        case REAI_ANALYSIS_STATUS_ERROR : {
            DISPLAY_ERROR (
                "The applied/created RevEngAI analysis has errored out.\n"
                "I need a complete analysis to function decompilation. Please restart analysis."
            );
            return R_CMD_STATUS_ERROR;
        }
        case REAI_ANALYSIS_STATUS_QUEUED : {
            DISPLAY_ERROR (
                "The applied/created RevEngAI analysis is currently in queue.\n"
                "Please wait for the analysis to be analyzed."
            );
            return R_CMD_STATUS_OK;
        }
        case REAI_ANALYSIS_STATUS_PROCESSING : {
            DISPLAY_ERROR (
                "The applied/created RevEngAI analysis is currently being processed (analyzed).\n"
                "Please wait for the analysis to complete."
            );
            return R_CMD_STATUS_OK;
        }
        case REAI_ANALYSIS_STATUS_COMPLETE : {
            REAI_LOG_TRACE ("Analysis for binary ID %llu is COMPLETE.", reai_binary_id());
            break;
        }
        default : {
            DISPLAY_ERROR (
                "Oops... something bad happened :-(\n"
                "I got an invalid value for RevEngAI analysis status.\n"
                "Consider\n"
                "\t- Checking the binary ID, reapply the correct one if wrong\n"
                "\t- Retrying the command\n"
                "\t- Restarting the plugin\n"
                "\t- Checking logs in $TMPDIR or $TMP or $PWD (reai_<pid>)\n"
                "\t- Checking the connection with RevEngAI host.\n"
                "\t- Contacting support if the issue persists\n"
            );
            return R_CMD_STATUS_ERROR;
        }
    }

    const char*    fn_name = argv[1];
    RAnalFunction* rfn     = r_anal_get_function_byname (core->anal, fn_name);

    if (!rfn) {
        DISPLAY_ERROR (
            "A function with given name does not exist in Radare.\n"
            "Cannot decompile :-("
        );
        return R_CMD_STATUS_ERROR;
    }

    /* NOTE(brightprogrammer): Error count is a hack used to mitigate the case
     * where the AI decompilation process is already errored out and user wants
     * to restart the process. */
    int error_count = 0;

    while (true) {
        DISPLAY_INFO ("Checking decompilation status...");

        ReaiAiDecompilationStatus status =
            reai_plugin_check_decompiler_status_running_at (core, rfn->addr);

        switch (status) {
            case REAI_AI_DECOMPILATION_STATUS_ERROR :
                if (!error_count) {
                    DISPLAY_INFO (
                        "Looks like the decompilation process failed last time\n"
                        "I'll restart the decompilation process again..."
                    );
                    reai_plugin_decompile_at (core, rfn->addr);
                } else if (error_count > 1) {
                    DISPLAY_ERROR (
                        "Failed to decompile \"%s\"\n"
                        "Is this function from RevEngAI's analysis?\n"
                        "What's the output of REfl?",
                        fn_name
                    );
                    return R_CMD_STATUS_ERROR;
                }
                error_count++;
                break;
            case REAI_AI_DECOMPILATION_STATUS_UNINITIALIZED :
                DISPLAY_INFO ("No decompilation exists for this function...");
                reai_plugin_decompile_at (core, rfn->addr);
                break;
            case REAI_AI_DECOMPILATION_STATUS_SUCCESS : {
                DISPLAY_INFO ("AI decompilation complete ;-)\n");
                CString code = reai_plugin_get_decompiled_code_at (core, rfn->addr);
                if (code) {
                    r_cons_println (code);
                    r_cons_flush();
                    FREE (code);
                }
                return R_CMD_STATUS_OK;
            }
            default :
                break;
        }

        DISPLAY_INFO ("Going to sleep for two seconds...");
        r_sys_sleep (2);
    }

    return R_CMD_STATUS_OK;
}

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
    if (argc < 1 || r_str_startswith (argv[0], "REfl?")) {
        DISPLAY_ERROR (
            "USAGE : REfl\nList all functions detected/provided to/by RevEngAI analysis.\nExisting "
            "attached analysis is required. Either create a new analysis or apply an existing one."
        );
        return R_CMD_STATUS_ERROR;
    }

    /* get binary id of opened file */
    ReaiBinaryId binary_id = reai_binary_id();
    if (!binary_id) {
        DISPLAY_ERROR (
            "Please apply existing RevEngAI analysis (using REap command) or create a new one.\n"
            "Cannot get function info from RevEng.AI without an existing analysis."
        );
        return R_CMD_STATUS_ERROR;
    }

    /* an analysis must already exist in order to make function-rename work */
    ReaiAnalysisStatus analysis_status =
        reai_get_analysis_status (reai(), reai_response(), reai_binary_id());
    switch (analysis_status) {
        case REAI_ANALYSIS_STATUS_ERROR : {
            DISPLAY_ERROR (
                "The applied/created RevEngAI analysis has errored out.\n"
                "I need a complete analysis to get function info. Please restart analysis."
            );
            return R_CMD_STATUS_ERROR;
        }
        case REAI_ANALYSIS_STATUS_QUEUED : {
            DISPLAY_ERROR (
                "The applied/created RevEngAI analysis is currently in queue.\n"
                "Please wait for the analysis to be analyzed."
            );
            return R_CMD_STATUS_OK;
        }
        case REAI_ANALYSIS_STATUS_PROCESSING : {
            DISPLAY_ERROR (
                "The applied/created RevEngAI analysis is currently being processed (analyzed).\n"
                "Please wait for the analysis to complete."
            );
            return R_CMD_STATUS_OK;
        }
        case REAI_ANALYSIS_STATUS_COMPLETE : {
            REAI_LOG_TRACE ("Analysis for binary ID %llu is COMPLETE.", reai_binary_id());
            break;
        }
        default : {
            DISPLAY_ERROR (
                "Oops... something bad happened :-(\n"
                "I got an invalid value for RevEngAI analysis status.\n"
                "Consider\n"
                "\t- Checking the binary ID, reapply the correct one if wrong\n"
                "\t- Retrying the command\n"
                "\t- Restarting the plugin\n"
                "\t- Checking logs in $TMPDIR or $TMP or $PWD (reai_<pid>)\n"
                "\t- Checking the connection with RevEngAI host.\n"
                "\t- Contacting support if the issue persists\n"
            );
            return R_CMD_STATUS_ERROR;
        }
    }

    /* Make sure analysis functions exist in rizin as well, so we can get functions by their address values. */
    if (!reai_plugin_get_radare_analysis_function_count (core)) {
        r_core_cmd_call (core, "aaaaa");
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
        DISPLAY_ERROR ("USAGE : REfr <old_addr> <new_name>");
        return R_CMD_STATUS_ERROR;
    }

    /* get binary id of opened file */
    ReaiBinaryId binary_id = reai_binary_id();
    if (!binary_id) {
        DISPLAY_ERROR (
            "Please apply existing RevEngAI analysis (using REap command) or create a new one.\n"
            "Cannot get function info from RevEng.AI without an existing analysis."
        );
        return R_CMD_STATUS_ERROR;
    }

    /* an analysis must already exist in order to make function-rename work */
    ReaiAnalysisStatus analysis_status =
        reai_get_analysis_status (reai(), reai_response(), reai_binary_id());
    switch (analysis_status) {
        case REAI_ANALYSIS_STATUS_ERROR : {
            DISPLAY_ERROR (
                "The applied/created RevEngAI analysis has errored out.\n"
                "Please restart analysis."
            );
            return R_CMD_STATUS_ERROR;
        }
        case REAI_ANALYSIS_STATUS_QUEUED : {
            DISPLAY_ERROR (
                "The applied/created RevEngAI analysis is currently in queue.\n"
                "Please wait for the analysis to be analyzed."
            );
            return R_CMD_STATUS_OK;
        }
        case REAI_ANALYSIS_STATUS_PROCESSING : {
            DISPLAY_ERROR (
                "The applied/created RevEngAI analysis is currently being processed (analyzed).\n"
                "Please wait for the analysis to complete."
            );
            return R_CMD_STATUS_OK;
        }
        case REAI_ANALYSIS_STATUS_COMPLETE : {
            REAI_LOG_TRACE ("Analysis for binary ID %llu is COMPLETE.", reai_binary_id());
            break;
        }
        default : {
            DISPLAY_ERROR (
                "Oops... something bad happened :-(\n"
                "I got an invalid value for RevEngAI analysis status.\n"
                "Consider\n"
                "\t- Checking the binary ID, reapply the correct one if wrong\n"
                "\t- Retrying the command\n"
                "\t- Restarting the plugin\n"
                "\t- Checking logs in $TMPDIR or $TMP or $PWD (reai_<pid>)\n"
                "\t- Checking the connection with RevEngAI host.\n"
                "\t- Contacting support if the issue persists\n"
            );
            return R_CMD_STATUS_ERROR;
        }
    }

    /* Make sure analysis functions exist in rizin as well, so we can get functions by their address values. */
    if (!reai_plugin_get_radare_analysis_function_count (core)) {
        r_core_cmd_call (core, "aaaaa");
    }

    CString old_name = argv[1];
    CString new_name = argv[2];

    // get function at given address
    RAnalFunction* fn = r_anal_get_function_byname (core->anal, old_name);
    if (!fn) {
        DISPLAY_ERROR ("Function with given name not found.");
        return R_CMD_STATUS_ERROR;
    }

    ReaiFunctionId fn_id = reai_plugin_get_function_id_for_radare_function (core, fn);
    if (!fn_id) {
        DISPLAY_ERROR (
            "A function ID for given function does not exist in RevEngAI analysis.\n"
            "I won't be able to rename this function."
        );
        return R_CMD_STATUS_ERROR;
    }

    /* perform rename operation */
    if (reai_rename_function (reai(), reai_response(), fn_id, new_name)) {
        if (r_anal_function_rename (fn, new_name)) {
            DISPLAY_INFO ("Rename success.");
        } else {
            DISPLAY_ERROR ("Rename failed in radare.");
            return R_CMD_STATUS_ERROR;
        }
    } else {
        DISPLAY_ERROR ("Failed to rename the function in RevEngAI.");
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
    if (argc < 2 || r_str_startswith (argv[0], "REfs?")) {
        DISPLAY_ERROR ("USAGE : REfs <function_name> <min_similarity>=95 <max_results>=20");
        return R_CMD_STATUS_ERROR;
    }

    /* Make sure analysis functions exist in rizin as well, so we can get functions by their address values. */
    if (!reai_plugin_get_radare_analysis_function_count (core)) {
        r_core_cmd_call (core, "aaaaa");
    }

    // Parse command line arguments
    CString function_name     = argv[1];
    Uint32  min_similarity    = 95;
    Uint32  max_results_count = 20;

    min_similarity    = (argc > 2) ? (Uint32)r_num_math (core->num, argv[2]) : min_similarity;
    max_results_count = (argc > 3) ? (Uint32)r_num_math (core->num, argv[3]) : max_results_count;

    if (!reai_plugin_search_and_show_similar_functions (
            core,
            function_name,
            max_results_count,
            min_similarity,
            false // no restrictions on search suggestions
        )) {
        DISPLAY_ERROR ("Failed to get similar functions search result.");
        return R_CMD_STATUS_ERROR;
    }

    return R_CMD_STATUS_OK;
}

/**
 * "REfsd"
 *
 * @b Similar function name search. Restrict search suggestions to debug symbols only. 
 * */
R_IPI RCmdStatus reai_function_similarity_search_restrict_debug_handler (
    RCore*       core,
    int          argc,
    const char** argv
) {
    REAI_LOG_TRACE ("[CMD] Function similarity search");
    if (argc < 2 || argc > 6 || r_str_startswith (argv[0], "REfsd?")) {
        DISPLAY_ERROR (
            "Usage: REfsd <function_name> <min_similarity>=95 <max_results>=20 <collection_ids>= "
            "<binary_ids>=   # RevEng.AI ANN functions similarity search. Search suggestions "
            "restricted to debug symbols only.\n"
            "\n"
            "Function Name:\n"
            "| REfsd sym.main                     # Search similar function for sym.main function "
            "with minimum similarity of 90%%\n"
            "| REfsd __memcmp 95                  # Search similar function for __memcmp, with "
            "minimum 95%% similarity\n"
            "| REfsd postHandleCall 72 10         # Max 10 results\n"
            "| REfsd fcn.8086.xmrig-0ddf8e62 80 10 \"194728, 170418, 161885\" # Search only in "
            "provided list of comma separated collection IDs\n"
            "| REfsd FUN_8a3004 90 25 \"\" \"420229, 38445\" # Can provide binary IDs as well to "
            "limit the search for functions to those binaries\n"
        );
        return R_CMD_STATUS_ERROR;
    }

    /* Make sure analysis functions exist in rizin as well, so we can get functions by their address values. */
    if (!reai_plugin_get_radare_analysis_function_count (core)) {
        r_core_cmd_call (core, "aaaaa");
    }

    // Parse command line arguments
    CString function_name     = argv[1];
    Uint32  min_similarity    = 95;
    Uint32  max_results_count = 20;

    min_similarity    = (argc > 2) ? (Uint32)r_num_math (core->num, argv[2]) : min_similarity;
    max_results_count = (argc > 3) ? (Uint32)r_num_math (core->num, argv[3]) : max_results_count;

    CString collection_ids_csv = (argc > 4) ? argv[4] : NULL;
    CString binary_ids_csv     = (argc > 5) ? argv[5] : NULL;

    // TODO: needs to be updated
    if (!reai_plugin_search_and_show_similar_functions (
            core,
            function_name,
            max_results_count,
            min_similarity,
            true // restrict search suggestions to debug symbols only
        )) {
        DISPLAY_ERROR ("Failed to get similar functions search result.");
        return R_CMD_STATUS_ERROR;
    }

    return R_CMD_STATUS_OK;
}

/**
 * "REc"
 * */
R_IPI RCmdStatus reai_collection_cmd_group_help_handler (RCore* core, int argc, const char** argv) {
    UNUSED (core && argc);
    if (!r_str_startswith (argv[0], "REc?")) {
        DISPLAY_ERROR (
            "ERROR: Command '%s' does not exist.\n"
            "ERROR: Displaying the help of command 'REc'.\n\n",
            argv[0]
        );
    }

    DISPLAY_INFO (
        "Usage: REc<lads>   # RevEngAI commands for interacting with collections"
        "| REcl <collection_id> # Provide a RevEngAI link to view more information about "
        "collection in browser."
        "| REca<tonms>          # Get information about collections, ordered in ascending order."
        "| REcd<tonms>          # Get information about collections, ordered in descending order."
        "| REcs[cbh]            # Perform a collection search through either partial collection "
        "name, binary name or sha256 hash of binary."
    );

    return R_CMD_STATUS_OK;
}

/**
 * "REcsc"
 * */
R_IPI RCmdStatus
    reai_collection_search_by_collection_name_handler (RCore* core, int argc, const char** argv) {
    if (argc < 2 || argc > 3 || r_str_startswith (argv[0], "REcsn?")) {
        DISPLAY_ERROR (
            "Usage: REcsc <partial_collection_name>= <model_name>=   # Perform a collection search "
            "through partial collection name only.\n"
            "\n"
            "Examples:\n"
            "| REcsc gafgyt                     # Perform collection search using a partial "
            "collection name\n"
            "| REcsc xmrig binnet-0.5-x86-linux # Can provide model name as well to narrow down to "
            "latest model version\n"
            "| REcsc xmrig binnet-0.4-x86-linux # Or to an older model version. If you have an "
            "older analysis incompatible with latest versions\n"
        );
        return R_CMD_STATUS_ERROR;
    }

    CString partial_collection_name = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString model_name              = argv[2] && strlen (argv[2]) ? argv[2] : NULL;

    if (reai_plugin_collection_search (
            core,
            partial_collection_name,
            NULL,
            NULL,
            model_name,
            NULL
        )) {
        return R_CMD_STATUS_OK;
    }

    return R_CMD_STATUS_ERROR;
}

/**
 * "REcsb"
 * */
R_IPI RCmdStatus
    reai_collection_search_by_binary_name_handler (RCore* core, int argc, const char** argv) {
    if (argc < 2 || argc > 3 || r_str_startswith (argv[0], "REcsn?")) {
        DISPLAY_ERROR (
            "Usage: REcsb <partial_binary_name>= <model_name>=   # Perform a collection search "
            "through partial binary name only.\n"
            "\n"
            "Examples:\n"
            "| REcsb miner                     # Perform collection search using a partial binary "
            "name\n"
            "| REcsb xmrig binnet-0.5-x86-linux # Can provide model name as well to narrow down to "
            "latest model version\n"
            "| REcsb xmrig binnet-0.4-x86-linux # Or to an older model version. If you have an "
            "older analysis incompatible with latest versions\n"
        );
        return R_CMD_STATUS_ERROR;
    }

    CString partial_binary_name = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString model_name          = argv[2] && strlen (argv[2]) ? argv[2] : NULL;

    if (reai_plugin_collection_search (core, NULL, partial_binary_name, NULL, model_name, NULL)) {
        return R_CMD_STATUS_OK;
    }

    return R_CMD_STATUS_ERROR;
}

/**
 * "REcsh"
 * */
R_IPI RCmdStatus
    reai_collection_search_by_binary_sha256_handler (RCore* core, int argc, const char** argv) {
    if (argc < 2 || argc > 3 || r_str_startswith (argv[0], "REcsn?")) {
        DISPLAY_ERROR (
            "Usage: REcsh <partial_binary_sha256>= <model_name>=   # Perform a collection search "
            "through partial SHA256 hash only.\n"
            "\n"
            "Examples:\n"
            "| REcsh 0a569366eee                   # Perform collection search using a partial "
            "SHA256 hash\n"
            "| REcsh 79a5c74f binnet-0.5-x86-linux # Can provide model name as well to narrow down "
            "to latest model version\n"
            "| REcsh 79a5c74f binnet-0.4-x86-linux # Or to an older model version. If you have an "
            "older analysis incompatible with latest versions\n"
        );
        return R_CMD_STATUS_ERROR;
    }

    CString partial_binary_sha256 = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString model_name            = argv[2] && strlen (argv[2]) ? argv[2] : NULL;

    if (reai_plugin_collection_search (core, NULL, NULL, partial_binary_sha256, model_name, NULL)) {
        return R_CMD_STATUS_OK;
    }

    return R_CMD_STATUS_ERROR;
}

/**
 * "REcs"
 * */
R_IPI RCmdStatus reai_collection_search_handler (RCore* core, int argc, const char** argv) {
    if (r_str_startswith (argv[0], "REcs??")) {
        DISPLAY_ERROR (
            "Usage: REcs <partial_collection_name>= <partial_binary_name>= "
            "<partial_binary_sha256>= <model_name>= <tags>=   # Perform a collection search "
            "through either partial collection name, binary\n"
            "                                                                                      "
            "                           name or sha256 hash of binary.\n\n"
            "Examples:\n"
            "| REcs gafgyt                     # Perform collection search using a partial "
            "collection name\n"
            "| REcs "
            " xmrig                   # Perform collection search using a partial binary name\n"
            "| REcs "
            " "
            " 79a5c74f             # Perform collection search using a partial SHA256 hash\n"
            "| REcs xmrig xmrig 79a5c74f       # Can combine all search parameters at the same "
            "time as well\n"
            "| REcs xmrig "
            " 79a5c74f binnet-0.5-x86-linux # Can provide model name as well to narrow down to "
            "latest model version\n"
        );
        return R_CMD_STATUS_OK;
    }

    if (argc < 2 || argc > 6 || r_str_startswith (argv[0], "REcs?")) {
        DISPLAY_ERROR (
            "Usage: REcs[cbh]   # Perform a collection search through either partial collection "
            "name, binary name or sha256 hash of binary.\n"
            "| REcs <partial_collection_name>= <partial_binary_name>= <partial_binary_sha256>= "
            "<model_name>= <tags>= # Perform a collection search through either partial collection "
            "name, binary name or\n"
            "                                                                                      "
            "                    sha256 hash of binary.\n"
            "| REcsc <partial_collection_name>= <model_name>=                 # Perform a "
            "collection search through partial collection name only.\n"
            "| REcsb <partial_binary_name>= <model_name>=                     # Perform a "
            "collection search through partial binary name only.\n"
            "| REcsh <partial_binary_sha256>= <model_name>=                   # Perform a "
            "collection search through partial SHA256 hash only.\n"
            "\n"
            "Detailed help for REcs <partial_collection_name>= <partial_binary_name>= "
            "<partial_binary_sha256>= <model_name>= <tags>= is provided by REcs??.\n"
        );
        return R_CMD_STATUS_ERROR;
    }

    CString partial_collection_name = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString partial_binary_name     = argv[2] && strlen (argv[2]) ? argv[2] : NULL;
    CString partial_binary_sha256   = argv[3] && strlen (argv[3]) ? argv[3] : NULL;
    CString model_name              = argv[4] && strlen (argv[4]) ? argv[4] : NULL;
    CString tags_csv                = argv[5] && strlen (argv[5]) ? argv[5] : NULL;

    if (reai_plugin_collection_search (
            core,
            partial_collection_name,
            partial_binary_name,
            partial_binary_sha256,
            model_name,
            tags_csv
        )) {
        return R_CMD_STATUS_OK;
    }

    return R_CMD_STATUS_ERROR;
}

static Bool str_to_filter_flags (CString filters, ReaiCollectionBasicInfoFilterFlags* flags) {
    if (!flags) {
        return false;
    }

    if (!filters) {
        return true;
    }

    while (*filters) {
        switch (*filters) {
            case 'o' :
                *flags |= REAI_COLLECTION_BASIC_INFO_FILTER_OFFICIAL;
                break;
            case 'u' :
                *flags |= REAI_COLLECTION_BASIC_INFO_FILTER_PUBLIC;
                break;
            case 't' :
                *flags |= REAI_COLLECTION_BASIC_INFO_FILTER_TEAM;
                break;
            case 'p' :
                *flags |= REAI_COLLECTION_BASIC_INFO_FILTER_PUBLIC;
                break;
            default :
                APPEND_ERROR (
                    "Invalid filter flag '%c'.\nAvailable flags are [o] - official, [u] - user, "
                    "[t] - team, [p] - public only",
                    *filters
                );
                return false;
                break;
        }
        filters++;
    }

    return true;
}

/**
 * REcat
 * */
R_IPI RCmdStatus
    reai_collection_basic_info_asc_time_handler (RCore* core, int argc, const char** argv) {
    if (argc < 2 || argc > 3 || r_str_startswith (argv[0], "REcat?")) {
        DISPLAY_ERROR (
            "Usage: REcat <search_term> <filter_flags>=   # Get information about collections, "
            "ordered by creation time, in ascending order.\n"
            "\n"
            "Examples:\n"
            "| REcat rat outp      # In total four filters available. [o] - order, [u] - user and "
            "[t] - creation time, [p] - public.\n"
            "| REcat miner otp     # Search for collections with name miner, ordered by creation "
            "time, and are official only [o], team only [t] and public only [p]\n"
            "| REcat mirai u       # user only [u]\n"
            "| REcat bruteratel uo # user only [u], official only [o]\n"
            "| REcat mysql utop    # Order of filter flags can change without changing the search "
            "results\n"
            "| REcat mysql         # Search can be done without any filters as well!\n"
        );
        return R_CMD_STATUS_ERROR;
    }

    CString search_term = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString filters     = argv[2] && strlen (argv[2]) ? argv[2] : NULL;

    ReaiCollectionBasicInfoFilterFlags filter_flags = REAI_COLLECTION_BASIC_INFO_FILTER_HIDE_EMPTY;
    if (!str_to_filter_flags (filters, &filter_flags)) {
        DISPLAY_ERROR ("Failed to understand provided filter flags");
        return R_CMD_STATUS_ERROR;
    }

    if (reai_plugin_collection_basic_info (
            core,
            search_term,
            filter_flags,
            REAI_COLLECTION_BASIC_INFO_ORDER_BY_CREATED,
            REAI_COLLECTION_BASIC_INFO_ORDER_IN_ASC
        )) {
        return R_CMD_STATUS_OK;
    }
    return R_CMD_STATUS_ERROR;
}

/**
 * REcao
 * */
R_IPI RCmdStatus
    reai_collection_basic_info_asc_owner_handler (RCore* core, int argc, const char** argv) {
    if (argc < 2 || argc > 3 || r_str_startswith (argv[0], "REcao?")) {
        DISPLAY_ERROR (
            "Usage: REcao <search_term> <filter_flags>=   # Get information about collections, "
            "ordered by collection owner, in ascending order.\n"
            "\n"
            "Examples:\n"
            "| REcao rat outp      # In total four filters available. [o] - order, [u] - user and "
            "[t] - creation time, [p] - public.\n"
            "| REcao miner otp     # Search for collections with name miner, ordered by collection "
            "owner, and are official only [o], team only [t] and public only [p]\n"
            "| REcao mirai u       # user only [u]\n"
            "| REcao bruteratel uo # user only [u], official only [o]\n"
            "| REcao mysql utop    # Order of filter flags can change without changing the search "
            "results\n"
            "| REcao mysql         # Search can be done without any filters as well!\n"
        );
        return R_CMD_STATUS_ERROR;
    }

    CString search_term = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString filters     = argv[2] && strlen (argv[2]) ? argv[2] : NULL;

    ReaiCollectionBasicInfoFilterFlags filter_flags = REAI_COLLECTION_BASIC_INFO_FILTER_HIDE_EMPTY;
    if (!str_to_filter_flags (filters, &filter_flags)) {
        DISPLAY_ERROR ("Failed to understand provided filter flags");
        return R_CMD_STATUS_ERROR;
    }

    if (reai_plugin_collection_basic_info (
            core,
            search_term,
            filter_flags,
            REAI_COLLECTION_BASIC_INFO_ORDER_BY_OWNER,
            REAI_COLLECTION_BASIC_INFO_ORDER_IN_ASC
        )) {
        return R_CMD_STATUS_OK;
    }
    return R_CMD_STATUS_ERROR;
}

/**
 * REcan
 * */
R_IPI RCmdStatus
    reai_collection_basic_info_asc_name_handler (RCore* core, int argc, const char** argv) {
    if (argc < 2 || argc > 3 || r_str_startswith (argv[0], "REcan?")) {
        DISPLAY_ERROR (
            "Usage: REcan <search_term> <filter_flags>=   # Get information about collections, "
            "ordered by collection name, in ascending order.\n"
            "\n"
            "Examples:\n"
            "| REcan rat outp      # In total four filters available. [o] - order, [u] - user and "
            "[t] - creation time, [p] - public.\n"
            "| REcan miner otp     # Search for collections with name miner, ordered by collection "
            "name, and are official only [o], team only [t] and public only [p]\n"
            "| REcan mirai u       # user only [u]\n"
            "| REcan bruteratel uo # user only [u], official only [o]\n"
            "| REcan mysql utop    # Order of filter flags can change without changing the search "
            "results\n"
            "| REcan mysql         # Search can be done without any filters as well!\n"
        );
        return R_CMD_STATUS_ERROR;
    }

    CString search_term = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString filters     = argv[2] && strlen (argv[2]) ? argv[2] : NULL;

    ReaiCollectionBasicInfoFilterFlags filter_flags = REAI_COLLECTION_BASIC_INFO_FILTER_HIDE_EMPTY;
    if (!str_to_filter_flags (filters, &filter_flags)) {
        DISPLAY_ERROR ("Failed to understand provided filter flags");
        return R_CMD_STATUS_ERROR;
    }

    if (reai_plugin_collection_basic_info (
            core,
            search_term,
            filter_flags,
            REAI_COLLECTION_BASIC_INFO_ORDER_BY_COLLECTION,
            REAI_COLLECTION_BASIC_INFO_ORDER_IN_ASC
        )) {
        return R_CMD_STATUS_OK;
    }
    return R_CMD_STATUS_ERROR;
}

/**
 * REcam
 * */
R_IPI RCmdStatus
    reai_collection_basic_info_asc_model_handler (RCore* core, int argc, const char** argv) {
    if (argc < 2 || argc > 3 || r_str_startswith (argv[0], "REcam?")) {
        DISPLAY_ERROR (
            "Usage: REcam <search_term> <filter_flags>=   # Get information about collections, "
            "ordered by model version, in ascending order.\n"
            "\n"
            "Examples:\n"
            "| REcam rat outp      # In total four filters available. [o] - order, [u] - user and "
            "[t] - creation time, [p] - public.\n"
            "| REcam miner otp     # Search for collections with name miner, ordered by model "
            "version, and are official only [o], team only [t] and public only [p]\n"
            "| REcam mirai u       # user only [u]\n"
            "| REcam bruteratel uo # user only [u], official only [o]\n"
            "| REcam mysql utop    # Order of filter flags can change without changing the search "
            "results\n"
            "| REcam mysql         # Search can be done without any filters as well!\n"
        );
        return R_CMD_STATUS_ERROR;
    }

    CString search_term = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString filters     = argv[2] && strlen (argv[2]) ? argv[2] : NULL;

    ReaiCollectionBasicInfoFilterFlags filter_flags = REAI_COLLECTION_BASIC_INFO_FILTER_HIDE_EMPTY;
    if (!str_to_filter_flags (filters, &filter_flags)) {
        DISPLAY_ERROR ("Failed to understand provided filter flags");
        return R_CMD_STATUS_ERROR;
    }

    if (reai_plugin_collection_basic_info (
            core,
            search_term,
            filter_flags,
            REAI_COLLECTION_BASIC_INFO_ORDER_BY_MODEL,
            REAI_COLLECTION_BASIC_INFO_ORDER_IN_ASC
        )) {
        return R_CMD_STATUS_OK;
    }
    return R_CMD_STATUS_ERROR;
}

/**
 * REcas
 * */
R_IPI RCmdStatus
    reai_collection_basic_info_asc_size_handler (RCore* core, int argc, const char** argv) {
    if (argc < 2 || argc > 3 || r_str_startswith (argv[0], "REcas?")) {
        DISPLAY_ERROR (
            "Usage: REcas <search_term> <filter_flags>=   # Get information about collections, "
            "ordered by collection size, in ascending order.\n"
            "\n"
            "Examples:\n"
            "| REcas rat outp      # In total four filters available. [o] - order, [u] - user and "
            "[t] - creation time, [p] - public.\n"
            "| REcas miner otp     # Search for collections with name miner, ordered by collection "
            "size, and are official only [o], team only [t] and public only [p]\n"
            "| REcas mirai u       # user only [u]\n"
            "| REcas bruteratel uo # user only [u], official only [o]\n"
            "| REcas mysql utop    # Order of filter flags can change without changing the search "
            "results\n"
            "| REcas mysql         # Search can be done without any filters as well!\n"
        );
        return R_CMD_STATUS_ERROR;
    }

    CString search_term = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString filters     = argv[2] && strlen (argv[2]) ? argv[2] : NULL;

    ReaiCollectionBasicInfoFilterFlags filter_flags = REAI_COLLECTION_BASIC_INFO_FILTER_HIDE_EMPTY;
    if (!str_to_filter_flags (filters, &filter_flags)) {
        DISPLAY_ERROR ("Failed to understand provided filter flags");
        return R_CMD_STATUS_ERROR;
    }

    if (reai_plugin_collection_basic_info (
            core,
            search_term,
            filter_flags,
            REAI_COLLECTION_BASIC_INFO_ORDER_BY_COLLECTION_SIZE,
            REAI_COLLECTION_BASIC_INFO_ORDER_IN_ASC
        )) {
        return R_CMD_STATUS_OK;
    }
    return R_CMD_STATUS_ERROR;
}

// "REca"
R_IPI RCmdStatus reai_collection_basic_info_asc_cmd_group_help_handler (
    RCore*       core,
    int          argc,
    const char** argv
) {
    UNUSED (core && argc);
    if (!r_str_startswith (argv[0], "REca?")) {
        DISPLAY_ERROR (
            "ERROR: Command '%s' does not exist.\n"
            "ERROR: Displaying the help of command 'REca'.\n\n",
            argv[0]
        );
    }

    DISPLAY_INFO (
        "Usage: REca<tonms>   # Get information about collections, ordered in ascending order.\n"
        "| REcat <search_term> <filter_flags>= # Get information about collections, ordered by "
        "creation time, in ascending order.\n"
        "| REcao <search_term> <filter_flags>= # Get information about collections, ordered by "
        "collection owner, in ascending order.\n"
        "| REcan <search_term> <filter_flags>= # Get information about collections, ordered by "
        "collection name, in ascending order.\n"
        "| REcam <search_term> <filter_flags>= # Get information about collections, ordered by "
        "model version, in ascending order.\n"
        "| REcas <search_term> <filter_flags>= # Get information about collections, ordered by "
        "collection size, in ascending order.\n"
    );

    return R_CMD_STATUS_OK;
}

/**
 * REcdt
 * */
R_IPI RCmdStatus
    reai_collection_basic_info_desc_time_handler (RCore* core, int argc, const char** argv) {
    if (argc < 2 || argc > 3 || r_str_startswith (argv[0], "REcdt?")) {
        DISPLAY_ERROR (
            "Usage: REcdt <search_term> <filter_flags>=   # Get information about collections, "
            "ordered by creation time, in descending order.\n"
            "\n"
            "Examples:\n"
            "| REcdt rat outp      # In total four filters available. [o] - order, [u] - user and "
            "[t] - creation time, [p] - public.\n"
            "| REcdt miner otp     # Search for collections with name miner, ordered by creation "
            "time, and are official only [o], team only [t] and public only [p]\n"
            "| REcdt mirai u       # user only [u]\n"
            "| REcdt bruteratel uo # user only [u], official only [o]\n"
            "| REcdt mysql utop    # Order of filter flags can change without changing the search "
            "results\n"
            "| REcdt mysql         # Search can be done without any filters as well!\n"
        );
        return R_CMD_STATUS_ERROR;
    }

    CString search_term = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString filters     = argv[2] && strlen (argv[2]) ? argv[2] : NULL;

    ReaiCollectionBasicInfoFilterFlags filter_flags = REAI_COLLECTION_BASIC_INFO_FILTER_HIDE_EMPTY;
    if (!str_to_filter_flags (filters, &filter_flags)) {
        DISPLAY_ERROR ("Failed to understand provided filter flags");
        return R_CMD_STATUS_ERROR;
    }

    if (reai_plugin_collection_basic_info (
            core,
            search_term,
            filter_flags,
            REAI_COLLECTION_BASIC_INFO_ORDER_BY_CREATED,
            REAI_COLLECTION_BASIC_INFO_ORDER_IN_DESC
        )) {
        return R_CMD_STATUS_OK;
    }
    return R_CMD_STATUS_ERROR;
}

/**
 * REcdo
 * */
R_IPI RCmdStatus
    reai_collection_basic_info_desc_owner_handler (RCore* core, int argc, const char** argv) {
    if (argc < 2 || argc > 3 || r_str_startswith (argv[0], "REcdo?")) {
        DISPLAY_ERROR (
            "Usage: REcdo <search_term> <filter_flags>=   # Get information about collections, "
            "ordered by collection owner, in descending order.\n"
            "\n"
            "Examples:\n"
            "| REcdo rat outp      # In total four filters available. [o] - order, [u] - user and "
            "[t] - creation time, [p] - public.\n"
            "| REcdo miner otp     # Search for collections with name miner, ordered by collection "
            "owner, and are official only [o], team only [t] and public only [p]\n"
            "| REcdo mirai u       # user only [u]\n"
            "| REcdo bruteratel uo # user only [u], official only [o]\n"
            "| REcdo mysql utop    # Order of filter flags can change without changing the search "
            "results\n"
            "| REcdo mysql         # Search can be done without any filters as well!\n"
        );
        return R_CMD_STATUS_ERROR;
    }

    CString search_term = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString filters     = argv[2] && strlen (argv[2]) ? argv[2] : NULL;

    ReaiCollectionBasicInfoFilterFlags filter_flags = REAI_COLLECTION_BASIC_INFO_FILTER_HIDE_EMPTY;
    if (!str_to_filter_flags (filters, &filter_flags)) {
        DISPLAY_ERROR ("Failed to understand provided filter flags");
        return R_CMD_STATUS_ERROR;
    }

    if (reai_plugin_collection_basic_info (
            core,
            search_term,
            filter_flags,
            REAI_COLLECTION_BASIC_INFO_ORDER_BY_OWNER,
            REAI_COLLECTION_BASIC_INFO_ORDER_IN_DESC
        )) {
        return R_CMD_STATUS_OK;
    }
    return R_CMD_STATUS_ERROR;
}

/**
 * REcdn
 * */
R_IPI RCmdStatus
    reai_collection_basic_info_desc_name_handler (RCore* core, int argc, const char** argv) {
    if (argc < 2 || argc > 3 || r_str_startswith (argv[0], "REcdn?")) {
        DISPLAY_ERROR (
            "Usage: REcdn <search_term> <filter_flags>=   # Get information about collections, "
            "ordered by collection name, in descending order.\n"
            "\n"
            "Examples:\n"
            "| REcdn rat outp      # In total four filters available. [o] - order, [u] - user and "
            "[t] - creation time, [p] - public.\n"
            "| REcdn miner otp     # Search for collections with name miner, ordered by collection "
            "name, and are official only [o], team only [t] and public only [p]\n"
            "| REcdn mirai u       # user only [u]\n"
            "| REcdn bruteratel uo # user only [u], official only [o]\n"
            "| REcdn mysql utop    # Order of filter flags can change without changing the search "
            "results\n"
            "| REcdn mysql         # Search can be done without any filters as well!\n"
        );
        return R_CMD_STATUS_ERROR;
    }

    CString search_term = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString filters     = argv[2] && strlen (argv[2]) ? argv[2] : NULL;

    ReaiCollectionBasicInfoFilterFlags filter_flags = REAI_COLLECTION_BASIC_INFO_FILTER_HIDE_EMPTY;
    if (!str_to_filter_flags (filters, &filter_flags)) {
        DISPLAY_ERROR ("Failed to understand provided filter flags");
        return R_CMD_STATUS_ERROR;
    }

    if (reai_plugin_collection_basic_info (
            core,
            search_term,
            filter_flags,
            REAI_COLLECTION_BASIC_INFO_ORDER_BY_COLLECTION,
            REAI_COLLECTION_BASIC_INFO_ORDER_IN_DESC
        )) {
        return R_CMD_STATUS_OK;
    }
    return R_CMD_STATUS_ERROR;
}

/**
 * REcdm
 * */
R_IPI RCmdStatus
    reai_collection_basic_info_desc_model_handler (RCore* core, int argc, const char** argv) {
    if (argc < 2 || argc > 3 || r_str_startswith (argv[0], "REcdm?")) {
        DISPLAY_ERROR (
            "Usage: REcdm <search_term> <filter_flags>=   # Get information about collections, "
            "ordered by model version, in descending order.\n"
            "\n"
            "Examples:\n"
            "| REcdm rat outp      # In total four filters available. [o] - order, [u] - user and "
            "[t] - creation time, [p] - public.\n"
            "| REcdm miner otp     # Search for collections with name miner, ordered by model "
            "version, and are official only [o], team only [t] and public only [p]\n"
            "| REcdm mirai u       # user only [u]\n"
            "| REcdm bruteratel uo # user only [u], official only [o]\n"
            "| REcdm mysql utop    # Order of filter flags can change without changing the search "
            "results\n"
            "| REcdm mysql         # Search can be done without any filters as well!\n"
        );
        return R_CMD_STATUS_ERROR;
    }

    CString search_term = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString filters     = argv[2] && strlen (argv[2]) ? argv[2] : NULL;

    ReaiCollectionBasicInfoFilterFlags filter_flags = REAI_COLLECTION_BASIC_INFO_FILTER_HIDE_EMPTY;
    if (!str_to_filter_flags (filters, &filter_flags)) {
        DISPLAY_ERROR ("Failed to understand provided filter flags");
        return R_CMD_STATUS_ERROR;
    }

    if (reai_plugin_collection_basic_info (
            core,
            search_term,
            filter_flags,
            REAI_COLLECTION_BASIC_INFO_ORDER_BY_MODEL,
            REAI_COLLECTION_BASIC_INFO_ORDER_IN_DESC
        )) {
        return R_CMD_STATUS_OK;
    }
    return R_CMD_STATUS_ERROR;
}

/**
 * REcds
 * */
R_IPI RCmdStatus
    reai_collection_basic_info_desc_size_handler (RCore* core, int argc, const char** argv) {
    if (argc < 2 || argc > 3 || r_str_startswith (argv[0], "REcds?")) {
        DISPLAY_ERROR (
            "Usage: REcds <search_term> <filter_flags>=   # Get information about collections, "
            "ordered by collection size, in descending order.\n"
            "\n"
            "Examples:\n"
            "| REcds rat outp      # In total four filters available. [o] - order, [u] - user and "
            "[t] - creation time, [p] - public.\n"
            "| REcds miner otp     # Search for collections with name miner, ordered by collection "
            "size, and are official only [o], team only [t] and public only [p]\n"
            "| REcds mirai u       # user only [u]\n"
            "| REcds bruteratel uo # user only [u], official only [o]\n"
            "| REcds mysql utop    # Order of filter flags can change without changing the search "
            "results\n"
            "| REcds mysql         # Search can be done without any filters as well!\n"
        );
        return R_CMD_STATUS_ERROR;
    }

    CString search_term = argv[1] && strlen (argv[1]) ? argv[1] : NULL;
    CString filters     = argv[2] && strlen (argv[2]) ? argv[2] : NULL;

    ReaiCollectionBasicInfoFilterFlags filter_flags = REAI_COLLECTION_BASIC_INFO_FILTER_HIDE_EMPTY;
    if (!str_to_filter_flags (filters, &filter_flags)) {
        DISPLAY_ERROR ("Failed to understand provided filter flags");
        return R_CMD_STATUS_ERROR;
    }

    if (reai_plugin_collection_basic_info (
            core,
            search_term,
            filter_flags,
            REAI_COLLECTION_BASIC_INFO_ORDER_BY_COLLECTION_SIZE,
            REAI_COLLECTION_BASIC_INFO_ORDER_IN_DESC
        )) {
        return R_CMD_STATUS_OK;
    }
    return R_CMD_STATUS_ERROR;
}

// "REcd"
R_IPI RCmdStatus reai_collection_basic_info_desc_cmd_group_help_handler (
    RCore*       core,
    int          argc,
    const char** argv
) {
    UNUSED (core && argc);
    if (!r_str_startswith (argv[0], "REcd?")) {
        DISPLAY_ERROR (
            "ERROR: Command '%s' does not exist.\n"
            "ERROR: Displaying the help of command 'REcd'.\n\n",
            argv[0]
        );
    }

    DISPLAY_INFO (
        "Usage: REcd<tonms>   # Get information about collections, ordered in descending order.\n"
        "| REcdt <search_term> <filter_flags>= # Get information about collections, ordered by "
        "creation time, in descending order.\n"
        "| REcdo <search_term> <filter_flags>= # Get information about collections, ordered by "
        "collection owner, in descending order.\n"
        "| REcdn <search_term> <filter_flags>= # Get information about collections, ordered by "
        "collection name, in descending order.\n"
        "| REcdm <search_term> <filter_flags>= # Get information about collections, ordered by "
        "model version, in descending order.\n"
        "| REcds <search_term> <filter_flags>= # Get information about collections, ordered by "
        "collection size, in descending order.\n"
    );

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
