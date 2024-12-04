/**
 * @file : CmdHandlers.c
 * @date : 13th June 2024
 * @author : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright: Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

/* radare */
#include <r_anal.h>
#include <r_asm.h>
#include <r_cmd.h>
#include <r_core.h>
#include <r_lib.h>
#include <r_th.h>
#include <r_types.h>

/* revengai */
#include <Reai/Api/Response.h>
#include <Reai/Api/Reai.h>
#include <Reai/AnalysisInfo.h>
#include <Reai/Api/Api.h>
#include <Reai/Common.h>
#include <Reai/Config.h>
#include <Reai/Log.h>
#include <Reai/Types.h>

/* libc */
#include <r_util/r_sys.h>

/* plugin includes */
#include <Plugin.h>
#include <Table.h>

/**
 * NOTE: This is a background worker. Must not be used directly.
 * */
RThreadFunctionRet get_ai_models_in_bg (RThread *th) {
    ReaiPlugin *plugin = th->user;

    while (plugin->locked)
        ;

    plugin->locked = true;
    REAI_LOG_TRACE ("Plugin lock acquired");

    if (!plugin->ai_models) {
        plugin->ai_models = reai_cstr_vec_clone_create (
            reai_get_available_models (plugin->reai, plugin->reai_response)
        );

        if (plugin->ai_models) {
            REAI_LOG_TRACE ("Got the AI models");
        } else {
            REAI_LOG_ERROR (
                "Failed to get AI models. This might cause some features to fail working."
            );
        }
    }

    plugin->locked = false;
    REAI_LOG_TRACE ("Plugin lock released");

    return R_TH_STOP;
}

RThreadFunctionRet perform_auth_check_in_bg (RThread *th) {
    ReaiPlugin *plugin = th->user;

    while (plugin->locked)
        ;

    plugin->locked = true;
    REAI_LOG_TRACE ("Plugin lock acquired");

    if (reai_auth_check (
            plugin->reai,
            plugin->reai_response,
            plugin->reai_config->host,
            plugin->reai_config->apikey
        )) {
        REAI_LOG_TRACE ("Auth check success");
    } else {
        REAI_LOG_ERROR (
            "RevEngAI auth check failed. You won't be able to use any of the plugin features!"
        );
    }

    plugin->locked = false;
    REAI_LOG_TRACE ("Plugin lock released");

    return R_TH_STOP;
}

// TODO: remove this in next radare release
const char *radare_analysis_function_force_rename (RAnalFunction *fcn, CString name) {
    r_return_val_if_fail (fcn && name, NULL);

    // first attempt to rename normally, if that fails we try force rename
    if (r_anal_function_rename (fcn, name)) {
        return fcn->name;
    }

    // {name}_{addr} is guaranteed to be unique
    const char *new_name = r_str_newf ("%s_%" PFMT64x, name, fcn->addr);
    bool        ok       = r_anal_function_rename (fcn, new_name);
    R_FREE (new_name);
    return ok ? fcn->name : NULL;
}

/**
 * @b Get name of function with given origin function id having max
 *    confidence.
 *
 * If multiple functions have same confidence level then the one that appears
 * first in the array will be returned.
 *
 * Returned pointer MUST NOT freed because it is owned by given @c fn_matches
 * vector. Destroying the vector will automatically free the returned string.
 *
 * @param fn_matches Array that contains all functions with their confidence levels.
 * @param origin_fn_id Function ID to search for.
 * @param confidence Pointer to @c Float64 value specifying min confidence level.
 *        If not @c NULL then value of max confidence of returned function name will
 *        be stored in this pointer.
 *        If @c NULL then just the function with max confidence will be selected.
 *
 * @return @c Name of function if present and has a confidence level greater than or equal to
 *            given confidence.
 * @return @c NULL otherwise.
 * */
PRIVATE CString get_function_name_with_max_confidence (
    ReaiAnnFnMatchVec *fn_matches,
    ReaiFunctionId     origin_fn_id,
    Float64           *required_confidence
) {
    if (!fn_matches) {
        DISPLAY_ERROR ("Function matches are invalid. Cannot proceed.");
        return NULL;
    }

    if (!origin_fn_id) {
        DISPLAY_ERROR ("Origin function ID is invalid. Cannot proceed.");
        return NULL;
    }

    Float64 max_confidence = 0;
    CString fn_name        = NULL;
    REAI_VEC_FOREACH (fn_matches, fn_match, {
        /* if function name starts with FUN_ then no need to rename */
        if (!strncmp (fn_match->nn_function_name, "FUN_", 4)) {
            continue;
        }

        /* otherwise find function with max confidence */
        if ((fn_match->confidence > max_confidence) &&
            (fn_match->origin_function_id == origin_fn_id)) {
            fn_name        = fn_match->nn_function_name;
            max_confidence = fn_match->confidence;
        }
    });

    if (required_confidence) {
        fn_name              = max_confidence >= *required_confidence ? fn_name : NULL;
        *required_confidence = max_confidence;
    }

    return fn_name;
}

/**
 * @b Get function infos for given binary id.
 *
 * The returned vector must be destroyed after use.
 *
 * @param bin_id
 *
 * @return @c ReaiFnInfoVec on success.
 * @return @c NULL otherwise.
 * */
PRIVATE ReaiFnInfoVec *get_fn_infos (ReaiBinaryId bin_id) {
    if (!bin_id) {
        DISPLAY_ERROR (
            "Invalid binary ID provied. Cannot fetch function info list from RevEng.AI servers."
        );
        return NULL;
    }

    /* get function names for all functions in the binary (this is why we need analysis) */
    ReaiFnInfoVec *fn_infos = reai_get_basic_function_info (reai(), reai_response(), bin_id);
    if (!fn_infos) {
        DISPLAY_ERROR ("Failed to get binary function names.");
        return NULL;
    }

    if (!fn_infos->count) {
        DISPLAY_ERROR ("Current binary does not have any function.");
        return NULL;
    }

    /* try cloning */
    fn_infos = reai_fn_info_vec_clone_create (fn_infos);
    if (!fn_infos) {
        DISPLAY_ERROR ("FnInfos vector clone failed");
        return NULL;
    }

    return fn_infos;
}

/**
 * @b Get function matches for given binary id.
 *
 * The returned vector must be destroyed after use.
 *
 * @param bin_id
 * @param max_results
 * @param max_dist
 * @param collections
 *
 * @return @c ReaiAnnFnMatchVec on success.
 * @return @c NULL otherwise.
 * */
PRIVATE ReaiAnnFnMatchVec *get_fn_matches (
    ReaiBinaryId bin_id,
    Uint32       max_results,
    Float64      max_dist,
    CStrVec     *collections,
    Bool         debug_mode
) {
    if (!bin_id) {
        DISPLAY_ERROR ("Invalid binary ID provided. Cannot get function matches.");
        return NULL;
    }

    ReaiAnnFnMatchVec *fn_matches = reai_batch_binary_symbol_ann (
        reai(),
        reai_response(),
        bin_id,
        max_results,
        max_dist,
        collections,
        debug_mode
    );

    if (!fn_matches) {
        DISPLAY_ERROR ("Failed to get ANN binary symbol similarity result");
        return NULL;
    }

    if (!fn_matches->count) {
        DISPLAY_ERROR ("No similar functions found.");
        return NULL;
    }

    /* try clone */
    fn_matches = reai_ann_fn_match_vec_clone_create (fn_matches);
    if (!fn_matches) {
        DISPLAY_ERROR ("ANN Fn Match vector clone failed.");
        return NULL;
    }

    return fn_matches;
}
/**
 * Get Reai Plugin object.
 * */
ReaiPlugin *reai_plugin() {
    static ReaiPlugin *plugin = NULL;

    if (plugin) {
        while (plugin->locked)
            ;
        return plugin;
    }

    if (!(plugin = NEW (ReaiPlugin))) {
        DISPLAY_ERROR (ERR_OUT_OF_MEMORY);
        return NULL;
    }

    return plugin;
}

/**
 * @b Get function boundaries from given binary file.
 *
 *@NOTE: returned vector is owned by the caller and hence is
 * responsible for destroying the vector after use.
 *
 * @param core
 *
 * @return @c ReaiFnInfoVec reference on success.
 * @return @c NULL otherwise.
 *  */
ReaiFnInfoVec *reai_plugin_get_function_boundaries (RCore *core) {
    if (!core) {
        DISPLAY_ERROR ("Invalid radare core provided. Cannot get function boundaries.");
        return NULL;
    }


    /* prepare symbols info  */
    RList         *fns           = core->anal->fcns;
    ReaiFnInfoVec *fn_boundaries = reai_fn_info_vec_create();

    /** NOTE: We're sending addresses here in form of `base + offset`
     * but what we receive from reveng.ai is in `offset` only form */

    /* add all symbols corresponding to functions */
    RListIter     *fn_iter = NULL;
    RAnalFunction *fn      = NULL;
    r_list_foreach (fns, fn_iter, fn) {
        ReaiFnInfo fn_info = {
            .name  = fn->name,
            .vaddr = fn->addr,
            .size  = r_anal_function_linear_size (fn)
        };

        if (!reai_fn_info_vec_append (fn_boundaries, &fn_info)) {
            DISPLAY_ERROR ("Failed to append function info in function boundaries list.");
            reai_fn_info_vec_destroy (fn_boundaries);
            return NULL;
        }
    }

    return fn_boundaries;
}

/**
 * @brief Called by radare when loading reai_plugin()-> This is the plugin
 * entrypoint where we register all the commands and corresponding handlers.
 *
 * To know about how commands work for this plugin, refer to `CmdGen/README.md`.
 * */
Bool reai_plugin_init (RCore *core) {
    reai_plugin_deinit();

    if (!core) {
        DISPLAY_ERROR ("Invalid radare core provided.");
        return false;
    }

    /* load default config */
    reai_plugin()->reai_config = reai_config_load (NULL);
    if (!reai_config()) {
        DISPLAY_ERROR (
            "Failed to load RevEng.AI toolkit config file. Please make sure the config exists or "
            "create a config using the plugin."
        );
        return false;
    }

    /* initialize reai object. */
    if (!reai()) {
        reai_plugin()->reai = reai_create (reai_config()->host, reai_config()->apikey);
        if (!reai()) {
            DISPLAY_ERROR ("Failed to create Reai object.");
            return false;
        }
    }

    /* create response object */
    if (!reai_response()) {
        reai_plugin()->reai_response = NEW (ReaiResponse);
        if (!reai_response_init (reai_response())) {
            DISPLAY_ERROR ("Failed to create/init ReaiResponse object.");
            FREE (reai_response());
            return false;
        }
    }

    /* create bg workers */
    reai_plugin()->bg_workers = reai_bg_workers_vec_create();
    if (!reai_bg_workers()) {
        DISPLAY_ERROR ("Failed to initialize background workers vec.");
        return false;
    }

    if (!reai_plugin_add_bg_work (perform_auth_check_in_bg, reai_plugin())) {
        REAI_LOG_ERROR ("Failed to add perform-auth-check bg worker.");
    }

    if (!reai_plugin_add_bg_work (get_ai_models_in_bg, reai_plugin())) {
        REAI_LOG_ERROR ("Failed to add get-ai-models bg worker.");
    }

    // get binary id
    reai_binary_id() = r_config_get_i (core->config, "reai.id");

    // if file is not loaded from a project, or the project does not have a binary id
    // then binary id will be 0
    if (!reai_binary_id()) {
        // unlock and create a variable so that in future we can update it
        r_config_lock (core->config, false);
        r_config_set_i (core->config, "reai.id", 0);
        r_config_lock (core->config, true);
    }

    return true;
}

/**
 * @b Must be called before unloading the plugin.
 *
 * @param core
 *
 * @return true on successful plugin init.
 * @return false otherwise.
 * */
Bool reai_plugin_deinit() {
    /* this must be destroyed first and set to NULL to signal the background
    * worker thread to stop working */
    if (reai()) {
        reai_destroy (reai());
        reai_plugin()->reai = NULL;
    }

    if (reai_response()) {
        reai_response_deinit (reai_response());
        FREE (reai_response());
    }

    if (reai_config()) {
        reai_config_destroy (reai_config());
    }

    if (reai_ai_models()) {
        reai_cstr_vec_destroy (reai_ai_models());
        reai_plugin()->ai_models = NULL;
    }

    if (reai_bg_workers()) {
        // wait for and destroy all threads first
        REAI_VEC_FOREACH (reai_bg_workers(), th, {
            r_th_kill (*th, true);
            r_th_free (*th);
        });

        reai_bg_workers_vec_destroy (reai_bg_workers());
        reai_plugin()->bg_workers = NULL;
    }

    memset (reai_plugin(), 0, sizeof (ReaiPlugin));

    return true;
}

Bool reai_plugin_add_bg_work (RThreadFunction fn, void *user_data) {
    if (!fn) {
        DISPLAY_ERROR ("Invalid function provided. Cannot start background work");
        return false;
    }

    const Size MAX_WORKERS = 16;
    if (reai_bg_workers()->count >= MAX_WORKERS) {
        // destroy oldest thread
        RThread *th = reai_bg_workers()->items[0];
        r_th_wait (th);
        r_th_free (th);

        // remove oldest thread
        reai_bg_workers_vec_remove (reai_bg_workers(), 0);
    }

    // create new thread
    RThread *th = r_th_new (fn, user_data, 0);
    if (!th) {
        DISPLAY_ERROR ("Failed to create a new background worker thread. Task won't be executed.");
        return false;
    }
    r_th_start (th);

    // insert at end
    if (!reai_bg_workers_vec_append (reai_bg_workers(), &th)) {
        DISPLAY_WARN (
            "Failed to add background worker thread to collection of threads. This might cause "
            "memory leaks because thread object won't be destroyed."
        );
        return false;
    }

    return true;
}

/**
 * @b Check whether or not the default config exists.
 *
 * @return @c true on success.
 * @return @c NULL otherwise.
 * */
Bool reai_plugin_check_config_exists() {
    return !!reai_config();
}

/**
 * @b Save given config to a file.
 *
 * @param host
 * @param api_key
 * @param model
 * @param log_dir_path
 * */
Bool reai_plugin_save_config (CString host, CString api_key) {
    // if reai object is not created, create
    if (!reai()) {
        reai_plugin()->reai = reai_create (host, api_key);
        if (!reai()) {
            DISPLAY_ERROR ("Failed to create Reai object.");
            return false;
        }
    }

    /* create response object */
    if (!reai_response()) {
        reai_plugin()->reai_response = NEW (ReaiResponse);
        if (!reai_response_init (reai_response())) {
            DISPLAY_ERROR ("Failed to create/init ReaiResponse object.");
            FREE (reai_response());
            return false;
        }
    }

    if (!reai_auth_check (reai(), reai_response(), host, api_key)) {
        DISPLAY_ERROR ("Invalid host or api-key provided. Please check once again and retry.");
        return false;
    }

    CString reai_config_file_path = reai_config_get_default_path();
    if (!reai_config_file_path) {
        DISPLAY_ERROR ("Failed to get config file default path.");
        return false;
    } else {
        REAI_LOG_INFO ("Config will be saved at %s\n", reai_config_file_path);
    }

    FILE *reai_config_file = fopen (reai_config_file_path, "w");
    if (!reai_config_file) {
        DISPLAY_ERROR ("Failed to open config file. %s", strerror (errno));
        return false;
    }

    fprintf (reai_config_file, "host         = \"%s\"\n", host);
    fprintf (reai_config_file, "apikey       = \"%s\"\n", api_key);

    fclose (reai_config_file);

    return true;
}

/**
 * @b If a binary file is opened, then upload the binary file.
 *
 * @param core To get the currently opened binary file in radare.
 *
 * @return true on successful upload.
 * @return false otherwise.
 * */
Bool reai_plugin_upload_opened_binary_file (RCore *core) {
    if (!core) {
        DISPLAY_ERROR ("Invalid radare core provided. Cannot perform upload.");
        return false;
    }

    /* get file path */
    CString binfile_path = reai_plugin_get_opened_binary_file_path (core);
    if (!binfile_path) {
        DISPLAY_ERROR ("No binary file opened in radare. Cannot perform upload.");
        return false;
    }

    /* check if file is already uploaded or otherwise upload */
    CString sha256 = reai_upload_file (reai(), reai_response(), binfile_path);
    if (!sha256) {
        DISPLAY_ERROR ("Failed to upload binary file.");
        FREE (binfile_path);
        return false;
    }

    return true;
}

/**
 * @b Create a new analysis for currently opened binary file.
 *
 * This method first checks whether upload already exists for a given file path.
 * If upload does exist then the existing upload is used.
 *
 * @param core To get currently opened binary file in radare/cutter.
 *
 * @return true on success.
 * @return false otherwise.
 * */
Bool reai_plugin_create_analysis_for_opened_binary_file (
    RCore  *core,
    CString prog_name,
    CString cmdline_args,
    CString ai_model,
    Bool    is_private
) {
    if (!core) {
        DISPLAY_ERROR ("Invalid radare core provided. Cannot create analysis.");
        return false;
    }

    if (!prog_name || !strlen (prog_name)) {
        DISPLAY_ERROR ("Invalid program name provided. Cannot create analysis.");
        return false;
    }

    if (!ai_model || !strlen (ai_model)) {
        DISPLAY_ERROR ("Invalid AI model provided. Cannot create analysis.");
        return false;
    }

    /* warn the use if no analysis exists */
    if (!reai_plugin_get_radare_analysis_function_count (core)) {
        DISPLAY_ERROR (
            "It seems that radare analysis hasn't been performed yet. "
            "Please create radare analysis "
            "first."
        );
        return false;
    }

    RBin *bin = reai_plugin_get_opened_binary_file (core);
    if (!bin) {
        DISPLAY_ERROR ("No binary file opened. Cannot create analysis");
        return false;
    }

    CString binfile_path = reai_plugin_get_opened_binary_file_path (core);
    if (!binfile_path) {
        DISPLAY_ERROR ("Failed to get binary file full path. Cannot create analysis");
        return false;
    }

    CString sha256 = reai_upload_file (reai(), reai_response(), binfile_path);
    if (!sha256) {
        DISPLAY_ERROR ("Failed to upload file");
        FREE (binfile_path);
        return false;
    }
    sha256 = strdup (sha256);
    REAI_LOG_INFO ("Binary uploaded successfully.");

    /* get function boundaries to create analysis */
    ReaiFnInfoVec *fn_boundaries = reai_plugin_get_function_boundaries (core);
    if (!fn_boundaries) {
        DISPLAY_ERROR (
            "Failed to get function boundary information from radare "
            "analysis. Cannot create "
            "RevEng.AI analysis."
        );
        FREE (sha256);
        FREE (binfile_path);
        return false;
    }

    /* create analysis */
    ReaiBinaryId bin_id = reai_create_analysis (
        reai(),
        reai_response(),
        ai_model,
        reai_plugin_get_opened_binary_file_baseaddr (core),
        fn_boundaries,
        is_private,
        sha256,
        prog_name,
        cmdline_args, // cmdline args
        r_bin_get_size (bin)
    );

    if (!bin_id) {
        DISPLAY_ERROR ("Failed to create RevEng.AI analysis.");
        FREE (sha256);
        FREE (binfile_path);
        reai_fn_info_vec_destroy (fn_boundaries);
        return false;
    }

    /* destroy after use */
    FREE (sha256);
    FREE (binfile_path);
    reai_fn_info_vec_destroy (fn_boundaries);

    reai_binary_id() = bin_id;
    r_config_set_i (core->config, "reai.id", reai_binary_id());

    return true;
}

/**
 * @b Apply existing analysis to opened binary file.
 *
 * @param[in]  core
 * @param[in]  bin_id        RevEng.AI analysis binary ID.
 * @param[in]  apply_to_all  Rename all functions, even those with valid names.
 *                           Otherwise, rename just those starting with "fcn.".
 *
 * @return True on successful application of renames
 * @return False otherwise.
 * */
Bool reai_plugin_apply_existing_analysis (RCore *core, ReaiBinaryId bin_id, Bool apply_to_all) {
    if (!core) {
        DISPLAY_ERROR ("Invalid radare core provided. Cannot apply analysis.");
        return false;
    }

    if (!bin_id) {
        DISPLAY_ERROR ("Invalid RevEng.AI binary id provided. Cannot apply analysis.");
        return false;
    }

    /* an analysis must already exist in order to make auto-analysis work */
    ReaiAnalysisStatus analysis_status = reai_get_analysis_status (reai(), reai_response(), bin_id);
    CString            status_str      = reai_analysis_status_to_cstr (analysis_status);
    if (analysis_status != REAI_ANALYSIS_STATUS_COMPLETE) {
        DISPLAY_WARN (
            "Analysis not complete yet. Please wait for some time and "
            "then try again! Current analysis status = %s for binary id = %llu",
            status_str ? status_str : "INVALID",
            bin_id
        );
        return false;
    }

    /* names of current functions */
    ReaiFnInfoVec *fn_infos = get_fn_infos (bin_id);
    if (!fn_infos) {
        DISPLAY_ERROR ("Failed to get funciton info for opened binary.");
        return false;
    }

    /* prepare table and print info */
    ReaiPluginTable *successful_renames = reai_plugin_table_create();
    if (!successful_renames) {
        DISPLAY_ERROR ("Failed to create table to display successful renam operations.");
        reai_fn_info_vec_destroy (fn_infos);
        return false;
    }
    reai_plugin_table_set_title (successful_renames, "Successfully Renamed Functions");
    reai_plugin_table_set_columnsf (successful_renames, "ssn", "old_name", "new_name", "address");

    ReaiPluginTable *failed_renames = reai_plugin_table_create();
    if (!failed_renames) {
        DISPLAY_ERROR ("Failed to create table to display failed rename operations.");
        reai_plugin_table_destroy (successful_renames);
        reai_fn_info_vec_destroy (fn_infos);
        return false;
    }
    reai_plugin_table_set_title (failed_renames, "Failed Function Rename Operations");
    reai_plugin_table_set_columnsf (
        failed_renames,
        "sssn",
        "old_name",
        "new_name",
        "reason",
        "address"
    );

    Bool success_cases_exist = false;
    Bool failed_cases_exist  = false;

    /* display information about what renames will be performed */ /* add rename information to new name mapping */
    /* rename the functions in radare */
    CString old_name = NULL;

    REAI_VEC_FOREACH (fn_infos, fn, {
        if (old_name) {
            FREE (old_name);
        }

        Uint64 fn_addr = fn->vaddr + reai_plugin_get_opened_binary_file_baseaddr (core);

        /* get function */
        RAnalFunction *r_fn = r_anal_get_function_at (core->anal, fn_addr);
        if (r_fn) {
            old_name         = strdup (r_fn->name);
            CString new_name = fn->name;

            // Skip if name already matches
            if (!strcmp (r_fn->name, fn->name)) {
                REAI_LOG_INFO (
                    "Name \"%s\" already matches for function at address %llx",
                    old_name,
                    fn_addr
                );
                continue;
            }

            // Rename only those functions whose name starts with "fcn."
            if (apply_to_all || !strncmp (r_fn->name, "fcn.", 4)) {
                // NOTE: Not comparing function size here. Can this create problems in future??
                if (radare_analysis_function_force_rename (r_fn, new_name)) {
                    reai_plugin_table_add_rowf (
                        successful_renames,
                        "ssx",
                        old_name,
                        r_fn->name,
                        fn_addr
                    );
                    success_cases_exist = true;
                } else {
                    reai_plugin_table_add_rowf (
                        failed_renames,
                        "sssx",
                        old_name,
                        new_name,
                        "radare rename error",
                        fn_addr
                    );
                    failed_cases_exist = true;
                }
            } else {
                REAI_LOG_INFO (
                    "Not renaming. Human readbale name already present : \"%s\"",
                    r_fn->name
                );
            }
        } else { // If no radare funciton exists at given address
            reai_plugin_table_add_rowf (
                failed_renames,
                "sssx",
                "N/A",
                "N/A",
                "radare function not found at address",
                fn_addr
            );
            failed_cases_exist = true;
        }
    });

    if (old_name) {
        FREE (old_name);
    }

    if (success_cases_exist) {
        reai_plugin_table_show (successful_renames);
    }

    if (failed_cases_exist) {
        reai_plugin_table_show (failed_renames);
    }

    // Mass Destruction!!!!
    reai_plugin_table_destroy (successful_renames);
    reai_plugin_table_destroy (failed_renames);
    reai_fn_info_vec_destroy (fn_infos);

    reai_binary_id() = bin_id;
    r_config_set_i (core->config, "reai.id", reai_binary_id());

    return true;
}

/**
 * @b Get analysis status for given binary id (analyis id).
 *
 * @param core
 *
 * @return @c ReaiAnalysisStatus other than @c REAI_ANALYSIS_STATUS_INVALID on
 * success.
 * @return @c REAI_ANALYSIS_STATUS_INVALID otherwise.
 * */
ReaiAnalysisStatus reai_plugin_get_analysis_status_for_binary_id (ReaiBinaryId binary_id) {
    if (!binary_id) {
        DISPLAY_ERROR ("Invalid binary id provided. Cannot fetch analysis status.");
        return REAI_ANALYSIS_STATUS_INVALID;
    }

    ReaiAnalysisStatus analysis_status =
        reai_get_analysis_status (reai(), reai_response(), binary_id);

    if (!analysis_status) {
        DISPLAY_ERROR ("Failed to get analysis status from RevEng.AI servers.");
        return REAI_ANALYSIS_STATUS_INVALID;
    }

    REAI_LOG_TRACE (
        "Fetched analysis status \"%s\".",
        reai_analysis_status_to_cstr (analysis_status)
    );
    return analysis_status;
}

/**
 * @b Automatically rename all funcitons with matching names.
 *
 * @param core To get currently opened binary file.
 * @param max_distance RevEng.AI function matching parameter.
 * @param max_results per function RevEng.AI function matching parameter.
 * @param max_distance RevEng.AI function matching parameter.
 * */
Bool reai_plugin_auto_analyze_opened_binary_file (
    RCore  *core,
    Size    max_results_per_function,
    Float64 min_confidence,
    Bool    debug_mode,
    Bool    apply_to_all
) {
    if (!core) {
        DISPLAY_ERROR ("Invalid radare core provided. Cannot perform auto-analysis.");
        return false;
    }

    /* try to get latest analysis for loaded binary (if exists) */
    ReaiBinaryId bin_id = reai_binary_id();
    if (!bin_id) {
        DISPLAY_ERROR (
            "Please apply an existing analysis or create a new one. I cannot perform auto-analysis "
            "without an existing RevEng.AI analysis."
        );
        return false;
    }

    /* an analysis must already exist in order to make auto-analysis work */
    ReaiAnalysisStatus analysis_status = reai_plugin_get_analysis_status_for_binary_id (bin_id);
    if (analysis_status != REAI_ANALYSIS_STATUS_COMPLETE) {
        DISPLAY_WARN (
            "Analysis not complete yet. Please wait for some time and "
            "then try again!"
        );
        return false;
    }

    /* names of current functions */
    ReaiFnInfoVec *fn_infos = get_fn_infos (bin_id);
    if (!fn_infos) {
        DISPLAY_ERROR ("Failed to get funciton info for opened binary.");
        return false;
    }

    /* function matches */
    ReaiAnnFnMatchVec *fn_matches =
        get_fn_matches (bin_id, max_results_per_function, 1 - min_confidence, NULL, debug_mode);
    if (!fn_matches) {
        DISPLAY_ERROR ("Failed to get function matches for opened binary.");
        reai_fn_info_vec_destroy (fn_infos);
        return false;
    }

    /* new vector where new names of functions will be stored */
    ReaiFnInfoVec *new_name_mapping = reai_fn_info_vec_create();
    if (!new_name_mapping) {
        DISPLAY_ERROR ("Failed to create a new-name-mapping object.");
        reai_ann_fn_match_vec_destroy (fn_matches);
        reai_fn_info_vec_destroy (fn_infos);
        return false;
    }

    /* prepare table and print info */
    ReaiPluginTable *successful_renames = reai_plugin_table_create();
    if (!successful_renames) {
        DISPLAY_ERROR ("Failed to create table to display new name mapping.");
        reai_fn_info_vec_destroy (new_name_mapping);
        reai_ann_fn_match_vec_destroy (fn_matches);
        reai_fn_info_vec_destroy (fn_infos);
        return false;
    }
    reai_plugin_table_set_columnsf (
        successful_renames,
        "ssfn",
        "Old Name",
        "New Name",
        "Confidence",
        "Address"
    );

    ReaiPluginTable *failed_renames = reai_plugin_table_create();
    if (!failed_renames) {
        DISPLAY_ERROR ("Failed to create table to display new name mapping.");
        reai_fn_info_vec_destroy (new_name_mapping);
        reai_ann_fn_match_vec_destroy (fn_matches);
        reai_fn_info_vec_destroy (fn_infos);
        return false;
    }
    reai_plugin_table_set_columnsf (
        failed_renames,
        "sssn",
        "Old Name",
        "New Name",
        "Reason",
        "Address"
    );

    Bool success_cases_exist = false;
    Bool failed_cases_exist  = false;

    /* display information about what renames will be performed */ /* add rename information to new name mapping */
    /* rename the functions in radare */
    CString old_name = NULL;
    REAI_VEC_FOREACH (fn_infos, fn, {
        if (old_name) {
            FREE (old_name);
        }

        Float64 confidence = min_confidence;
        CString new_name   = NULL;
        old_name           = strdup (fn->name);

        Uint64 fn_addr = fn->vaddr + reai_plugin_get_opened_binary_file_baseaddr (core);

        /* if we get a match with required confidence level then we add to rename */
        if ((new_name = get_function_name_with_max_confidence (fn_matches, fn->id, &confidence))) {
            /* If functions already are same then no need to rename */
            if (!strcmp (new_name, old_name)) {
                REAI_LOG_INFO (
                    "Name \"%s\" already matches for function at address %llx",
                    old_name,
                    fn_addr
                );
                continue;
            }

            /* get function */
            RAnalFunction *r_fn = r_anal_get_function_at (core->anal, fn_addr);
            if (apply_to_all || !strncmp (r_fn->name, "fcn.", 4)) {
                if (r_fn) {
                    if (radare_analysis_function_force_rename (r_fn, new_name)) {
                        reai_plugin_table_add_rowf (
                            successful_renames,
                            "ssfx",
                            old_name,
                            new_name,
                            confidence,
                            fn_addr
                        );

                        reai_fn_info_vec_append (
                            new_name_mapping,
                            &((ReaiFnInfo) {.name = new_name, .id = fn->id})
                        );

                        success_cases_exist = true;
                    } else {
                        reai_plugin_table_add_rowf (
                            failed_renames,
                            "sssx",
                            old_name,
                            new_name,
                            "radare rename error",
                            fn_addr
                        );
                        failed_cases_exist = true;
                    }
                } else { // If no radare funciton exists at given address
                    reai_plugin_table_add_rowf (
                        failed_renames,
                        "sssx",
                        old_name,
                        new_name,
                        "function not found",
                        fn_addr
                    );
                    failed_cases_exist = true;
                }
            } else {
                REAI_LOG_TRACE (
                    "Skipping rename for \"%s\". Name already looks valid to me",
                    r_fn->name
                );
            }
        } else { // If not able to find a function with given confidence
            reai_plugin_table_add_rowf (
                failed_renames,
                "sssx",
                old_name,
                "n/a",
                "match not found",
                fn->vaddr
            );
            failed_cases_exist = true;
        }
    });

    if (old_name) {
        FREE (old_name);
    }

    if (success_cases_exist) {
        reai_plugin_table_show (successful_renames);
    }

    if (failed_cases_exist) {
        reai_plugin_table_show (failed_renames);
    }

    /* perform a batch rename */
    if (new_name_mapping->count) {
        // NOTE: in a meeting it was assured by product management lead that this api endpoint will never fail
        // If it does, then the information displayed by tables above won't concurr with the message that will
        // be displayed below on failure.

        Bool res = reai_batch_renames_functions (reai(), reai_response(), new_name_mapping);
        if (!res) {
            DISPLAY_ERROR ("Failed to rename all functions in binary");
        }
    } else {
        eprintf ("No function will be renamed.\n");
    }

    reai_plugin_table_destroy (successful_renames);
    reai_plugin_table_destroy (failed_renames);
    reai_fn_info_vec_destroy (new_name_mapping);
    reai_ann_fn_match_vec_destroy (fn_matches);
    reai_fn_info_vec_destroy (fn_infos);

    return true;
}

/**
 * @b Search for function with given name and get the corresponding function id.
 *
 * @param core
 * @param fn_name
 *
 * @return Non-zero function ID corresponding to given function name on success, and if found.
 * @return zero otherwise.
 * */
ReaiFunctionId reai_plugin_get_function_id_for_radare_function (RCore *core, RAnalFunction *r_fn) {
    if (!core) {
        DISPLAY_ERROR (
            "Invalid radare core provided. Cannot fetch function ID for given function name."
        );
        return 0;
    }

    if (!r_fn || !r_fn->name) {
        DISPLAY_ERROR ("Invalid radare function provided. Cannot get a function ID.");
        return 0;
    }

    ReaiBinaryId bin_id = reai_binary_id();
    if (!bin_id) {
        DISPLAY_ERROR (
            "Please create a new analysis or apply an existing analysis. I need an existing "
            "analysis to get function information."
        );
        return 0;
    }

    ReaiFnInfoVec *fn_infos = NULL;
    /* avoid making multiple calls subsequent calls to same endpoint if possible */
    if (reai_response()->type == REAI_RESPONSE_TYPE_BASIC_FUNCTION_INFO) {
        REAI_LOG_TRACE ("Using previously fetched response of basic function info.");

        fn_infos = reai_response()->basic_function_info.fn_infos;
    } else {
        REAI_LOG_TRACE ("Fetching basic function info again");

        fn_infos = reai_get_basic_function_info (reai(), reai_response(), bin_id);
        if (!fn_infos) {
            DISPLAY_ERROR (
                "Failed to get function info list for opened binary file from RevEng.AI servers."
            );
            return 0;
        }
    }

    Uint64 base_addr = reai_plugin_get_opened_binary_file_baseaddr (core);

    for (ReaiFnInfo *fn_info = fn_infos->items; fn_info < fn_infos->items + fn_infos->count;
         fn_info++) {
        Uint64 min_addr = r_anal_function_min_addr (r_fn) - base_addr;
        Uint64 max_addr = r_anal_function_max_addr (r_fn) - base_addr;

        if (min_addr <= fn_info->vaddr && fn_info->vaddr <= max_addr) {
            REAI_LOG_TRACE (
                "Found function ID for radare function \"%s\" (\"%s\"): [%llu]",
                r_fn->name,
                fn_info->name,
                fn_info->id
            );
            return fn_info->id;
        }
    };

    REAI_LOG_TRACE ("Function ID not found for function \"%s\"", r_fn->name);

    return 0;
}

/**
 * @b Get a table of similar function name data.
 *
 * @param core
 * @param fcn_name Function name to search simlar functions for,
 * @param max_results_count
 * @param confidence
 * @param debug_mode
 *
 * @return @c ReaiPluginTable containing search suggestions on success.
 * @return @c NULL when no suggestions found.
 * */
Bool reai_plugin_search_and_show_similar_functions (
    RCore  *core,
    CString fcn_name,
    Size    max_results_count,
    Float32 confidence,
    Bool    debug_mode
) {
    if (!core) {
        DISPLAY_ERROR ("Invalid radare core porivded. Cannot perform similarity search.");
        return false;
    }

    if (!fcn_name) {
        DISPLAY_ERROR ("Invalid function name porivded. Cannot perform similarity search.");
        return false;
    }

    RAnalFunction *fn = r_anal_get_function_byname (core->anal, fcn_name);
    if (!fn) {
        DISPLAY_ERROR ("Provided function name does not exist. Cannot get similar function names.");
        return false;
    }

    ReaiFunctionId fn_id = reai_plugin_get_function_id_for_radare_function (core, fn);
    if (!fn_id) {
        DISPLAY_ERROR (
            "Failed to get function id of given function. Cannot get similar function names."
        );
        return false;
    }

    Float32            maxDistance = 1 - confidence;
    ReaiAnnFnMatchVec *fnMatches   = reai_batch_function_symbol_ann (
        reai(),
        reai_response(),
        fn_id,
        NULL, // speculative fn ids
        max_results_count,
        maxDistance,
        NULL, // collections
        debug_mode
    );

    if (fnMatches->count) {
        // Populate table
        ReaiPluginTable *table = reai_plugin_table_create();
        reai_plugin_table_set_columnsf (
            table,
            "sfns",
            "Function Name",
            "Confidence",
            "Function ID",
            "Binary Name"
        );
        reai_plugin_table_set_title (table, "Function Similarity Search Results");

        REAI_VEC_FOREACH (fnMatches, fnMatch, {
            reai_plugin_table_add_rowf (
                table,
                "sfns",
                fnMatch->nn_function_name,
                fnMatch->confidence,
                fnMatch->nn_function_id,
                fnMatch->nn_binary_name
            );
            REAI_LOG_TRACE (
                "Similarity Search Suggestion = (.name = \"%s\", .confidence = \"%lf\", "
                ".function_id = \"%llu\", .binary_name = \"%s\")",
                fnMatch->nn_function_name,
                fnMatch->confidence,
                fnMatch->nn_function_id,
                fnMatch->nn_binary_name
            );
        });

        reai_plugin_table_show (table);
        reai_plugin_table_destroy (table);
        return true;
    } else {
        return false;
    }
}

/**
 * @b Get referfence to @c RBinFile for currently opened binary file.
 *
 * @param core
 *
 * @return @c RBinFile if a binary file is opened (on success).
 * @return @c NULL otherwise.
 * */
RBin *reai_plugin_get_opened_binary_file (RCore *core) {
    if (!core) {
        DISPLAY_ERROR ("Invalid radare core provided. Cannot get opened binary file.");
        return NULL;
    }

    if (!core->bin) {
        DISPLAY_ERROR (
            "Seems like no binary file is opened yet. Binary container object is invalid. Cannot "
            "get opened binary file."
        );
        return NULL;
    }

    return core->bin;
}

/**
 * @b Get path of currently opened binary file.
 *
 * The returned string is owned by caller and must be passed to FREE.
 *
 * @param core
 *
 * @return @c CString if a binary file is opened.
 * @return @c NULL otherwise.
 * */
CString reai_plugin_get_opened_binary_file_path (RCore *core) {
    RBin *bin = reai_plugin_get_opened_binary_file (core);
    return bin ? r_file_abspath (bin->file) : NULL;
}

/**
 * @b Get base address of currently opened binary file.
 *
 * @param core
 *
 * @return @c Base address if a binary file is opened.
 * @return @c 0 otherwise.
 * */
Uint64 reai_plugin_get_opened_binary_file_baseaddr (RCore *core) {
    RBin *bin = reai_plugin_get_opened_binary_file (core);
    return bin ? r_bin_get_baddr (bin) : 0;
}

/**
 * @b Get number of functions detected by radare's own analysis.
 *
 * @param core To get analysis information.
 *
 * @return number of functions on success.
 * @return 0 otherwise.
 * */
Uint64 reai_plugin_get_radare_analysis_function_count (RCore *core) {
    if (!core) {
        DISPLAY_ERROR ("Invalid radare core provided. Cannot get analysis function count.");
        return 0;
    }

    if (!core->anal) {
        DISPLAY_ERROR (
            "Seems like radare analysis is not performed yet. The analysis object is invalid. "
            "Cannot get "
            "analysis function count."
        );
        return 0;
    }

    RList *fns = core->anal->fcns;
    if (!fns) {
        DISPLAY_ERROR (
            "Seems like radare analysis is not performed yet. Function list is invalid. Cannot get "
            "function with given name."
        );
        return 0;
    }

    return fns->length;
}
