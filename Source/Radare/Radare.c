/**
 * @file : Radare.c
 * @date : 2nd December 2024
 * @author : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright: Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

// radare
#include <r_core.h>
#include <r_util.h>

// plugin
#include <Radare/CmdHandlers.h>
#include <Plugin.h>

// reai
#include <Reai/Log.h>
#include <Reai/Common.h>

static void split_args (const char *input, int *argc, char ***argv);
static void free_args (int argc, char **argv);

CStrVec *dmsgs[REAI_LOG_LEVEL_MAX];

/**
 * Display a message of given level in rizin shell.
 *
 * @param level
 * @param msg
 * */
void reai_plugin_display_msg (ReaiLogLevel level, CString msg) {
    if (!msg) {
        REAI_LOG_ERROR (ERR_INVALID_ARGUMENTS);
        return;
    }

    reai_plugin_append_msg (level, msg);

    /* append logs from each category */
    for (int x = 0; x < REAI_LOG_LEVEL_MAX; x++) {
        CStrVec *v = dmsgs[x];
        for (size_t l = 0; l < v->count; l++) {
            CString m = v->items[l];
            reai_log_printf (level, "rizin.display", m);
            r_cons_println (m);
            FREE (v->items[l]);
        }
        v->count = 0;
    }

    r_cons_flush();
}

/**
 * Apend a message to a vector to be displayed all at once later on.
 *
 * @param level
 * @param msg
 * */
void reai_plugin_append_msg (ReaiLogLevel level, CString msg) {
    if (!msg) {
        REAI_LOG_ERROR (ERR_INVALID_ARGUMENTS);
        return;
    }

    reai_cstr_vec_append (dmsgs[level], &msg);
}

int reai_r2_core_init (void *user, const char *cmd) {
    UNUSED (cmd);
    RCmd  *rcmd = (RCmd *)user;
    RCore *core = (RCore *)rcmd->data;

    for (int x = 0; x < REAI_LOG_LEVEL_MAX; x++) {
        dmsgs[x] = reai_cstr_vec_create();
    }

    if (!core) {
        DISPLAY_ERROR ("Invalid radare core provided. Cannot initialize plugin.");
        return false;
    }

    if (!reai_plugin_init (core)) {
        DISPLAY_ERROR ("Failed to initialize plugin.");
    }

    return true;
}

int reai_r2_core_fini (void *user, const char *cmd) {
    UNUSED (user && cmd);

    reai_plugin_deinit();

    for (int x = 0; x < REAI_LOG_LEVEL_MAX; x++) {
        reai_cstr_vec_destroy (dmsgs[x]);
        dmsgs[x] = NULL;
    }

    return true;
}

typedef struct ReaiCmdHandlerInfo {
    char cmd[8];
    RCmdStatus (*handler) (RCore *core, int argc, const char **argv);
    size_t cmdlen;
} ReaiCmdHandlerInfo;

static size_t             num_cmds           = 0;
static ReaiCmdHandlerInfo cmd_to_handler[64] = {0};

void reai_init_cmd_handler_infos() {
    ReaiCmdHandlerInfo handlers[] = {
        {  "REi",                         reai_plugin_initialize_handler, 0},
        {  "REm",                  reai_list_available_ai_models_handler, 0},
        {  "REh",                              reai_health_check_handler, 0},
        {  "REd",                              reai_ai_decompile_handler, 0},

        { "REac",                   reai_create_analysis_private_handler, 0},
        {"REacp",                    reai_create_analysis_public_handler, 0},
        { "REau",                          reai_ann_auto_analyze_handler, 0},
        {"REaud",           reai_ann_auto_analyze_restrict_debug_handler, 0},
        { "REap",                   reai_apply_existing_analysis_handler, 0},
        {  "REa",                   reai_analysis_cmd_group_help_handler, 0},

        { "REbl",                               reai_binary_link_handler, 0},
        {"REbsn",                     reai_binary_search_by_name_handler, 0},
        {"REbsh",                   reai_binary_search_by_sha256_handler, 0},
        { "REbs",                             reai_binary_search_handler, 0},
        {  "REb",                     reai_binary_cmd_group_help_handler, 0},

        { "REcl",                           reai_collection_link_handler, 0},
        {"REcat",            reai_collection_basic_info_asc_time_handler, 0},
        {"REcao",           reai_collection_basic_info_asc_owner_handler, 0},
        {"REcan",            reai_collection_basic_info_asc_name_handler, 0},
        {"REcam",           reai_collection_basic_info_asc_model_handler, 0},
        {"REcas",            reai_collection_basic_info_asc_size_handler, 0},
        { "REca",  reai_collection_basic_info_asc_cmd_group_help_handler, 0},
        {"REcdt",           reai_collection_basic_info_desc_time_handler, 0},
        {"REcdo",          reai_collection_basic_info_desc_owner_handler, 0},
        {"REcdn",           reai_collection_basic_info_desc_name_handler, 0},
        {"REcdm",          reai_collection_basic_info_desc_model_handler, 0},
        {"REcds",           reai_collection_basic_info_desc_size_handler, 0},
        { "REcd", reai_collection_basic_info_desc_cmd_group_help_handler, 0},
        {"REcsc",      reai_collection_search_by_collection_name_handler, 0},
        {"REcsb",          reai_collection_search_by_binary_name_handler, 0},
        {"REcsh",        reai_collection_search_by_binary_sha256_handler, 0},
        { "REcs",                         reai_collection_search_handler, 0},
        {  "REc",                 reai_collection_cmd_group_help_handler, 0},

        { "REfl",                   reai_get_basic_function_info_handler, 0},
        { "REfr",                           reai_rename_function_handler, 0},
        { "REfs",                reai_function_similarity_search_handler, 0},
        {"REfsd", reai_function_similarity_search_restrict_debug_handler, 0},
        {  "REf",                   reai_function_cmd_group_help_handler, 0},

        {"REart",                         reai_show_revengai_art_handler, 0},
    };
    num_cmds = sizeof (handlers) / sizeof (handlers[0]);

    for (size_t x = 0; x < num_cmds; x++) {
        ReaiCmdHandlerInfo *ho = &cmd_to_handler[x];
        ReaiCmdHandlerInfo *it = &handlers[x];

        memset (ho->cmd, 0, sizeof (ho->cmd));

        ho->cmdlen  = strlen (it->cmd);
        ho->handler = it->handler;
        memcpy (ho->cmd, it->cmd, ho->cmdlen);
    }
}

int reai_r2_core_cmd (void *user, const char *input) {
    RCore *core = (RCore *)user;

    if (!num_cmds) {
        reai_init_cmd_handler_infos();
    }

    if (r_str_startswith (input, "RE")) {
        int          argc = 0;
        const char **argv = NULL;
        split_args (input, &argc, (char ***)&argv);

        bool cmd_dispatched = false;
        for (int c = num_cmds - 1; c >= 0; c--) {
            // handler info
            ReaiCmdHandlerInfo *hi = &cmd_to_handler[c];

            // exact command match
            char *cmd = hi->cmd;
            if (!strcmp (argv[0], cmd)) {
                cmd_to_handler[c].handler (core, argc, argv);
                cmd_dispatched = true;
            }

            // command help match
            cmd[hi->cmdlen] = '?';
            if (!strcmp (argv[0], cmd)) {
                cmd_to_handler[c].handler (core, argc, argv);
                cmd_dispatched = true;
            }

            cmd[hi->cmdlen] = 0;
        }

        if (!cmd_dispatched) {
            reai_show_help_handler (core, argc, argv);
        }

        free_args (argc, (char **)argv);
        return true;
    }
    return false;
}

// TODO: needs review
void split_args (const char *input, int *argc, char ***argv) {
    int capacity = 10; // Initial capacity for argv array
    *argv        = malloc (capacity * sizeof (char *));
    *argc        = 0;

    const char *ptr       = input;
    char       *arg       = NULL;
    size_t      arg_len   = 0;
    int         in_quotes = 0; // Track if we are inside quotes

    while (*ptr != '\0') {
        // Skip leading whitespace outside of a token
        while (isspace (*ptr) && !in_quotes) {
            ptr++;
        }

        // Start of a new argument
        arg     = malloc (strlen (ptr) + 1); // Allocate memory for the argument
        arg_len = 0;

        // Parse the argument
        while (*ptr != '\0' && (in_quotes || !isspace (*ptr))) {
            if (*ptr == '"') {
                in_quotes = !in_quotes; // Toggle quote mode
            } else {
                arg[arg_len++] = *ptr;  // Copy character to argument
            }
            ptr++;
        }

        arg[arg_len] = '\0'; // Null-terminate the argument

        if (arg_len > 0) {
            (*argv)[*argc] = arg;
            (*argc)++;

            // Reallocate argv if necessary
            if (*argc >= capacity) {
                capacity *= 2;
                *argv     = realloc (*argv, capacity * sizeof (char *));
            }
        } else {
            (*argv)[*argc] = NULL;
            (*argc)++;
            free (arg); // Free the memory if the argument is empty
        }
    }

    // Null-terminate the argv array
    (*argv)[*argc] = NULL;
}

void free_args (int argc, char **argv) {
    for (int i = 0; i < argc; i++) {
        free (argv[i]);
    }
    free (argv);
}

RCorePlugin r_core_plugin_reai = {
    .meta =
        {
               .name    = "reai_r2",
               .desc    = "RevEngAI radare plugin",
               .license = "GPL3",
               .author  = "Siddharth Mishra",
               .version = "v1+search:apr10",
               },
    .call = reai_r2_core_cmd,
    .init = reai_r2_core_init,
    .fini = reai_r2_core_fini
};

#ifndef CORELIB
R_API RLibStruct radare_plugin = {
    .type    = R_LIB_TYPE_CORE,
    .data    = &r_core_plugin_reai,
    .version = R2_VERSION,
    .free    = NULL,
};
#endif
