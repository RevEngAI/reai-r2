/**
 * @file : Radare.c
 * @date : 2nd December 2024
 * @author : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright: Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

// radare
#include <r_core.h>

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

int reai_r2_core_cmd (void *user, const char *input) {
    RCore *core = (RCore *)user;

    struct {
        CString cmd;
        RCmdStatus (*handler) (RCore *core, int argc, const char **argv);
    } cmd_to_handler[] = {
        {  "REi",          reai_plugin_initialize_handler},
        {  "REm",   reai_list_available_ai_models_handler},
        {  "REh",               reai_health_check_handler},
        {  "REd",               reai_ai_decompile_handler},

        {  "REa",            reai_create_analysis_handler},
        { "REau",           reai_ann_auto_analyze_handler},
        { "REap",    reai_apply_existing_analysis_handler},

        { "REfl",    reai_get_basic_function_info_handler},
        { "REfr",            reai_rename_function_handler},
        { "REfs", reai_function_similarity_search_handler},

        {"REart",          reai_show_revengai_art_handler},
    };
    size_t num_cmds = sizeof (cmd_to_handler) / sizeof (cmd_to_handler[0]);

    if (r_str_startswith (input, "RE")) {
        int          argc = 0;
        const char **argv = NULL;
        split_args (input, &argc, (char ***)&argv);

        bool cmd_dispatched = false;
        for (size_t c = 0; c < num_cmds; c++) {
            if (!strcmp (argv[0], cmd_to_handler[c].cmd)) {
                cmd_to_handler[c].handler (core, argc, argv);
                cmd_dispatched = true;
            }
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
               .version = "v1+ai_decomp:feb5",
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
