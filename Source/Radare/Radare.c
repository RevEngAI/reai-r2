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
#include <Radare/CmdDesc.h>
#include <Plugin.h>
#include "PluginVersion.h"

// reai
#include <Reai/Log.h>

typedef int (*RAnalysisFunctionRenameCallback) (RAnal *analysis, void *core, RAnalFunction *fcn, const char *oldname);

Str *getMsg() {
    static Str  s;
    static bool is_inited = false;
    if (!is_inited) {
        s         = StrInit();
        is_inited = true;
    }
    return &s;
}

void rClearMsg() {
    StrClear (getMsg());
}

void rDisplayMsg (LogLevel level, Str *msg) {
    if (!msg) {
        LOG_ERROR ("Invalid arguments");
        return;
    }

    rAppendMsg (level, msg);
    r_cons_println (getMsg()->data);
    StrClear (getMsg());
}

void rAppendMsg (LogLevel level, Str *msg) {
    if (!msg) {
        LOG_ERROR ("Invalid arguments");
        return;
    }

    StrAppendf (
        getMsg(),
        "%s: %s\n",
        level == LOG_LEVEL_INFO ? "INFO" : (level == LOG_LEVEL_ERROR ? "ERROR" : "FATAL"),
        msg->data
    );
}

// NOTE: Hook function for function rename
// This is called back from Radare2 event system whenever a function is renamed.
static int reai_on_fcn_rename (struct r_anal_t *analysis, RCore *core, RAnalFunction *fcn, const char *oldname) {
    if (!analysis || !core || !fcn || !fcn->name || !oldname) {
        LOG_ERROR ("Invalid arguments in function rename callback");
        return 1;
    }
    
    LOG_INFO ("Function rename detected: new name '%s' at 0x%llx", fcn->name, fcn->addr);

    // Only sync if we have a valid binary ID (analysis is applied)
    // Use GetBinaryIdFromCore to check both local storage and RCore config.
    // Check if we can work with the current analysis
    if (!rCanWorkWithAnalysis (GetBinaryIdFromCore(core), false)) {
        LOG_INFO ("RevEngAI analysis not ready, skipping function rename sync");
        return 1;
    }

    // Look up the RevEngAI function ID for this Radare2 function
    FunctionId fn_id = rLookupFunctionId (core, fcn);
    if (!fn_id) {
        LOG_ERROR ("Failed to find RevEngAI function ID for function '%s' at 0x%llx", fcn->name, fcn->addr);
        return 1;
    }

    // Create new name string for the API call
    Str new_name = StrInitFromZstr (fcn->name);

    // Call RevEngAI API to rename the function
    if (RenameFunction (GetConnection(), fn_id, new_name)) {
        LOG_INFO ("Successfully synced function rename with RevEngAI: '%s' (ID: %llu)", fcn->name, fn_id);
        StrDeinit (&new_name);
        return 0;
    } else {
        LOG_ERROR ("Failed to sync function rename with RevEngAI for function '%s' (ID: %llu)", fcn->name, fn_id);
        StrDeinit (&new_name);
        return 1;
    }
}

int reai_r2_core_init (void *user, const char *cmd) {
    (void)cmd;

    LogInit (true);

    RCmd  *rcmd = (RCmd *)user;
    RCore *core = (RCore *)rcmd->data;

    if (!core) {
        DISPLAY_ERROR ("Invalid radare core provided. Cannot initialize plugin.");
        return false;
    }

    // Register our config variables
    if (core->config) {
        r_config_lock (core->config, false);
        r_config_set_i (core->config, "reai.binary_id", 0);
        r_config_desc (core->config, "reai.binary_id", "Current RevEngAI binary ID for cross-context access");
        r_config_lock (core->config, true);
        LOG_INFO ("Registered RevEngAI config variable: reai.binary_id");
    }

    // Install our hook
    if (core->anal) {
        core->anal->cb.on_fcn_rename = (RAnalysisFunctionRenameCallback)reai_on_fcn_rename;
        core->anal->user = core;  // Set the user data in the analysis structure
        LOG_INFO ("RevEngAI function rename hook installed");
    } else {
        LOG_ERROR ("Failed to install function rename hook: analysis not available");
    }

    return true;
}

int reai_r2_core_fini (void *user, const char *cmd) {
    (void)user;
    (void)cmd;

    return true;
}

int reai_r2_core_cmd (void *user, const char *input) {
    RCore *core = (RCore *)user;

    // Check if this is a RevEngAI command
    if (!r_str_startswith (input, "RE")) {
        return false;
    }

    // Use the global dispatcher to handle the command
    RCmdStatus status = reai_global_command_dispatcher (core, input);

    // Always return true for our commands, even if they fail
    return status == R_CMD_STATUS_OK;
}

RCorePlugin r_core_plugin_reai = {
    .meta =
        {
               .name    = "reai_r2",
               .desc    = "RevEngAI radare plugin",
               .license = "GPL3",
               .author  = "Siddharth Mishra",
               .version = REAI_PLUGIN_VERSION,
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
