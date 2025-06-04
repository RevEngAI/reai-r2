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

int reai_r2_core_init (void *user, const char *cmd) {
    (void)cmd;

    LogInit (true);

    RCmd  *rcmd = (RCmd *)user;
    RCore *core = (RCore *)rcmd->data;

    if (!core) {
        DISPLAY_ERROR ("Invalid radare core provided. Cannot initialize plugin.");
        return false;
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
    RCmdStatus status = reai_global_command_dispatcher(core, input);
    
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
