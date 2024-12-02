/**
 * @file : Radare.c
 * @date : 2nd December 2024
 * @author : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright: Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

#include <r_core.h>

/* int reai_r2_core_fini(void *user, const char *cmd); */
/* int reai_r2_core_init(void *user, const char *cmd); */
int reai_r2_core_cmd(void *user, const char *input);

RCorePlugin r_core_plugin_reai = {
#if R2_VERSION_NUMBER > 50808
    .meta =
        {
            .name = "reai_r2",
            .desc = "RevEngAI radare plugin",
            .license = "GPL3",
            .author = "Siddharth Mishra",
            .version = 0,
        },
#else
    .name = "reai_r2",
    .desc = "RevEngAI radare plugin",
    .license = "GPL3",
    .author = "Siddharth Mishra",
#endif
    .call = reai_r2_core_cmd,
    /* .init = reai_r2_core_init, */
    /* .fini = reai_r2_core_fini */
};

#ifndef CORELIB
#ifdef __cplusplus
extern "C"
#endif
    R_API RLibStruct radare_plugin = {.type = R_LIB_TYPE_CORE,
                                      .data = &r_core_plugin_reai,
                                      .version = R2_VERSION,
                                      .free = NULL,
#if R2_VERSION_NUMBER >= 40200
                                      .pkgname = "reai_r2"
#endif
};
#endif

/* int reai_r2_core_init(void *user, const char *cmd) { return true; } */
/* int reai_r2_core_fini(void *user, const char *cmd) { return true; } */
int reai_r2_core_cmd(void *user, const char *input) { return false; }
