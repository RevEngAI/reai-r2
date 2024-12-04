/**
 * @file      : Table.h
 * @date      : 4th Dec 2024
 * @author    : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 *
 * This header defines a uniform interface to create and display tables in
 * Rizin and cutter. This applies a hack to detect whether the header is being
 * included in Rizin or in Cutter.
 *
 * Rizin plugin source code is written completely in C and Cutter in C++ and C.
 * This means if the header is compiled by a C compiler, it's being used in Rizin,
 * and if it's being compiled by a C++ compiler, it's being used in Cutter.
 *
 * Using this, we can switch between the API selection.
 *
 * This hack needs to be applied because at the time of writing this, Rizin plugin does
 * not have a method to add a new row by taking a format string and a va_list. Due to this,
 * we cannot forward variadic arguments to RzTable API.
 * */

#ifndef REAI_PLUGIN_TABLE_H
#define REAI_PLUGIN_TABLE_H

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct ReaiPluginTable ReaiPluginTable;

    ReaiPluginTable* reai_plugin_table_create();
    void             reai_plugin_table_destroy (ReaiPluginTable* table);
    ReaiPluginTable* reai_plugin_table_set_title (ReaiPluginTable* table, const char* title);
    ReaiPluginTable*
        reai_plugin_table_set_columnsf (ReaiPluginTable* table, const char* fmtstr, ...);
    ReaiPluginTable* reai_plugin_table_add_rowf (ReaiPluginTable* table, const char* fmtstr, ...);
    ReaiPluginTable* reai_plugin_table_clear_contents (ReaiPluginTable* table);
    void             reai_plugin_table_show (ReaiPluginTable* table);

#ifdef __cplusplus
}
#endif // __cplusplus


#endif // REAI_PLUGIN_TABLE_H
