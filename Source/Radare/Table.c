/**
 * @file      : Table.c
 * @date      : 4th Dec 2024
 * @author    : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright : Copyright (c) 2024 RevEngAI. All Rights Reserved.
 *
 * Table API definitions for Radare plugin only.
 * */

/* plugin */
#include <Plugin.h>
#include <Table.h>

/* radare */
#include <r_util/r_table.h>

/**
 * Before the next release, this code for `r_table_add_vrowf` won't be present in radare's
 * source code. So, for now, we use this hack to make the feature work. After the next release,
 * this can be easily removed.
 * */
#define RADARE_TABLE_HACK 1

/* NOTE: The code in this ifdef-endif block is of the same license as radare.
 * For more reference, read : https://github.com/radareorg/radare/blob/dev/libr/util/table.c
 * */
#ifdef RADARE_TABLE_HACK

#    define add_column_to_rowf(row, fmt, ap)                                                       \
        do {                                                                                       \
            const char* arg = NULL;                                                                \
            switch (fmt) {                                                                         \
                case 's' :                                                                         \
                case 'z' :                                                                         \
                    arg = va_arg (ap, const char*);                                                \
                    r_list_push (row, R_STR_DUP (arg ? arg : ""));                                 \
                    break;                                                                         \
                case 'b' :                                                                         \
                    r_list_push (row, R_STR_DUP (r_str_bool (va_arg (ap, int))));                  \
                    break;                                                                         \
                case 'i' :                                                                         \
                case 'd' :                                                                         \
                    r_list_push (row, r_str_newf ("%d", va_arg (ap, int)));                        \
                    break;                                                                         \
                case 'n' :                                                                         \
                    r_list_push (row, r_str_newf ("%" PFMT64d, va_arg (ap, ut64)));                \
                    break;                                                                         \
                case 'u' :                                                                         \
                    r_list_push (row, r_num_units (NULL, 32, va_arg (ap, ut64)));                  \
                    break;                                                                         \
                case 'f' :                                                                         \
                    r_list_push (row, r_str_newf ("%8lf", va_arg (ap, double)));                   \
                    break;                                                                         \
                case 'x' :                                                                         \
                case 'X' : {                                                                       \
                    ut64 n = va_arg (ap, ut64);                                                    \
                    if (n == UT64_MAX) {                                                           \
                        if (fmt == 'X') {                                                          \
                            r_list_push (row, R_STR_DUP ("----------"));                           \
                        } else {                                                                   \
                            r_list_push (row, R_STR_DUP ("-1"));                                   \
                        }                                                                          \
                    } else {                                                                       \
                        if (fmt == 'X') {                                                          \
                            r_list_push (row, r_str_newf ("0x%08" PFMT64x, n));                    \
                        } else {                                                                   \
                            r_list_push (row, r_str_newf ("0x%" PFMT64x, n));                      \
                        }                                                                          \
                    }                                                                              \
                } break;                                                                           \
                default :                                                                          \
                    eprintf ("Invalid format string char '%c', use 's' or 'n'\n", fmt);            \
                    break;                                                                         \
            }                                                                                      \
        } while (0)

R_API void table_add_vrowf (RTable* t, const char* fmt, va_list ap) {
    r_return_if_fail (t && fmt);

    RList* list = r_list_new();
    for (const char* f = fmt; *f; f++) {
        add_column_to_rowf (list, *f, ap);
    }
    r_table_add_row_list (t, list);
}

#endif

struct ReaiPluginTable {
    RTable* table;
    CString title;
};

/**
 * @b Create plugin table for Radare plugin.
 *
 * This will internally create a `RTable` and externally treat it as a new type.
 * This is a hack to avoid defining a new type and allocating memory of it as well as `RTable`.
 *
 * This means that for Radare plugin, this datatype is always incomplete.
 *
 * @return @c ReaiPluginTable on success.
 * @return @c Null otherwise.
 * */
ReaiPluginTable* reai_plugin_table_create() {
    ReaiPluginTable* table = NEW (ReaiPluginTable);
    if (!table) {
        DISPLAY_ERROR (ERR_OUT_OF_MEMORY);
        return NULL;
    }

    table->table = r_table_new ("table");
    if (!table->table) {
        DISPLAY_ERROR ("Failed to create table");
        return NULL;
    }

    return table;
}

/**
 * @b Destroy given @c ReaiPluginTable object.
 *
 * @param table Table to be destroyed.
 * */
void reai_plugin_table_destroy (ReaiPluginTable* table) {
    if (!table) {
        DISPLAY_ERROR ("Invalid table. Cannot destroy a NULL table.");
        return;
    }

    if (table->table) {
        r_table_free (table->table);
        table->table = NULL;
    }

    if (table->title) {
        FREE (table->title);
    }

    FREE (table);
}

/**
 * @b Add columns with given format and names.
 *
 * @param table Table to add columns to.
 * @param fmtstr Table column format (ordering and type)
 * @param ... Variadic arguments respecting the provided format.
 *
 * @return Non NULL @c ReaiPluginTable (same as @c table) on success.
 * @return @c NULL otherwise.
 * */
ReaiPluginTable* reai_plugin_table_set_columnsf (ReaiPluginTable* table, const char* fmtstr, ...) {
    if (!table) {
        DISPLAY_ERROR ("invalid arguments.");
        return NULL;
    }

    RTable* t = table->table;

    va_list ap;
    va_start (ap, fmtstr);
    RTableColumnType* typeString = r_table_type ("string");
    RTableColumnType* typeNumber = r_table_type ("number");
    RTableColumnType* typeFloat  = r_table_type ("float");
    RTableColumnType* typeBool   = r_table_type ("bool");
    const char*       name;
    const char*       f = fmtstr;
    for (; *f; f++) {
        name = va_arg (ap, const char*);
        if (!name) {
            break;
        }
        switch (*f) {
            case 'b' :
                r_table_add_column (t, typeBool, name, 0);
                break;
            case 's' :
            case 'z' :
                r_table_add_column (t, typeString, name, 0);
                break;
            case 'f' :
                r_table_add_column (t, typeFloat, name, 0);
                break;
            case 'i' :
            case 'd' :
            case 'n' :
            case 'x' :
            case 'X' :
                r_table_add_column (t, typeNumber, name, 0);
                break;
            default :
                R_LOG_ERROR ("Invalid format string char '%c', use 's' or 'n'", *f);
                break;
        }
    }
    va_end (ap);

    return table;
}

/**
 * @b Add a row to table with given format and given values.
 *
 * @param table Table to add row to.
 * @param fmtstr Table column format (ordering and type)
 * @param ... Variadic arguments respecting the provided format.
 *
 * @return Non NULL @c ReaiPluginTable (same as @c table) on success.
 * @return @c NULL otherwise.
 * */
ReaiPluginTable* reai_plugin_table_add_rowf (ReaiPluginTable* table, const char* fmtstr, ...) {
    if (!table) {
        DISPLAY_ERROR ("Invalid table provided. Cannot add new row.");
        return NULL;
    }

    if (!fmtstr) {
        DISPLAY_ERROR ("Invalid format string provided. Cannot add row.");
        return NULL;
    }

    va_list ap;
    va_start (ap, fmtstr);
#ifdef RADARE_TABLE_HACK
    table_add_vrowf (table->table, fmtstr, ap);
#else
    r_table_add_vrowf (table->table, fmtstr, ap);
#endif
    va_end (ap);

    return table;
}

/**
 * @brief Print table
 * */
void reai_plugin_table_show (ReaiPluginTable* table) {
    if (!table) {
        DISPLAY_ERROR ("Invalid table provided. Cannot add new row.");
        return;
    }

    CString table_str = r_table_tofancystring (table->table);
    if (!table_str) {
        DISPLAY_ERROR ("Failed to convert table to string. Cannot display.");
        return;
    }

    if (table->title) {
        r_cons_printf ("\n%s\n%s\n", table->title, table_str);
    } else {
        r_cons_printf ("\n%s\n", table_str);
    }

    FREE (table_str);
}

/**
 * @b Set table title to be displayed before it
 *
 * This can be something like a short five to six word summary.
 *
 * @param table
 * @param title
 * */
ReaiPluginTable* reai_plugin_table_set_title (ReaiPluginTable* table, CString title) {
    if (!table) {
        DISPLAY_ERROR ("Invalid table provided.");
        return NULL;
    }

    if (!title) {
        DISPLAY_ERROR ("Invalid title provided.");
        return NULL;
    }

    table->title = strdup (title);

    return table;
}

/**
 * @b Clear table contents.
 *
 * @param table.
 *
 * @return @c table on success.
 * @return @c NULL otherwise.
 * */
ReaiPluginTable* reai_plugin_table_clear_contents (ReaiPluginTable* table) {
    if (!table) {
        DISPLAY_ERROR ("Invalid table provided.");
        return NULL;
    }

    // easiest way to clear contents is to recreate a new table
    RTable* new_table = r_table_new (table->title);
    if (new_table) {
        r_table_free (table->table);
        table->table = new_table;
        return table;
    } else {
        DISPLAY_ERROR ("Failed to clear table contents");
        return NULL;
    }
}
