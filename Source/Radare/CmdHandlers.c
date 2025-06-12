/**
 * @file : CmdHandlers.c
 * @date : 3rd December 2024
 * @author : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright: Copyright (c) 2024 RevEngAI. All Rights Reserved.
 * */

#include <Radare/CmdDesc.h>
#include <Reai/Api.h>
#include <Reai/Config.h>
#include <Reai/Log.h>
#include <Reai/Types.h>
#include <Reai/Util/Str.h>
#include <Reai/Sys.h>
#include <Reai/Diff.h>

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
#include <stdlib.h>
#include "Reai/Api/Types/AiDecompilation.h"
#include "Reai/Util/Vec.h"

// TODO: restrict to debug symbols only

#define ZSTR_ARG(vn, idx) (argc > (idx) ? (((vn) = argv[idx]), true) : false)
#define STR_ARG(vn, idx)  (argc > (idx) ? (((vn) = StrInitFromZstr (argv[idx])), true) : false)
#define NUM_ARG(vn, idx)  (argc > (idx) ? (((vn) = r_num_get (core->num, argv[idx])), true) : false)

R_IPI RCmdStatus r_plugin_initialize_handler (RCore* core, int argc, const char** argv) {
    (void)core;

    // NOTE(brightprogrammer): Developers should just change this in the config file.
    const char* host    = "https://api.reveng.ai"; // Hardcode API endpoint
    const char* api_key = argc > 1 ? argv[1] : NULL;

    // Check if API key is provided
    if (!api_key) {
        DISPLAY_ERROR ("API key not provided. Usage: REi <api_key>");
        return R_CMD_STATUS_WRONG_ARGS;
    }

    Config cfg = ConfigInit();
    ConfigAdd (&cfg, "host", host);
    ConfigAdd (&cfg, "api_key", api_key);
    ConfigWrite (&cfg, NULL);
    ConfigDeinit (&cfg);

    ReloadPluginData();
    r_cons_println ("RevEngAI plugin initialized successfully");

    return R_CMD_STATUS_OK;
}

/**
 * "REm"
 * */
R_IPI RCmdStatus r_list_available_ai_models_handler (RCore* core, int argc, const char** argv) {
    (void)core;
    (void)argc;
    (void)argv;

    ModelInfos* models = GetModels();
    VecForeach (models, model, { r_cons_println (model.name.data); });

    return R_CMD_STATUS_OK;
}

/**
 * "REh"
 *
 * @b Perform an auth-check api call to check connection.
 * */
R_IPI RCmdStatus r_health_check_handler (RCore* core, int argc, const char** argv) {
    (void)core;
    (void)argc;
    (void)argv;

    if (!Authenticate (GetConnection())) {
        r_cons_println ("No connection");
    } else {
        r_cons_println ("OK");
    }

    return R_CMD_STATUS_OK;
}

/**
 * "REu"
 *
 * @b Upload a binary file to RevEngAI servers.
 * */
R_IPI RCmdStatus r_upload_bin_handler (RCore* core, int argc, const char** argv) {
    (void)core;

    Str file_path = StrInit();

    if (STR_ARG (file_path, 1)) {
        Str sha256 = UploadFile (GetConnection(), file_path);

        if (sha256.length) {
            r_cons_printf ("Successfully uploaded file: %s\n", file_path.data);
            r_cons_printf ("SHA256: %s\n", sha256.data);
            StrDeinit (&sha256);
            StrDeinit (&file_path);
            return R_CMD_STATUS_OK;
        } else {
            DISPLAY_ERROR ("Failed to upload file: %s", file_path.data);
            StrDeinit (&file_path);
            return R_CMD_STATUS_OK;
        }
    } else {
        DISPLAY_ERROR ("Usage: REu <file_path>");
        StrDeinit (&file_path);
        return R_CMD_STATUS_WRONG_ARGS;
    }
}

RCmdStatus createAnalysis (RCore* core, int argc, const char** argv, bool is_private) {
    NewAnalysisRequest new_analysis = NewAnalysisRequestInit();
    BinaryId           bin_id       = 0;

    if (STR_ARG (new_analysis.ai_model, 1) && STR_ARG (new_analysis.file_name, 2)) {
        STR_ARG (new_analysis.cmdline_args, 3);

        new_analysis.is_private = is_private;

        Str path            = rGetCurrentBinaryPath (core);
        new_analysis.sha256 = UploadFile (GetConnection(), path);
        if (!new_analysis.sha256.length) {
            APPEND_ERROR ("Failed to upload binary");
        } else {
            new_analysis.base_addr = rGetCurrentBinaryBaseAddr (core);
            new_analysis.functions =
                VecInitWithDeepCopy_T (&new_analysis.functions, NULL, FunctionInfoDeinit);

            RListIter*     fn_iter = NULL;
            RAnalFunction* fn      = NULL;
            r_list_foreach (core->anal->fcns, fn_iter, fn) {
                FunctionInfo fi       = {0};
                fi.symbol.is_addr     = true;
                fi.symbol.is_external = false;
                fi.symbol.value.addr  = fn->addr;
                fi.symbol.name        = StrInitFromZstr (fn->name);
                fi.size               = r_anal_function_size_from_entry (fn);
                VecPushBack (&new_analysis.functions, fi);
            }
            bin_id = CreateNewAnalysis (GetConnection(), &new_analysis);
            SetBinaryId (bin_id);
        }
        StrDeinit (&path);
    }

    NewAnalysisRequestDeinit (&new_analysis);

    if (!bin_id) {
        DISPLAY_ERROR ("Failed to create new analysis");
        return R_CMD_STATUS_OK;
    }

    return R_CMD_STATUS_OK;
}

/**
 * "REa"
 * */
R_IPI RCmdStatus r_create_analysis_public_handler (RCore* core, int argc, const char** argv) {
    return createAnalysis (core, argc, argv, true);
}

/**
 * "REap"
 * */
R_IPI RCmdStatus r_create_analysis_private_handler (RCore* core, int argc, const char** argv) {
    return createAnalysis (core, argc, argv, false);
}

/**
 * "REae"
 * */
R_IPI RCmdStatus r_apply_existing_analysis_handler (RCore* core, int argc, const char** argv) {
    BinaryId bin_id = 0;

    if (NUM_ARG (bin_id, 1)) {
        rApplyAnalysis (core, bin_id);
        return R_CMD_STATUS_OK;
    } else {
        LOG_ERROR ("Invalid binary ID");
        return R_CMD_STATUS_WRONG_ARGS;
    }
}

RCmdStatus autoAnalyze (RCore* core, int argc, const char** argv, bool restruct_to_debug) {
    Config* cfg = GetConfig();

    Str* armx         = ConfigGet (cfg, "auto_rename_max_results_per_function");
    u32  result_count = 20;
    if (armx) {
        result_count = r_num_get (core->num, armx->data);
        result_count = CLAMP (result_count, 5, 50);
    }

    u32 min_similarity = 90;
    NUM_ARG (min_similarity, 1);

    rAutoRenameFunctions (core, result_count, min_similarity, restruct_to_debug);

    return R_CMD_STATUS_OK;
}

/**
 * REaa
 * */
R_IPI RCmdStatus r_ann_auto_analyze_handler (RCore* core, int argc, const char** argv) {
    return autoAnalyze (core, argc, argv, true);
}

/**
 * REaaa
 * */
R_IPI RCmdStatus r_ann_auto_analyze_all_handler (RCore* core, int argc, const char** argv) {
    return autoAnalyze (core, argc, argv, false);
}

/**
 * "REfl"
 * */
R_IPI RCmdStatus r_get_basic_function_info_handler (RCore* core, int argc, const char** argv) {
    (void)core;
    (void)argc;
    (void)argv;

    if (rCanWorkWithAnalysis (GetBinaryId(), true)) {
        FunctionInfos functions =
            GetBasicFunctionInfoUsingBinaryId (GetConnection(), GetBinaryId());

        if (!functions.length) {
            DISPLAY_ERROR ("Failed to get functions from RevEngAI analysis.");
        }

        RTable* table = r_table_new ("Functions");
        if (!table) {
            DISPLAY_ERROR ("Failed to create the table.");
            return R_CMD_STATUS_OK;
        }

        r_table_set_columnsf (table, "nsxx", "function_id", "name", "vaddr", "size");
        VecForeachPtr (&functions, fn, {
            r_table_add_rowf (
                table,
                "nsxx",
                fn->id,
                fn->symbol.name.data,
                fn->symbol.value.addr,
                fn->size
            );
        });

        const char* table_str = r_table_tofancystring (table);
        if (!table_str) {
            DISPLAY_ERROR ("Failed to convert table to string.");
            r_table_free (table);
            return R_CMD_STATUS_OK;
        }

        r_cons_println (table_str);

        FREE (table_str);
        r_table_free (table);
    } else {
        DISPLAY_ERROR (
            "Current session has no completed analysis attached to it.\n"
            "Please create a new analysis and wait for it's completion or\n"
            "       apply an existing analysis that is already complete."
        );
    }

    return R_CMD_STATUS_OK;
}

/**
 * "REfr"
 *
 * @b Rename function with given function id to given new name.
 * */
R_IPI RCmdStatus r_rename_function_handler (RCore* core, int argc, const char** argv) {
    if (rCanWorkWithAnalysis (GetBinaryId(), true)) {
        Str old_name = StrInit(), new_name = StrInit();
        if (STR_ARG (old_name, 1), STR_ARG (new_name, 2)) {
            RAnalFunction* fn = r_anal_get_function_byname (core->anal, old_name.data);
            if (!fn) {
                DISPLAY_ERROR ("Rizin function with given name not found.");
                return R_CMD_STATUS_OK;
            }

            if (RenameFunction (GetConnection(), rLookupFunctionId (core, fn), new_name)) {
                DISPLAY_ERROR ("Failed to rename function");
                return R_CMD_STATUS_OK;
            }

            return R_CMD_STATUS_OK;
        }
    }

    return R_CMD_STATUS_WRONG_ARGS;
}

RCmdStatus
    functionSimilaritySearch (RCore* core, int argc, const char** argv, bool restrict_to_debug) {
    SimilarFunctionsRequest search = SimilarFunctionsRequestInit();

    const char* function_name      = NULL;
    Str         collection_ids_csv = StrInit();
    Str         binary_ids_csv     = StrInit();
    u32         min_similarity     = 0;

    if (ZSTR_ARG (function_name, 1) && NUM_ARG (min_similarity, 2) && NUM_ARG (search.limit, 3)) {
        STR_ARG (collection_ids_csv, 4);
        STR_ARG (binary_ids_csv, 5);


        search.distance = 1. - (CLAMP (min_similarity, 1, 100) / 100.);
        LOG_INFO ("Requested similarity = %f %%", 100 - search.distance * 100);

        search.debug_include.user_symbols     = restrict_to_debug;
        search.debug_include.system_symbols   = restrict_to_debug;
        search.debug_include.external_symbols = restrict_to_debug;

        Strs cids = StrSplit (&collection_ids_csv, ",");
        VecForeachPtr (&cids, cid, {
            VecPushBack (&search.collection_ids, strtoull (cid->data, NULL, 0));
        });
        StrDeinit (&collection_ids_csv);
        VecDeinit (&cids);

        Strs bids = StrSplit (&binary_ids_csv, ",");
        VecForeachPtr (&bids, bid, {
            VecPushBack (&search.binary_ids, strtoull (bid->data, NULL, 0));
        });
        StrDeinit (&binary_ids_csv);
        VecDeinit (&bids);

        search.function_id = rLookupFunctionIdForFunctionWithName (core, function_name);

        if (search.function_id) {
            SimilarFunctions functions = GetSimilarFunctions (GetConnection(), &search);

            if (functions.length) {
                RTable* table = r_table_new ("Similar Functions");
                r_table_set_columnsf (
                    table,
                    "snsnn",
                    "Function Name",
                    "Function ID",
                    "Binary Name",
                    "Binary ID",
                    "Similarity"
                );

                VecForeachPtr (&functions, fn, {
                    r_table_add_rowf (
                        table,
                        "snsnf",
                        fn->name.data,
                        fn->id,
                        fn->binary_name.data,
                        fn->binary_id,
                        (1. - fn->distance) * 100.
                    );
                });

                const char* table_str = r_table_tofancystring (table);
                r_cons_println (table_str);

                FREE (table_str);
                r_table_free (table);
                VecDeinit (&functions);
                SimilarFunctionsRequestDeinit (&search);

                return R_CMD_STATUS_OK;
            }
        }
    }

    DISPLAY_ERROR ("Failed to perform function similarity search");
    SimilarFunctionsRequestDeinit (&search);
    return R_CMD_STATUS_OK;
}

/**
 * "REfs"
 * */
R_IPI RCmdStatus r_function_similarity_search_handler (RCore* core, int argc, const char** argv) {
    return functionSimilaritySearch (core, argc, argv, false);
}

/**
 * "REfsd"
 * */
R_IPI RCmdStatus
    r_function_similarity_search_restrict_debug_handler (RCore* core, int argc, const char** argv) {
    return functionSimilaritySearch (core, argc, argv, true);
}

static inline Str getAiDecompilation (
    FunctionId       fn_id,
    bool             colorize,
    AiDecompilation* ai_decomp,
    Comments*        p_comments
) {
    if (!fn_id) {
        LOG_FATAL ("Invalid function Id provided. Expected a non-zero value.");
        return StrInit();
    }

    AiDecompilation aidec = GetAiDecompilation (GetConnection(), fn_id, true);

    Str summary = StrDup (&aidec.raw_ai_summary);

    static i32 SOFT_LIMIT = 120;

    i32   l = summary.length;
    char* p = summary.data;
    while (l > SOFT_LIMIT) {
        char* p1 = strchr (p + SOFT_LIMIT, ' ');
        if (p1) {
            StrAppendf (&summary, "// %.*s\n", (i32)(p1 - p), p);
            p1++;
            l -= (p1 - p);
            p  = p1;
        } else {
            break;
        }
    }

    // TODO: use colorize switch to optionally wrap replaced texts into colors

    Str decompilation = StrDup (&aidec.raw_decompilation);

    Str final_code = StrInit();

    Comments comments = GetAiDecompilationComments (GetConnection(), fn_id);
    if (p_comments) {
        *p_comments = (Comments)VecInitWithDeepCopy (NULL, CommentDeinit);
    }
    if (comments.length) {
        Strs decompilation_lines = StrSplit (&decompilation, "\n");
        StrDeinit (&decompilation);

        VecForeachPtrIdx (&decompilation_lines, line, line_idx, {
            Str comment_block = StrInit();

            VecForeachPtrReverseIdx (&comments, comment, comment_idx, {
                if (line_idx + 1 >= comment->context.start_line &&
                    line_idx + 1 <= comment->context.end_line) {
                    StrAppendf (&comment_block, "//> %s\n", comment->content.data);
                    if (p_comments) {
                        Comment c;
                        VecRemove (&comments, &c, comment_idx);
                        VecPushBack (p_comments, c);
                    } else {
                        VecDelete (&comments, comment_idx);
                    }
                }
            });

            StrAppendf (
                &final_code,
                "\n%s%s\n",
                comment_block.data ? comment_block.data : "",
                line->data
            );
        });
    } else {
        final_code = decompilation;
    }

    if (comments.length) {
        DISPLAY_ERROR ("Comments remaining! Not all added!");
        VecDeinit (&comments);
    }

    decompilation = final_code;

    LOG_INFO ("aidec.functions.length = %zu", aidec.functions.length);
    VecForeachIdx (&aidec.functions, function, idx, {
        Str dname = StrInit();
        StrPrintf (&dname, "<DISASM_FUNCTION_%llu>", idx);
        StrReplace (&decompilation, &dname, &function.name, -1);
        StrDeinit (&dname);
    });

    LOG_INFO ("aidec.strings.length = %zu", aidec.strings.length);
    VecForeachIdx (&aidec.strings, string, idx, {
        Str dname = StrInit();
        StrPrintf (&dname, "<DISASM_STRING_%llu>", idx);
        StrReplace (&decompilation, &dname, &string.string, -1);
        StrDeinit (&dname);
    });

    LOG_INFO ("aidec.unmatched.functions.length = %zu", aidec.unmatched.functions.length);
    VecForeachIdx (&aidec.unmatched.functions, function, idx, {
        Str dname = StrInit();
        StrPrintf (&dname, "<UNMATCHED_FUNCTION_%llu>", idx);
        StrReplace (&decompilation, &dname, &function.name, -1);
        StrDeinit (&dname);
    });

    LOG_INFO ("aidec.unmatched.strings.length = %zu", aidec.unmatched.strings.length);
    VecForeachIdx (&aidec.unmatched.strings, string, idx, {
        Str dname = StrInit();
        StrPrintf (&dname, "<UNMATCHED_STRING_%llu>", idx);
        StrReplace (&decompilation, &dname, &string.value.str, -1);
        StrDeinit (&dname);
    });

    LOG_INFO ("aidec.unmatched.vars.length = %zu", aidec.unmatched.vars.length);
    VecForeachIdx (&aidec.unmatched.vars, var, idx, {
        Str dname = StrInit();
        StrPrintf (&dname, "<VAR_%llu>", idx);
        StrReplace (&decompilation, &dname, &var.value.str, -1);
        StrDeinit (&dname);
    });

    LOG_INFO ("aidec.unmatched.external_vars.length = %zu", aidec.unmatched.external_vars.length);
    VecForeachIdx (&aidec.unmatched.external_vars, var, idx, {
        Str dname = StrInit();
        StrPrintf (&dname, "<EXTERNAL_VARIABLE_%llu>", idx);
        StrReplace (&decompilation, &dname, &var.value.str, -1);
        StrDeinit (&dname);
    });

    LOG_INFO ("aidec.unmatched.custom_types.length = %zu", aidec.unmatched.custom_types.length);
    VecForeachIdx (&aidec.unmatched.custom_types, var, idx, {
        Str dname = StrInit();
        StrPrintf (&dname, "<CUSTOM_TYPE_%llu>", idx);
        StrReplace (&decompilation, &dname, &var.value.str, -1);
        StrDeinit (&dname);
    });

    if (ai_decomp) {
        *ai_decomp = aidec;
    } else {
        AiDecompilationDeinit (&aidec);
    }

    return decompilation;
}

/**
 * "REda"
 * */
R_IPI RCmdStatus r_ai_decompile_handler (RCore* core, int argc, const char** argv) {
    LOG_INFO ("[CMD] AI decompile");
    const char* fn_name = NULL;
    if (!ZSTR_ARG (fn_name, 1)) {
        return R_CMD_STATUS_WRONG_ARGS;
    }

    if (rCanWorkWithAnalysis (GetBinaryId(), true)) {
        FunctionId fn_id = rLookupFunctionIdForFunctionWithName (core, fn_name);

        if (!fn_id) {
            DISPLAY_ERROR (
                "A function with that name does not exist in current Rizin session.\n"
                "Please provide a name from output of `afl` command."
            );
            return R_CMD_STATUS_WRONG_ARGS;
        }

        Status status = GetAiDecompilationStatus (GetConnection(), fn_id);
        if ((status & STATUS_MASK) == STATUS_ERROR) {
            if (!BeginAiDecompilation (GetConnection(), fn_id)) {
                DISPLAY_ERROR ("Failed to start AI decompilation process.");
                return R_CMD_STATUS_OK;
            }
        }

        while (true) {
            DISPLAY_INFO ("Checking decompilation status...");

            status = GetAiDecompilationStatus (GetConnection(), fn_id);
            switch (status & STATUS_MASK) {
                case STATUS_ERROR :
                    DISPLAY_ERROR (
                        "Failed to decompile '%s'\n"
                        "Is this function from RevEngAI's analysis?\n"
                        "What's the output of REfl?~'%s'",
                        fn_name,
                        fn_name
                    );
                    return R_CMD_STATUS_OK;

                case STATUS_UNINITIALIZED :
                    DISPLAY_INFO (
                        "No decompilation exists for this function...\n"
                        "Starting AI decompilation process!"
                    );
                    if (!BeginAiDecompilation (GetConnection(), fn_id)) {
                        DISPLAY_ERROR ("Failed to start AI decompilation process.");
                        return R_CMD_STATUS_OK;
                    }
                    break;

                case STATUS_PENDING : {
                    DISPLAY_INFO ("AI decompilation is queued and is pending. Should start soon!");
                    break;
                }

                case STATUS_SUCCESS : {
                    DISPLAY_INFO ("AI decompilation complete ;-)\n");
                    Str dec = getAiDecompilation (fn_id, true, NULL, NULL);
                    r_cons_println (dec.data);
                    StrDeinit (&dec);
                    return R_CMD_STATUS_OK;
                }
                default :
                    LOG_FATAL ("Unreachable code reached. Invalid decompilation status");
                    return R_CMD_STATUS_OK;
            }

            DISPLAY_INFO ("Going to sleep for two seconds...");
            r_sys_sleep (2);
        }
    } else {
        DISPLAY_ERROR ("Failed to get AI decompilation.");
        return R_CMD_STATUS_OK;
    }
}

RCmdStatus collectionSearch (SearchCollectionRequest* search) {
    CollectionInfos collections = SearchCollection (GetConnection(), search);
    SearchCollectionRequestDeinit (search);

    if (collections.length) {
        RTable* t = r_table_new ("Collections Search Result");
        r_table_set_columnsf (
            t,
            "snnssss",
            "Name",
            "Size",
            "Id",
            "Scope",
            "Last Updated",
            "Model",
            "Owner"
        );

        VecForeachPtr (&collections, collection, {
            r_table_add_rowf (
                t,
                "snnssss",
                collection->name.data,
                collection->size,
                collection->id,
                collection->is_private ? "PRIVATE" : "PUBLIC",
                collection->last_updated_at.data,
                collection->model_name.data,
                collection->owned_by.data
            );
        });

        const char* s = r_table_tofancystring (t);
        r_cons_println (s);
        FREE (s);
        r_table_free (t);
    } else {
        DISPLAY_ERROR ("Failed to get collection search results");
    }

    VecDeinit (&collections);

    return R_CMD_STATUS_OK;
}

/**
 * "REcs"
 * */
R_IPI RCmdStatus r_collection_search_handler (RCore* core, int argc, const char** argv) {
    (void)core;

    SearchCollectionRequest search = SearchCollectionRequestInit();

    Str tags = StrInit();

    STR_ARG (search.partial_collection_name, 1);
    STR_ARG (search.partial_binary_name, 2);
    STR_ARG (search.partial_binary_sha256, 3);
    STR_ARG (search.model_name, 4);
    STR_ARG (tags, 5);

    search.tags = StrSplit (&tags, ",");
    StrDeinit (&tags);

    return collectionSearch (&search);
}

R_IPI RCmdStatus
    r_collection_search_by_binary_name_handler (RCore* core, int argc, const char** argv) {
    (void)core;

    SearchCollectionRequest search = SearchCollectionRequestInit();

    STR_ARG (search.partial_binary_name, 1);
    STR_ARG (search.model_name, 2);

    return collectionSearch (&search);
}

R_IPI RCmdStatus
    r_collection_search_by_collection_name_handler (RCore* core, int argc, const char** argv) {
    (void)core;

    SearchCollectionRequest search = SearchCollectionRequestInit();

    STR_ARG (search.partial_collection_name, 1);
    STR_ARG (search.model_name, 2);

    return collectionSearch (&search);
}

/**
 * "REcsh"
 * */
R_IPI RCmdStatus
    r_collection_search_by_binary_sha256_handler (RCore* core, int argc, const char** argv) {
    (void)core;

    SearchCollectionRequest search = SearchCollectionRequestInit();

    STR_ARG (search.partial_binary_sha256, 1);
    STR_ARG (search.model_name, 2);

    return collectionSearch (&search);
}

RCmdStatus collectionFilteredSearch (Str term, Str filters, OrderBy order_by, bool is_asc) {
    SearchCollectionRequest search = SearchCollectionRequestInit();

    search.partial_collection_name = term;

    if (filters.data) {
        search.filter_public   = !!strchr (filters.data, 'p');
        search.filter_official = !!strchr (filters.data, 'o');
        search.filter_user     = !!strchr (filters.data, 'u');
        search.filter_team     = !!strchr (filters.data, 't');
        StrDeinit (&filters);
    }
    search.order_by     = order_by;
    search.order_in_asc = is_asc;

    return collectionSearch (&search);
}

/**
 * REcat
 * */
R_IPI RCmdStatus
    r_collection_basic_info_asc_time_handler (RCore* core, int argc, const char** argv) {
    (void)core;

    Str term = StrInit(), filters = StrInit();
    STR_ARG (term, 1);
    STR_ARG (filters, 2);
    return collectionFilteredSearch (term, filters, ORDER_BY_LAST_UPDATED, true);
}

/**
 * REcao
 * */
R_IPI RCmdStatus
    r_collection_basic_info_asc_owner_handler (RCore* core, int argc, const char** argv) {
    (void)core;

    Str term = StrInit(), filters = StrInit();
    STR_ARG (term, 1);
    STR_ARG (filters, 2);
    return collectionFilteredSearch (term, filters, ORDER_BY_OWNER, true);
}

/**
 * REcan
 * */
R_IPI RCmdStatus
    r_collection_basic_info_asc_name_handler (RCore* core, int argc, const char** argv) {
    (void)core;

    Str term = StrInit(), filters = StrInit();
    STR_ARG (term, 1);
    STR_ARG (filters, 2);
    return collectionFilteredSearch (term, filters, ORDER_BY_NAME, true);
}

/**
 * REcam
 * */
R_IPI RCmdStatus
    r_collection_basic_info_asc_model_handler (RCore* core, int argc, const char** argv) {
    (void)core;

    Str term = StrInit(), filters = StrInit();
    STR_ARG (term, 1);
    STR_ARG (filters, 2);
    return collectionFilteredSearch (term, filters, ORDER_BY_MODEL, true);
}

/**
 * REcas
 * */
R_IPI RCmdStatus
    r_collection_basic_info_asc_size_handler (RCore* core, int argc, const char** argv) {
    (void)core;

    Str term = StrInit(), filters = StrInit();
    STR_ARG (term, 1);
    STR_ARG (filters, 2);
    return collectionFilteredSearch (term, filters, ORDER_BY_SIZE, true);
}

/**
 * REcdt
 * */
R_IPI RCmdStatus
    r_collection_basic_info_desc_time_handler (RCore* core, int argc, const char** argv) {
    (void)core;

    Str term = StrInit(), filters = StrInit();
    STR_ARG (term, 1);
    STR_ARG (filters, 2);
    return collectionFilteredSearch (term, filters, ORDER_BY_LAST_UPDATED, false);
}

/**
 * REcdo
 * */
R_IPI RCmdStatus
    r_collection_basic_info_desc_owner_handler (RCore* core, int argc, const char** argv) {
    (void)core;

    Str term = StrInit(), filters = StrInit();
    STR_ARG (term, 1);
    STR_ARG (filters, 2);
    return collectionFilteredSearch (term, filters, ORDER_BY_OWNER, false);
}

/**
 * REcdn
 * */
R_IPI RCmdStatus
    r_collection_basic_info_desc_name_handler (RCore* core, int argc, const char** argv) {
    (void)core;

    Str term = StrInit(), filters = StrInit();
    STR_ARG (term, 1);
    STR_ARG (filters, 2);
    return collectionFilteredSearch (term, filters, ORDER_BY_NAME, false);
}

/**
 * REcdm
 * */
R_IPI RCmdStatus
    r_collection_basic_info_desc_model_handler (RCore* core, int argc, const char** argv) {
    (void)core;

    Str term = StrInit(), filters = StrInit();
    STR_ARG (term, 1);
    STR_ARG (filters, 2);
    return collectionFilteredSearch (term, filters, ORDER_BY_MODEL, false);
}

/**
 * REcds
 * */
R_IPI RCmdStatus
    r_collection_basic_info_desc_size_handler (RCore* core, int argc, const char** argv) {
    (void)core;

    Str term = StrInit(), filters = StrInit();
    STR_ARG (term, 1);
    STR_ARG (filters, 2);
    return collectionFilteredSearch (term, filters, ORDER_BY_SIZE, false);
}

RCmdStatus searchBinary (SearchBinaryRequest* search) {
    BinaryInfos binaries = SearchBinary (GetConnection(), search);
    SearchBinaryRequestDeinit (search);

    RTable* t = r_table_new ("Searched Binaries Results");
    r_table_set_columnsf (
        t,
        "snnssss",
        "name",
        "binary_id",
        "analysis_id",
        "model",
        "owner",
        "created_at",
        "sha256"
    );

    VecForeachPtr (&binaries, binary, {
        r_table_add_rowf (
            t,
            "snnssss",
            binary->binary_name.data,
            binary->binary_id,
            binary->analysis_id,
            binary->model_name.data,
            binary->owned_by.data,
            binary->created_at.data,
            binary->sha256.data
        );
    });

    const char* s = r_table_tofancystring (t);
    r_cons_println (s);
    FREE (s);
    r_table_free (t);

    VecDeinit (&binaries);

    return R_CMD_STATUS_OK;
}

/**
 * REbs
 * */
R_IPI RCmdStatus r_binary_search_handler (RCore* core, int argc, const char** argv) {
    (void)core;

    Str tags = StrInit();

    SearchBinaryRequest search = SearchBinaryRequestInit();
    STR_ARG (search.partial_name, 1);
    STR_ARG (search.partial_sha256, 2);
    STR_ARG (search.model_name, 3);
    STR_ARG (tags, 4);

    search.tags = StrSplit (&tags, ",");
    return searchBinary (&search);
}

/**
 * REbsn
 * */
R_IPI RCmdStatus r_binary_search_by_name_handler (RCore* core, int argc, const char** argv) {
    (void)core;

    SearchBinaryRequest search = SearchBinaryRequestInit();
    STR_ARG (search.partial_name, 1);
    STR_ARG (search.model_name, 3);
    return searchBinary (&search);
}

/**
 * REbsh
 * */
R_IPI RCmdStatus r_binary_search_by_sha256_handler (RCore* core, int argc, const char** argv) {
    (void)core;

    SearchBinaryRequest search = SearchBinaryRequestInit();
    STR_ARG (search.partial_sha256, 1);
    STR_ARG (search.model_name, 3);
    return searchBinary (&search);
}

RCmdStatus openLinkForId (const char* type, u64 id) {
    Connection* conn = GetConnection();

    Str host = StrDup (&conn->host);
    StrReplaceZstr (&host, "api", "portal", 1);
    StrAppendf (&host, "/%s/%llu", type, id);

    r_cons_println (host.data);

    const char* syscmd = NULL;
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
    syscmd = "start";
#elif __APPLE__
    syscmd = "open";
#elif __linux__
    syscmd = "xdg-open";
#else
    syscmd = NULL;
#    warn "Unsupported OS. Won't open links from command line."
#endif

    if (syscmd) {
        Str cmd = StrInit();
        StrPrintf (&cmd, "%s %s", syscmd, host.data);
        r_sys_cmd (cmd.data);
        StrDeinit (&cmd);
    }

    StrDeinit (&host);

    return R_CMD_STATUS_OK;
}

/**
 * REco
 * */
R_IPI RCmdStatus r_collection_link_handler (RCore* core, int argc, const char** argv) {
    CollectionId cid = 0;
    NUM_ARG (cid, 1);

    if (!cid) {
        DISPLAY_ERROR ("Invalid collection ID provided.");
        return R_CMD_STATUS_WRONG_ARGS;
    }

    return openLinkForId ("collection", cid);
}

/**
 * REao
 * */
R_IPI RCmdStatus r_analysis_link_handler (RCore* core, int argc, const char** argv) {
    BinaryId bid = 0;
    NUM_ARG (bid, 1);

    if (!bid) {
        bid = GetBinaryId();
        if (!bid) {
            DISPLAY_ERROR (
                "No existing analysis attached to current session, and no binary id provided.\n"
                "Please create a new analysis or apply an existing one, or provide a valid "
                "binary "
                "id"
            );
            return R_CMD_STATUS_WRONG_ARGS;
        }
    }

    return openLinkForId ("analyses", bid);
}

/**
 * REfo
 * */
R_IPI RCmdStatus r_function_link_handler (RCore* core, int argc, const char** argv) {
    FunctionId fid = 0;
    if (!NUM_ARG (fid, 1)) {
        DISPLAY_ERROR ("Invalid function ID provided.");
        return R_CMD_STATUS_WRONG_ARGS;
    }

    return openLinkForId ("collection", fid);
}

/**
 * REal
 * */
R_IPI RCmdStatus
    r_get_analysis_logs_using_analysis_id_handler (RCore* core, int argc, const char** argv) {
    AnalysisId analysis_id = 0;

    if (!NUM_ARG (analysis_id, 1)) {
        if (!GetBinaryId()) {
            DISPLAY_ERROR (
                "No RevEngAI analysis attached with current session.\n"
                "Either provide an analysis id, apply an existing analysis or create a new "
                "analysis\n"
            );
            return R_CMD_STATUS_WRONG_ARGS;
        }

        analysis_id = AnalysisIdFromBinaryId (GetConnection(), GetBinaryId());
        if (!analysis_id) {
            DISPLAY_ERROR ("Failed to get analysis id from binary id attached to this session");
            return R_CMD_STATUS_WRONG_ARGS;
        }
    }

    Str logs = GetAnalysisLogs (GetConnection(), analysis_id);
    if (logs.length) {
        r_cons_println (logs.data);
    } else {
        DISPLAY_ERROR ("Failed to get analysis logs.");
        return R_CMD_STATUS_WRONG_ARGS;
    }
    StrDeinit (&logs);

    return R_CMD_STATUS_OK;
}

/**
 * REalb
 * */
R_IPI RCmdStatus
    r_get_analysis_logs_using_binary_id_handler (RCore* core, int argc, const char** argv) {
    AnalysisId binary_id = 0;
    NUM_ARG (binary_id, 1);

    if (!binary_id && !GetBinaryId()) {
        DISPLAY_ERROR (
            "No RevEngAI analysis attached with current session.\n"
            "Either provide an analysis id, apply an existing analysis or create a new "
            "analysis\n"
        );
        return R_CMD_STATUS_WRONG_ARGS;
    }

    AnalysisId analysis_id = AnalysisIdFromBinaryId (GetConnection(), GetBinaryId());
    if (!analysis_id) {
        DISPLAY_ERROR (
            "Failed to get analysis id from binary id. Please check validity of provided "
            "binary id"
        );
        return R_CMD_STATUS_OK;
    }

    Str logs = GetAnalysisLogs (GetConnection(), analysis_id);
    if (logs.length) {
        r_cons_println (logs.data);
    } else {
        DISPLAY_ERROR (
            "Failed to get analysis logs. Please check your internet connection, and plugin "
            "log "
            "file."
        );
        return R_CMD_STATUS_OK;
    }
    StrDeinit (&logs);

    return R_CMD_STATUS_OK;
}

/**
 * "REar"
 * */
R_IPI RCmdStatus r_get_recent_analyses_handler (RCore* core, int argc, const char** argv) {
    (void)core;
    (void)argc;
    (void)argv;

    RecentAnalysisRequest recents  = RecentAnalysisRequestInit();
    AnalysisInfos         analyses = GetRecentAnalysis (GetConnection(), &recents);
    RecentAnalysisRequestDeinit (&recents);

    if (!analyses.length) {
        DISPLAY_ERROR ("Failed to get most recent analysis. Are you a new user?");
        return R_CMD_STATUS_OK;
    }

    RTable* t = r_table_new ("Most Recent Analysis");
    r_table_set_columnsf (
        t,
        "nnssss",
        "analysis_id",
        "binary_id",
        "status",
        "creation",
        "binary_name",
        "scope"
    );

    VecForeachPtr (&analyses, analysis, {
        Str status_str = StrInit();
        StatusToStr (analysis->status, &status_str);
        r_table_add_rowf (
            t,
            "nnssss",
            analysis->analysis_id,
            analysis->binary_id,
            status_str.data,
            analysis->creation.data,
            analysis->binary_name.data,
            analysis->is_private ? "PRIVATE" : "PUBLIC"
        );
        StrDeinit (&status_str);
    });

    const char* s = r_table_tofancystring (t);
    r_cons_println (s);
    FREE (s);
    r_table_free (t);

    return R_CMD_STATUS_OK;
}

/**
 * "REaud"
 * */
R_IPI RCmdStatus
    r_ann_auto_analyze_restrict_debug_handler (RCore* core, int argc, const char** argv) {
    return autoAnalyze (core, argc, argv, true);
}

/// Launches the given editor with the given filepath and waits for it to exit.
/// Handles both GUI and terminal editors.
static inline int launchEditorAndWait (Str* user_editor, const char* filepath) {
    // Choose default editor if not specified
    const char* editor = user_editor ? user_editor->data :
#ifdef _WIN32
                                       "notepad";
#elif __APPLE__
                                       "open -W -n -e TextEdit";
#else
                                       "nano";
#endif

    Str command = StrInit();
    StrPrintf (&command, "%s \"%s\"", editor, filepath);

    LOG_INFO ("Launching editor command = %s", command.data);

#ifdef _WIN32
    // Use system() on Windows — simple, no forking
    int res = system (command);

    StrDeinit (&command);
    return res;
#else
    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        execl ("/bin/sh", "sh", "-c", command.data, (char*)NULL);
        perror ("execl failed");
        StrDeinit (&command);
        exit (127);
    } else if (pid > 0) {
        // Parent process waits for terminal editors
        int status;
        waitpid (pid, &status, 0);
        StrDeinit (&command);
        return WIFEXITED (status) ? WEXITSTATUS (status) : -1;
    } else {
        StrDeinit (&command);
        perror ("fork failed");
        return -1;
    }
#endif
}

static inline bool isUserComment (Str* str) {
    if (!str || !str->data) {
        return false;
    }

    // Skip leading whitespace
    u32 i = 0;
    while (i < str->length && isspace (str->data[i])) {
        i++;
    }

    // Check if remaining string starts with "//>", 
    if (i + 3 <= str->length && 
        str->data[i] == '/' && 
        str->data[i + 1] == '/' && 
        str->data[i + 2] == '>') {
        return true;
    }

    return false;
}

static inline Str extractCommentString (Str* comment_line) {
    if (!comment_line || !comment_line->data) {
        return StrInit();
    }

    // Skip leading whitespace
    u32 i = 0;
    while (i < comment_line->length && isspace (comment_line->data[i])) {
        i++;
    }

    // Skip "//>" prefix
    if (i + 3 <= comment_line->length && 
        comment_line->data[i] == '/' && 
        comment_line->data[i + 1] == '/' && 
        comment_line->data[i + 2] == '>') {
        i += 3;
        
        // Skip any whitespace after "//>", 
        while (i < comment_line->length && isspace (comment_line->data[i])) {
            i++;
        }
        
        // Return the remaining string as the comment content
        return StrInitFromCstr (
            comment_line->data + i,
            comment_line->length - i
        );
    }

    return StrInit();
}

Comment* findComment (Str* to_search, Comments* comments) {
    if (!isUserComment (to_search)) {
        LOG_FATAL ("Invalid comment start");
    }

    // skip whitespace
    u32 off = 3;
    while (isspace (StrCharAt (to_search, off))) {
        off++;
    }

    VecForeachPtr (comments, comment, {
        if (!strcmp (StrCharPtrAt (to_search, off), comment->content.data)) {
            return comment;
        }
    });

    return NULL;
}

bool getCommentRange (
    DiffLines* diff,
    Strs*      original_dec,
    u64        search_start,
    u64*       out_start,
    u64*       out_end
) {
    if (!diff || !original_dec || !out_start || !out_end) {
        LOG_FATAL ("Invalid arguments");
    }

    LOG_INFO ("getCommentRange: search_start=%llu, diff->length=%zu", search_start, diff->length);

    for (u64 s = search_start; s < diff->length; s++) {
        DiffLine* dl = VecPtrAt (diff, s);
        LOG_INFO ("getCommentRange: processing diff line %llu, type=%c", s, (char)dl->type);

        // skip all following comments
        bool found_comment = true;
        while (found_comment && s < diff->length) {
            switch (dl->type) {
                case DIFF_TYPE_MOD :
                case DIFF_TYPE_MOV : {
                    if (isUserComment (&dl->mod.new_content)) {
                        s++;
                        if (s < diff->length) {
                            dl = VecPtrAt (diff, s);
                        }
                        found_comment = true;
                    } else {
                        found_comment = false;
                    }
                    break;
                }

                case DIFF_TYPE_REM :
                case DIFF_TYPE_ADD :
                case DIFF_TYPE_SAM : {
                    if (isUserComment (&dl->sam.content)) {
                        s++;
                        if (s < diff->length) {
                            dl = VecPtrAt (diff, s);
                        }
                        found_comment = true;
                    } else {
                        found_comment = false;
                    }
                    break;
                }

                default : {
                    LOG_FATAL ("Unreachable code reached. Invalid diff line type");
                }
            }
        }

        // find modified code lines from decompilation output
        // a continuous sequence of modified code lines defines our range
        *out_start = -1;
        *out_end   = -1;
        LOG_INFO ("getCommentRange: starting range detection at diff line %llu", s);
        while (s < diff->length) {
            switch (dl->type) {
                case DIFF_TYPE_MOD : {
                    if (*out_start == (u64)-1) {
                        *out_start = dl->mod.new_line;
                    }

                    *out_end = dl->mod.new_line;
                    LOG_INFO ("getCommentRange: found MOD line, range now (%llu, %llu)", *out_start, *out_end);
                    break;
                }

                case DIFF_TYPE_MOV :
                case DIFF_TYPE_SAM :
                case DIFF_TYPE_REM :
                case DIFF_TYPE_ADD : {
                    LOG_INFO ("getCommentRange: hit non-MOD line (type=%c), returning %s", (char)dl->type, (*out_start != (u64)-1) ? "true" : "false");
                    return *out_start != (u64)-1;
                }
            }

            s++;
            if (s < diff->length) {
                dl = VecPtrAt (diff, s);
            }
        }

        // If we exit the while loop because we reached the end of diff,
        // and we found some MOD lines, return the range
        if (*out_start != (u64)-1) {
            LOG_INFO ("getCommentRange: reached end of diff, returning range (%llu, %llu)", *out_start, *out_end);
            return true;
        }
    }

    LOG_INFO ("getCommentRange: reached end of function, returning false");
    return false;
}

R_IPI RCmdStatus
    updateDecompilerComments (RCore* core, const char* function_name, bool for_ai_comments) {
    FunctionId function_id = rLookupFunctionIdForFunctionWithName (core, function_name);
    if (!function_id) {
        DISPLAY_ERROR ("Failed to get a function ID for function with given name.");
        return R_CMD_STATUS_WRONG_ARGS;
    }

    if (!for_ai_comments) {
        LOG_ERROR ("Only AI Decompilation supported for now!");
        return R_CMD_STATUS_OK;
    }

    Comments        comments  = VecInit();
    AiDecompilation ai_decomp = {0};
    Str             code      = getAiDecompilation (function_id, false, &ai_decomp, &comments);

    const char* tmpfilepath = r_file_temp (NULL);
    FILE*       f           = fopen (tmpfilepath, "w");
    fputs (code.data, f);
    fclose (f);

    LOG_INFO ("written decompilation contents to temp file path = %s", tmpfilepath);

    int launch_result = launchEditorAndWait (ConfigGet (GetConfig(), "editor"), tmpfilepath);
    if (launch_result != 0) {
        DISPLAY_ERROR (
            "Editor process failed with code %d. Failed to provide access to decompiled code.",
            launch_result
        );
        return R_CMD_STATUS_OK;
    }

    // Read the modified content
    FILE* fp = fopen (tmpfilepath, "r");
    if (!fp) {
        Str errstr = StrInit();
        SysStrError (errno, &errstr);
        LOG_ERROR ("Failed to open file temporary file : %s", errstr.data);
        StrDeinit (&errstr);
        return R_CMD_STATUS_OK;
    }

    fseek (fp, 0, SEEK_END);
    u64 new_code_length = ftell (fp);
    rewind (fp);

    Str new_code = StrInit();
    StrReserve (&new_code, new_code_length);
    fread (new_code.data, 1, new_code_length, fp);
    new_code.data[new_code_length] = '\0';
    new_code.length = new_code_length;
    fclose (fp);

    // get lines from original decompilation string
    // without comments, without summary, just vanilla decompilation
    Strs original_decomp = StrSplit (&ai_decomp.decompilation, "\n");

    DiffLines diff = GetDiff (&code, &new_code);
    VecForeachPtrIdx (&diff, d, diff_line_idx, {
        switch (d->type) {
            case DIFF_TYPE_SAM : {
                if (isUserComment (&d->sam.content)) {
                    DISPLAY_INFO ("= %s", d->sam.content.data);
                }
                break;
            }

            case DIFF_TYPE_REM : {
                if (isUserComment (&d->rem.content)) {
                    Comment* comment = findComment (&d->rem.content, &comments);
                    if (comment) {
                        if (DeleteAiDecompilationComment (
                                GetConnection(),
                                function_id,
                                comment->id
                            )) {
                            DISPLAY_INFO ("- %s", comment->content.data);
                        } else {
                            DISPLAY_ERROR ("!- %s", comment->content.data);
                        }
                    } else {
                        LOG_ERROR("Non-existent comment deleted. This might indicate bug in program! : %s", d->rem.content.data);
                        DISPLAY_ERROR ("Internal error! Please check plugin logs. Contact developers.");
                        return R_CMD_STATUS_OK;
                    }
                } else {
                    DISPLAY_ERROR (
                        "Diff shows deletion of a non-comment line! "
                        "Please make changes to comments only!\n"
                        "Deleted line : %s",
                        d->rem.content.data
                    );
                }
                break;
            }

            case DIFF_TYPE_ADD : {
                if (isUserComment (&d->add.content)) {
                    Str comment_content = extractCommentString (&d->add.content);

                    u64 start_line = 0;
                    u64 end_line   = 0;

                    if (getCommentRange (
                            &diff,
                            &original_decomp,
                            diff_line_idx,
                            &start_line,
                            &end_line
                        )) {
                        if (AddAiDecompilationComment (
                                GetConnection(),
                                function_id,
                                &comment_content,
                                start_line,
                                end_line
                            )) {
                            DISPLAY_INFO (
                                "+ (%llu, %llu) %s",
                                start_line,
                                end_line,
                                comment_content.data
                            );
                        } else {
                            DISPLAY_INFO ("!+ (?, ?) %s", comment_content.data);
                        }
                    } else {
                        DISPLAY_ERROR (
                            "Failed to get comment region for a comment.\n"
                            "Did you forget to indent code to specify comment region?"
                        );
                    }

                    StrDeinit (&comment_content);
                } else {
                    DISPLAY_ERROR (
                        "Diff shows addition of a non-comment line! "
                        "Please make changes to comments only!\n"
                        "All user-comments must begin with prefix //>\n"
                        "Added line : %s",
                        d->add.content.data
                    );
                }
                break;
            }

            case DIFF_TYPE_MOD : {
                if (isUserComment (&d->mod.new_content) &&
                    isUserComment (&d->mod.old_content)) {
                    // get exact old comment string, skipping whitespaces
                    // this will also help us find comment id for comment to be updated
                    Str old_comment_content = extractCommentString (&d->mod.old_content);

                    // find old comment, if non-existent then there's a bug in diff
                    Comment* old_comment = findComment (&old_comment_content, &comments);
                    if (!old_comment) {
                        LOG_ERROR (
                            "Non-existent comment deleted. This might indicate bug in program!"
                        );
                        DISPLAY_ERROR (
                            "Internal error. Please check plugin logs. Contact developers."
                        );
                        return R_CMD_STATUS_OK;
                    }

                    // get exact new comment, skipping whitespaces
                    Str new_comment_content = extractCommentString (&d->mod.new_content);


                    if (UpdateAiDecompilationComment (
                            GetConnection(),
                            function_id,
                            old_comment->id,
                            &new_comment_content
                        )) {
                        DISPLAY_INFO ("~ %s", new_comment_content.data);
                    } else {
                        DISPLAY_ERROR (
                            "Failed to update comment.\n"
                            "OLD : %s\n"
                            "NEW : %s",
                            old_comment_content.data,
                            new_comment_content.data
                        );
                    }

                    StrDeinit (&new_comment_content);
                    StrDeinit (&old_comment_content);
                } else {
                    Str old_trimmed = StrStrip (&d->mod.old_content, NULL);
                    Str new_trimmed = StrStrip (&d->mod.new_content, NULL);
                    if (StrCmp (&old_trimmed, &new_trimmed) != 0) {
                        DISPLAY_ERROR (
                            "Diff shows modification of/to a non-comment line! "
                            "Please make changes to comments only!\n"
                            "Non-comment lines should only be indented, not modified completely!\n"
                            "Modified line : %s",
                            d->mod.new_content.data
                        );
                    }
                    StrDeinit (&old_trimmed);
                    StrDeinit (&new_trimmed);
                }
                break;
            }

            case DIFF_TYPE_MOV : {
                // NOTE: In case of mov, new_content and old_content are exactly same
                // but are clones of each other, hence pointers are not same!
                if (isUserComment (&d->mov.new_content)) {
                    // remove old comment
                    Comment* old_comment = findComment (&d->mov.old_content, &comments);
                    if (old_comment) {
                        if (DeleteAiDecompilationComment (
                                GetConnection(),
                                function_id,
                                old_comment->id
                            )) {
                            DISPLAY_INFO ("- %s", old_comment->content.data);
                        } else {
                            DISPLAY_ERROR ("!- %s", old_comment->content.data);
                        }
                    } else {
                        DISPLAY_ERROR (
                            "Diff shows movement of a non-existent comment!\n\t%s\n",
                            d->mov.old_content.data
                        );
                    }

                    // add new comment with new range
                    u64 start_line = 0;
                    u64 end_line   = 0;
                    if (getCommentRange (
                            &diff,
                            &original_decomp,
                            diff_line_idx,
                            &start_line,
                            &end_line
                        )) {
                        if (AddAiDecompilationComment (
                                GetConnection(),
                                function_id,
                                &old_comment->content,
                                start_line,
                                end_line
                            )) {
                            DISPLAY_INFO (
                                "+ (%llu, %llu) %s",
                                start_line,
                                end_line,
                                old_comment->content.data
                            );
                        } else {
                            DISPLAY_INFO ("!+ (?, ?) %s", old_comment->content.data);
                        }
                    } else {
                        DISPLAY_ERROR (
                            "Failed to get comment region for a moved comment.\n"
                            "Did you forget to indent code to specify comment region?"
                        );
                    }
                }
                break;
            }

            default : {
                LOG_FATAL ("Unreachable code reached : invalid diff line type");
            }
        }
    });

    // Clean up resources
    VecDeinit (&comments);
    AiDecompilationDeinit (&ai_decomp);
    StrDeinit (&code);
    StrDeinit (&new_code);
    VecDeinit (&original_decomp);
    VecDeinit (&diff);
    FREE (tmpfilepath);

    return R_CMD_STATUS_OK;
}

/**
 * "REdac"
 * */
R_IPI RCmdStatus
    r_update_ai_decompilation_comments_handler (RCore* core, int argc, const char** argv) {
    const char* fn_name = NULL;
    if (ZSTR_ARG (fn_name, 1)) {
        return updateDecompilerComments (core, fn_name, true);
    }
    return R_CMD_STATUS_WRONG_ARGS;
}

/**
 * "REdc"
 * */
R_IPI RCmdStatus
    r_update_decompilation_comments_handler (RCore* core, int argc, const char** argv) {
    const char* fn_name = NULL;
    if (ZSTR_ARG (fn_name, 1)) {
        return updateDecompilerComments (core, fn_name, false);
    }
    return R_CMD_STATUS_WRONG_ARGS;
}

/**
 * "REart"
 * */


// clang-format off
R_IPI RCmdStatus r_show_revengai_art_handler (RCore* core, int argc, const char** argv) {
    (void)core;
    (void)argc;
    (void)argv;

    r_cons_println (
        "\n"
        "\n"
        ":::::::::::        :::::::::::\n"
        "::    ::::::      ::::    ::::             %%%%%%%%%%%%%                                        %%%%%%%%%%%%%%%\n"
        "::    :::::::    :::::    ::::            %%%%%%%%%%%%%%%                                       %%%%%%%%%%%%%%%                                %%%%%@\n"
        "::::::::::::::::::::::::::::::           %%%%%%%    %%%%%                                       %%%%%                                          %%%%%%\n"
        ":::::::::   ::::   :::::::::::           %%%%%%     %%%%%     @%%%%%%%%%%    %%%%%@    %%%%%    %%%%%             %%%%% %%%%%%%%      @%%%%%%%%%%%\n"
        " :::::::    ::::    :::::::::            %%%%%%     %%%%%    %%%%%%%%%%%%%%  %%%%%%    %%%%%%   %%%%%%%%%%%%%%    %%%%%%%%%%%%%%%    %%%%%%%%%%%%%%\n"
        "     ::::::::::::::::::::                %%%%%%%%%%%%%%%   %%%%%     @%%%%%  %%%%%%    %%%%%    %%%%%%%%%%%%%%    %%%%%%    %%%%%%  %%%%%@    %%%%%@\n"
        "       ::::::::::::::::                    %%%%%%%%%%%%%  @%%%%%%%%%%%%%%%%   %%%%%@   %%%%%    %%%%%%%%%%%%%%    %%%%%     %%%%%%  %%%%%%    %%%%%%               @@@@    @@@@@@@@\n"
        "     ::::   ::::    :::::                  @%%%%%@ %%%%%  %%%%%%%%%%%%%%%%%   %%%%%% %%%%%%     %%%%%             %%%%%     %%%%%%   %%%%%%%%%%%%%@               @@@@@@     @@@\n"
        " ::::::::   ::::    :::::::::              %%%%%%@ %%%%%   %%%%%               %%%%%%%%%%%      %%%%%             %%%%%     %%%%%%     %%%%%%%%%%                @@@@ @@@    @@@\n"
        "::::::::::::::::::::::::::::::          %%%%%%%%   %%%%%   %%%%%%@   %%%%%      %%%%%%%%%       %%%%%%%%%%%%%%%   %%%%%     %%%%%%   %%%%                        @@@@@@@@    @@@\n"
        "::    ::::::::::::::::    ::::          %%%%%%%    %%%%%    @%%%%%%%%%%%%%       %%%%%%%%       %%%%%%%%%%%%%%%   %%%%%     %%%%%%   %%%%%%%%%%%%%%%    @@@@    @@@@  @@@@ @@@@@@@@\n"
        "::    :::::::    :::::    ::::          %%%%%      %%%%%       %%%%%%%%%         %%%%%%%        %%%%%%%%%%%%%%    %%%%%     %%%%%@   %%%%%%%%%%%%%%%%    @@@    @@@   @@@@ @@@@@@@@\n"
        ":.::::::::::      ::::::::::::                                                                                                      %%%%        %%%%%\n"
        ":::::::::::        :::::::::::                                                                                                      %%%%%%%%%%%%%%%%%\n"
        "                                                                                                                                     %%%%%%%%%%%%%%\n"
        "\n"
    );
    return R_CMD_STATUS_OK;
}
