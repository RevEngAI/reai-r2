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
#include <Reai/Diff.h>

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

                    AiDecompilation aidec = GetAiDecompilation (GetConnection(), fn_id, true);
                    Str*            smry  = &aidec.raw_ai_summary;
                    Str*            dec   = &aidec.raw_decompilation;

                    Str code = StrInit();

                    static i32 SOFT_LIMIT = 120;

                    i32   l = smry->length;
                    char* p = smry->data;
                    while (l > SOFT_LIMIT) {
                        char* p1 = strchr (p + SOFT_LIMIT, ' ');
                        if (p1) {
                            StrAppendf (&code, "// %.*s\n", (i32)(p1 - p), p);
                            p1++;
                            l -= (p1 - p);
                            p  = p1;
                        } else {
                            break;
                        }
                    }
                    StrAppendf (&code, "// %.*s\n\n", (i32)l, p);
                    StrMerge (&code, dec);

                    LOG_INFO ("aidec.functions.length = %zu", aidec.functions.length);
                    VecForeachIdx (&aidec.functions, function, idx, {
                        Str dname = StrInit();
                        StrPrintf (&dname, "<DISASM_FUNCTION_%llu>", idx);
                        StrReplace (&code, &dname, &function.name, -1);
                        StrDeinit (&dname);
                    });

                    LOG_INFO ("aidec.strings.length = %zu", aidec.strings.length);
                    VecForeachIdx (&aidec.strings, string, idx, {
                        Str dname = StrInit();
                        StrPrintf (&dname, "<DISASM_STRING_%llu>", idx);
                        StrReplace (&code, &dname, &string.string, -1);
                        StrDeinit (&dname);
                    });

                    LOG_INFO (
                        "aidec.unmatched.functions.length = %zu",
                        aidec.unmatched.functions.length
                    );
                    VecForeachIdx (&aidec.unmatched.functions, function, idx, {
                        Str dname = StrInit();
                        StrPrintf (&dname, "<UNMATCHED_FUNCTION_%llu>", idx);
                        StrReplace (&code, &dname, &function.name, -1);
                        StrDeinit (&dname);
                    });

                    LOG_INFO (
                        "aidec.unmatched.strings.length = %zu",
                        aidec.unmatched.strings.length
                    );
                    VecForeachIdx (&aidec.unmatched.strings, string, idx, {
                        Str dname = StrInit();
                        StrPrintf (&dname, "<UNMATCHED_STRING_%llu>", idx);
                        StrReplace (&code, &dname, &string.value.str, -1);
                        StrDeinit (&dname);
                    });

                    LOG_INFO ("aidec.unmatched.vars.length = %zu", aidec.unmatched.vars.length);
                    VecForeachIdx (&aidec.unmatched.vars, var, idx, {
                        Str dname = StrInit();
                        StrPrintf (&dname, "<VAR_%llu>", idx);
                        StrReplace (&code, &dname, &var.value.str, -1);
                        StrDeinit (&dname);
                    });

                    LOG_INFO (
                        "aidec.unmatched.external_vars.length = %zu",
                        aidec.unmatched.external_vars.length
                    );
                    VecForeachIdx (&aidec.unmatched.external_vars, var, idx, {
                        Str dname = StrInit();
                        StrPrintf (&dname, "<EXTERNAL_VARIABLE_%llu>", idx);
                        StrReplace (&code, &dname, &var.value.str, -1);
                        StrDeinit (&dname);
                    });

                    LOG_INFO (
                        "aidec.unmatched.custom_types.length = %zu",
                        aidec.unmatched.custom_types.length
                    );
                    VecForeachIdx (&aidec.unmatched.custom_types, var, idx, {
                        Str dname = StrInit();
                        StrPrintf (&dname, "<CUSTOM_TYPE_%llu>", idx);
                        StrReplace (&code, &dname, &var.value.str, -1);
                        StrDeinit (&dname);
                    });

                    // print decompiled code with summary
                    r_cons_println (code.data);

                    StrDeinit (&code);
                    AiDecompilationDeinit (&aidec);
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
                "Please create a new analysis or apply an existing one, or provide a valid binary "
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
            "Either provide an analysis id, apply an existing analysis or create a new analysis\n"
        );
        return R_CMD_STATUS_WRONG_ARGS;
    }

    AnalysisId analysis_id = AnalysisIdFromBinaryId (GetConnection(), GetBinaryId());
    if (!analysis_id) {
        DISPLAY_ERROR (
            "Failed to get analysis id from binary id. Please check validity of provided binary id"
        );
        return R_CMD_STATUS_OK;
    }

    Str logs = GetAnalysisLogs (GetConnection(), analysis_id);
    if (logs.length) {
        r_cons_println (logs.data);
    } else {
        DISPLAY_ERROR (
            "Failed to get analysis logs. Please check your internet connection, and plugin log "
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

int sep = 2;



bool drawSourceDiff (RConsCanvas* c, int w, int h, DiffLines* diff) {
    int x = sep / 2;
    int y = sep / 2;
    w     = w / 2 - sep;
    h     = h - sep;

    r_cons_canvas_box (c, x, y, w, h, Color_RESET);
    r_cons_canvas_write_at (c, "SOURCE", x + 2, y + 1);

    int line_y = y + 3;
    int max_lines = h - 5;
    int current_line = 0;
    int content_width = w - 8;

    if(content_width <= 0 || max_lines <= 0) {
        return false;
    }

        VecForeachPtr (diff, diff_line, {
        if (current_line >= max_lines) break;

        Str line_str = StrInit();

        switch (diff_line->type) {
            case DIFF_TYPE_SAM: {
                // Same lines - show normally
                int content_len = MIN2(diff_line->sam.content.length, (u64)content_width);
                StrPrintf(&line_str, "%3llu %.*s", diff_line->sam.line + 1, content_len, diff_line->sam.content.data);
                break;
            }
            case DIFF_TYPE_REM: {
                // Removed lines
                int content_len = MIN2(diff_line->rem.content.length, (u64)content_width);
                StrPrintf(&line_str, "%3llu %.*s", diff_line->rem.line + 1, content_len, diff_line->rem.content.data);
                break;
            }
            case DIFF_TYPE_MOD: {
                // Modified lines - show old content
                int content_len = MIN2(diff_line->mod.old_content.length, (u64)content_width);
                StrPrintf(&line_str, "%3llu %.*s", diff_line->mod.old_line + 1, content_len, diff_line->mod.old_content.data);
                break;
            }
            case DIFF_TYPE_MOV: {
                // Moved lines
                int content_len = MIN2(diff_line->mov.old_content.length, (u64)content_width);
                StrPrintf(&line_str, "%3llu %.*s", diff_line->mov.old_line + 1, content_len, diff_line->mov.old_content.data);
                break;
            }
            case DIFF_TYPE_ADD: {
                // Added lines - show empty space in source
                StrPrintf(&line_str, "    ");
                break;
            }
            default:
                StrDeinit(&line_str);
                continue;
        }

        r_cons_canvas_write_at (c, line_str.data, x + 1, line_y + current_line);
        StrDeinit(&line_str);
        current_line++;
    });

    return true;
}

bool drawTargetDiff (RConsCanvas* c, int w, int h, DiffLines* diff) {
    int y = sep / 2;
    int x = sep / 2;
    x     = w / 2 + sep / 2;
    w     = w / 2 - sep;
    h     = h - sep;

    r_cons_canvas_box (c, x, y, w, h, Color_RESET);
    r_cons_canvas_write_at (c, "TARGET", x + 2, y + 1);

    int line_y = y + 3;
    int max_lines = h - 5;
    int current_line = 0;
    int content_width = w - 8;

    if(content_width <= 0 || max_lines <= 0) {
        return false;
    }

    VecForeachPtr (diff, diff_line, {
        if (current_line >= max_lines) break;

        Str line_str = StrInit();

        switch (diff_line->type) {
            case DIFF_TYPE_SAM: {
                // Same lines - show normally
                int content_len = MIN2(diff_line->sam.content.length, (u64)content_width);
                StrPrintf(&line_str, "%3llu %.*s", diff_line->sam.line + 1, content_len, diff_line->sam.content.data);
                break;
            }
            case DIFF_TYPE_ADD: {
                // Added lines
                int content_len = MIN2(diff_line->add.content.length, (u64)content_width);
                StrPrintf(&line_str, "%3llu %.*s", diff_line->add.line + 1, content_len, diff_line->add.content.data);
                break;
            }
            case DIFF_TYPE_MOD: {
                // Modified lines - show new content
                int content_len = MIN2(diff_line->mod.new_content.length, (u64)content_width);
                StrPrintf(&line_str, "%3llu %.*s", diff_line->mod.new_line + 1, content_len, diff_line->mod.new_content.data);
                break;
            }
            case DIFF_TYPE_MOV: {
                // Moved lines
                int content_len = MIN2(diff_line->mov.new_content.length, (u64)content_width);
                StrPrintf(&line_str, "%3llu %.*s", diff_line->mov.new_line + 1, content_len, diff_line->mov.new_content.data);
                break;
            }
            case DIFF_TYPE_REM: {
                // Removed lines - show empty space in target
                StrPrintf(&line_str, "    ");
                break;
            }
            default:
                StrDeinit(&line_str);
                continue;
        }

        r_cons_canvas_write_at (c, line_str.data, x + 1, line_y + current_line);
        StrDeinit(&line_str);
        current_line++;
    });
    
    return true;
}

RConsCanvas* drawDiff (RConsCanvas* c, DiffLines* diff) {
    // get terminal size
    int h, w = r_cons_get_size (&h);

    // if canvas is not created then create
    if (c == NULL) {
        c = r_cons_canvas_new (w, h);
    }

    // resize canvas on windows resize
    if (c->w != w || c->h != h) {
        r_cons_canvas_resize (c, w, h);
    }

    // create canvas
    r_cons_canvas_clear (c);
    if(!drawSourceDiff (c, w, h, diff)) {
        return NULL;
    }
    if(!drawTargetDiff (c, w, h, diff)) {
        return NULL;
    }
    r_cons_canvas_print (c);
    r_cons_flush();

    return c;
}

// Structure to hold list items and their corresponding target strings
typedef struct {
    Str name;           // Display name in the list
    Str target_content; // Corresponding target string for diff
} DiffListItem;

typedef Vec(DiffListItem) DiffListItems;

bool drawInteractiveList (RConsCanvas* c, int w, int h, DiffListItems* items, int selected_idx) {
    int x = sep / 2;
    int y = sep / 2;
    int list_width = w / 4 - sep;  // Take 1/4 of screen width for list
    h = h - sep;

    if (list_width <= 0 || h <= 0) {
        return false;
    }

    r_cons_canvas_box (c, x, y, list_width, h, Color_RESET);
    r_cons_canvas_write_at (c, "ASSEMBLY VARIATIONS", x + 2, y + 1);
    
    // Show selection counter
    char selection_info[64];
    snprintf(selection_info, sizeof(selection_info), "(%d/%d)", selected_idx + 1, (int)items->length);
    r_cons_canvas_write_at (c, selection_info, x + list_width - strlen(selection_info) - 2, y + 1);

    int line_y = y + 3;
    int max_lines = h - 5;
    int content_width = list_width - 4;

    if(content_width <= 0 || max_lines <= 0) {
        return false;
    }

    VecForeachIdx (items, item, idx, {
        if ((int)idx >= max_lines) break;

        Str line_str = StrInit();
        
        // Highlight selected item
        if ((int)idx == selected_idx) {
            StrPrintf(&line_str, "> %.*s", (int)MIN2(item.name.length, (u64)content_width - 2), item.name.data);
        } else {
            StrPrintf(&line_str, "  %.*s", (int)MIN2(item.name.length, (u64)content_width - 2), item.name.data);
        }

        r_cons_canvas_write_at (c, line_str.data, x + 1, line_y + (int)idx);
        StrDeinit(&line_str);
    });

    return true;
}

bool drawInteractiveSourceDiff (RConsCanvas* c, int w, int h, DiffLines* diff) {
    int x = w / 4 + sep / 2;  // Start after the list
    int y = sep / 2;
    int diff_width = (w * 3 / 4) / 2 - sep;  // Half of remaining space
    h = h - sep;

    if (diff_width <= 0 || h <= 0) {
        return false;
    }

    r_cons_canvas_box (c, x, y, diff_width, h, Color_RESET);
    r_cons_canvas_write_at (c, "SOURCE", x + 2, y + 1);

    int line_y = y + 3;
    int max_lines = h - 5;
    int current_line = 0;
    int content_width = diff_width - 8;

    if(content_width <= 0 || max_lines <= 0) {
        return false;
    }

    VecForeachPtr (diff, diff_line, {
        if (current_line >= max_lines) break;

        Str line_str = StrInit();

        switch (diff_line->type) {
            case DIFF_TYPE_SAM: {
                int content_len = MIN2(diff_line->sam.content.length, (u64)content_width);
                StrPrintf(&line_str, "%3llu %.*s", diff_line->sam.line + 1, content_len, diff_line->sam.content.data);
                break;
            }
            case DIFF_TYPE_REM: {
                int content_len = MIN2(diff_line->rem.content.length, (u64)content_width);
                StrPrintf(&line_str, "%3llu %.*s", diff_line->rem.line + 1, content_len, diff_line->rem.content.data);
                break;
            }
            case DIFF_TYPE_MOD: {
                int content_len = MIN2(diff_line->mod.old_content.length, (u64)content_width);
                StrPrintf(&line_str, "%3llu %.*s", diff_line->mod.old_line + 1, content_len, diff_line->mod.old_content.data);
                break;
            }
            case DIFF_TYPE_MOV: {
                int content_len = MIN2(diff_line->mov.old_content.length, (u64)content_width);
                StrPrintf(&line_str, "%3llu %.*s", diff_line->mov.old_line + 1, content_len, diff_line->mov.old_content.data);
                break;
            }
            case DIFF_TYPE_ADD: {
                StrPrintf(&line_str, "    ");
                break;
            }
            default:
                StrDeinit(&line_str);
                continue;
        }

        r_cons_canvas_write_at (c, line_str.data, x + 1, line_y + current_line);
        StrDeinit(&line_str);
        current_line++;
    });

    return true;
}

bool drawInteractiveTargetDiff (RConsCanvas* c, int w, int h, DiffLines* diff) {
    int x = w / 4 + (w * 3 / 4) / 2 + sep / 2;  // Start at last quarter
    int y = sep / 2;
    int diff_width = (w * 3 / 4) / 2 - sep;
    h = h - sep;

    if (diff_width <= 0 || h <= 0) {
        return false;
    }

    r_cons_canvas_box (c, x, y, diff_width, h, Color_RESET);
    r_cons_canvas_write_at (c, "TARGET", x + 2, y + 1);

    int line_y = y + 3;
    int max_lines = h - 5;
    int current_line = 0;
    int content_width = diff_width - 8;

    if(content_width <= 0 || max_lines <= 0) {
        return false;
    }

    VecForeachPtr (diff, diff_line, {
        if (current_line >= max_lines) break;

        Str line_str = StrInit();

        switch (diff_line->type) {
            case DIFF_TYPE_SAM: {
                int content_len = MIN2(diff_line->sam.content.length, (u64)content_width);
                StrPrintf(&line_str, "%3llu %.*s", diff_line->sam.line + 1, content_len, diff_line->sam.content.data);
                break;
            }
            case DIFF_TYPE_ADD: {
                int content_len = MIN2(diff_line->add.content.length, (u64)content_width);
                StrPrintf(&line_str, "%3llu %.*s", diff_line->add.line + 1, content_len, diff_line->add.content.data);
                break;
            }
            case DIFF_TYPE_MOD: {
                int content_len = MIN2(diff_line->mod.new_content.length, (u64)content_width);
                StrPrintf(&line_str, "%3llu %.*s", diff_line->mod.new_line + 1, content_len, diff_line->mod.new_content.data);
                break;
            }
            case DIFF_TYPE_MOV: {
                int content_len = MIN2(diff_line->mov.new_content.length, (u64)content_width);
                StrPrintf(&line_str, "%3llu %.*s", diff_line->mov.new_line + 1, content_len, diff_line->mov.new_content.data);
                break;
            }
            case DIFF_TYPE_REM: {
                StrPrintf(&line_str, "    ");
                break;
            }
            default:
                StrDeinit(&line_str);
                continue;
        }

        r_cons_canvas_write_at (c, line_str.data, x + 1, line_y + current_line);
        StrDeinit(&line_str);
        current_line++;
    });
    
    return true;
}

RConsCanvas* drawInteractiveDiff (RConsCanvas* c, DiffListItems* items, int selected_idx, DiffLines* diff) {
    // get terminal size
    int h, w = r_cons_get_size (&h);

    // if canvas is not created then create
    if (c == NULL) {
        c = r_cons_canvas_new (w, h);
    }

    // resize canvas on windows resize
    if (c->w != w || c->h != h) {
        r_cons_canvas_resize (c, w, h);
    }

    // create canvas
    r_cons_canvas_clear (c);
    
    if(!drawInteractiveList (c, w, h, items, selected_idx)) {
        return NULL;
    }
    if(!drawInteractiveSourceDiff (c, w, h, diff)) {
        return NULL;
    }
    if(!drawInteractiveTargetDiff (c, w, h, diff)) {
        return NULL;
    }
    
    r_cons_canvas_print (c);
    r_cons_flush();

    return c;
}

void DiffListItemDeinit(DiffListItem* item) {
    StrDeinit(&item->name);
    StrDeinit(&item->target_content);
}

R_IPI RCmdStatus r_function_assembly_diff_handler (RCore* core, int argc, const char** argv) {
    (void)core;  // Suppress unused parameter warning
    (void)argc;  // Suppress unused parameter warning  
    (void)argv;  // Suppress unused parameter warning
    
    // Create source string - this stays constant
    Str src = StrInitFromZstr("push ebp\nmov ebp, esp\nsub esp, 16\nmov dword [ebp-4], edi\nmov dword [ebp-8], esi\ncall printf\nadd esp, 16\npop ebp\nret");
    
    // Create list of diff options with corresponding target strings
    DiffListItems items = VecInit();
    
    // Option 1: Function optimization
    DiffListItem item1 = {0};
    item1.name = StrInitFromZstr("Optimized Version");
    item1.target_content = StrInitFromZstr("push ebp\nmov ebp, esp\nsub esp, 8\nmov dword [ebp-4], edi\ncall printf\nadd esp, 8\npop ebp\nret");
    VecPushBack(&items, item1);
    
    // Option 2: Different calling convention
    DiffListItem item2 = {0};
    item2.name = StrInitFromZstr("Different Calling Convention");
    item2.target_content = StrInitFromZstr("push ebp\nmov ebp, esp\npush edi\npush esi\ncall printf\npop esi\npop edi\npop ebp\nret");
    VecPushBack(&items, item2);
    
    // Option 3: Debug version with extra checks
    DiffListItem item3 = {0};
    item3.name = StrInitFromZstr("Debug Version");
    item3.target_content = StrInitFromZstr("push ebp\nmov ebp, esp\nsub esp, 16\ntest edi, edi\njz error_exit\nmov dword [ebp-4], edi\nmov dword [ebp-8], esi\ncall printf\nadd esp, 16\npop ebp\nret\nerror_exit:\nmov eax, -1\npop ebp\nret");
    VecPushBack(&items, item3);
    
    // Option 4: Inlined version
    DiffListItem item4 = {0};
    item4.name = StrInitFromZstr("Inlined Printf");
    item4.target_content = StrInitFromZstr("push ebp\nmov ebp, esp\nsub esp, 16\nmov dword [ebp-4], edi\nmov dword [ebp-8], esi\npush esi\npush edi\npush format_str\ncall _write\nadd esp, 12\nadd esp, 16\npop ebp\nret");
    VecPushBack(&items, item4);
    
    // Option 5: Completely different function
    DiffListItem item5 = {0};
    item5.name = StrInitFromZstr("Scanner Function");
    item5.target_content = StrInitFromZstr("push ebp\nmov ebp, esp\nsub esp, 4\ncall scanf\ntest eax, eax\njz scan_error\nmov eax, dword [ebp-4]\nadd esp, 4\npop ebp\nret\nscan_error:\nmov eax, 0\nadd esp, 4\npop ebp\nret");
    VecPushBack(&items, item5);
    
    // Option 6: ARM assembly equivalent 
    DiffListItem item6 = {0};
    item6.name = StrInitFromZstr("ARM Assembly");
    item6.target_content = StrInitFromZstr("push {fp, lr}\nadd fp, sp, #4\nsub sp, sp, #8\nstr r0, [fp, #-8]\nstr r1, [fp, #-12]\nbl printf\nsub sp, fp, #4\npop {fp, pc}");
    VecPushBack(&items, item6);
    
    // Option 7: RISC-V assembly
    DiffListItem item7 = {0};
    item7.name = StrInitFromZstr("RISC-V Assembly");
    item7.target_content = StrInitFromZstr("addi sp, sp, -16\nsd ra, 8(sp)\nsd s0, 0(sp)\naddi s0, sp, 16\nmv a0, a0\ncall printf\nld ra, 8(sp)\nld s0, 0(sp)\naddi sp, sp, 16\nret");
    VecPushBack(&items, item7);
    
    // Option 8: Minimal version
    DiffListItem item8 = {0};
    item8.name = StrInitFromZstr("Minimal Version");
    item8.target_content = StrInitFromZstr("call printf\nret");
    VecPushBack(&items, item8);
    
    int selected_idx = 0;  // Start with first item selected
    
    // Generate initial diff
    DiffListItem* current_item = VecPtrAt(&items, selected_idx);
    DiffLines diff = GetDiff(&src, &current_item->target_content);
    
    RConsCanvas* c = drawInteractiveDiff(NULL, &items, selected_idx, &diff);
    
    // Lazy help canvas - created once, reused multiple times
    static RConsCanvas* help_canvas = NULL;
    
    // Interactive loop
    r_cons_println("Interactive Assembly Diff Viewer");
    r_cons_println("Controls: k = Up, j = Down, q = Quit");
    r_cons_println("Use k/j keys to navigate the list and see different assembly variations");
    r_cons_flush();
    r_sys_sleep(2); // Show instructions for 2 seconds
    
    int ch = 0;  // Start with no input
    while (true) {
        // Only process and re-render when we have actual input
        if (ch != 0) {
            bool need_redraw = false;
            bool need_new_diff = false;
            
            switch (ch) {
                case 'q':
                case 'Q':
                case 27:   // ESC key
                    goto cleanup;
                    
                case 'k':  // Up
                    if (selected_idx > 0) {
                        selected_idx--;
                        need_redraw = true;
                        need_new_diff = true;
                    }
                    break;
                    
                case 'j':  // Down
                    if (selected_idx < (int)items.length - 1) {
                        selected_idx++;
                        need_redraw = true;
                        need_new_diff = true;
                    }
                    break;
                    
                case 'h':  // Help
                case '?':
                    {
                        // Get current terminal size
                        int help_h, help_w = r_cons_get_size(&help_h);
                        
                        // Lazy initialization - create help canvas only once
                        if (!help_canvas) {
                            help_canvas = r_cons_canvas_new(help_w, help_h);
                            
                            // Calculate center position for help box
                            int box_width = 60;
                            int box_height = 16;
                            int box_x = (help_w - box_width) / 2;
                            int box_y = (help_h - box_height) / 2;
                            
                            r_cons_canvas_clear(help_canvas);
                            
                            // Draw the help box (only once)
                            r_cons_canvas_box(help_canvas, box_x, box_y, box_width, box_height, Color_RESET);
                            
                            // Write help content (only once)
                            r_cons_canvas_write_at(help_canvas, "Interactive Assembly Diff Viewer - Help", box_x + 2, box_y + 1);
                            r_cons_canvas_write_at(help_canvas, "========================================", box_x + 2, box_y + 2);
                            
                            r_cons_canvas_write_at(help_canvas, "Navigation Controls:", box_x + 2, box_y + 4);
                            r_cons_canvas_write_at(help_canvas, "  k       : Move selection up", box_x + 4, box_y + 5);
                            r_cons_canvas_write_at(help_canvas, "  j       : Move selection down", box_x + 4, box_y + 6);
                            r_cons_canvas_write_at(help_canvas, "  q / ESC : Quit viewer", box_x + 4, box_y + 7);
                            r_cons_canvas_write_at(help_canvas, "  h / ?   : Show this help", box_x + 4, box_y + 8);
                            
                            r_cons_canvas_write_at(help_canvas, "Usage:", box_x + 2, box_y + 10);
                            r_cons_canvas_write_at(help_canvas, "• Left panel shows assembly variations", box_x + 4, box_y + 11);
                            r_cons_canvas_write_at(help_canvas, "• Right panels show source vs target diff", box_x + 4, box_y + 12);
                            r_cons_canvas_write_at(help_canvas, "• Use k/j to navigate and compare", box_x + 4, box_y + 13);
                            
                            r_cons_canvas_write_at(help_canvas, "Press any key to continue...", box_x + (box_width - 28) / 2, box_y + box_height - 2);
                        } else {
                            // Handle window resize - recreate canvas if size changed
                            if (help_canvas->w != help_w || help_canvas->h != help_h) {
                                r_cons_canvas_resize(help_canvas, help_w, help_h);
                                // Note: Content remains the same, just canvas size adjusted
                            }
                        }
                        
                        r_cons_canvas_print(help_canvas);
                        r_cons_flush();
                        r_cons_readchar();
                        need_redraw = true;
                    }
                    break;
                    
                default:
                    // Ignore unknown keys - no action needed
                    break;
            }
            
            if (need_new_diff) {
                // Clean up old diff
                VecDeinit(&diff);
                
                // Generate new diff with selected item
                current_item = VecPtrAt(&items, selected_idx);
                diff = GetDiff(&src, &current_item->target_content);
            }
            
            if (need_redraw) {
                if(!drawInteractiveDiff(c, &items, selected_idx, &diff)) {
                    r_cons_canvas_free(c);
                    c = NULL;
                    break;
                }
            }
        }
        
        // Wait for actual user input (blocking)
        ch = r_cons_readchar();
    }
    
cleanup:
    // Cleanup
    if(c) {
        r_cons_canvas_free(c);
    }
    
    // Lazy cleanup - free help canvas only at exit
    if(help_canvas) {
        r_cons_canvas_free(help_canvas);
        help_canvas = NULL;
    }
    
    VecDeinit(&diff);
    StrDeinit(&src);
    
    // Clean up list items
    VecForeachPtr(&items, item, {
        DiffListItemDeinit(item);
    });
    VecDeinit(&items);
    
    return R_CMD_STATUS_OK;
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
