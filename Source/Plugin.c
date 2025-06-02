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
#include <r_util/r_sys.h>


/* revengai */
#include <Reai/Api.h>
#include <Reai/Config.h>
#include <Reai/Log.h>
#include <Reai/Types.h>

/* plugin includes */
#include <Plugin.h>
#include <stdlib.h>

typedef struct Plugin {
    Config     config;
    Connection connection;
    BinaryId   binary_id;
    ModelInfos models;
} Plugin;

void pluginDeinit (Plugin *p) {
    if (!p) {
        LOG_FATAL ("Invalid argument");
    }

    StrDeinit (&p->connection.api_key);
    StrDeinit (&p->connection.host);
    ConfigDeinit (&p->config);
    VecDeinit (&p->models);
    memset (p, 0, sizeof (Plugin));
}

Plugin *getPlugin (bool reinit) {
    static Plugin p;
    static bool   is_inited = false;

    if (reinit) {
        if (!is_inited) {
            p.config             = ConfigInit();
            p.connection.host    = StrInit();
            p.connection.api_key = StrInit();
            p.binary_id          = 0;
            p.models             = VecInitWithDeepCopy_T (&p.models, NULL, ModelInfoDeinit);
        }
        pluginDeinit (&p);
        is_inited = false;
    }

    if (is_inited) {
        return &p;
    } else {
        p.config             = ConfigInit();
        p.connection.host    = StrInit();
        p.connection.api_key = StrInit();
        p.binary_id          = 0;
        p.models             = VecInitWithDeepCopy_T (&p.models, NULL, ModelInfoDeinit);

        // Load config
        p.config = ConfigRead (NULL);
        if (!p.config.length) {
            DISPLAY_ERROR ("Failed to load config. Plugin is in unusable state");
            pluginDeinit (&p);
            return NULL;
        }

        // Get connection parameters
        Str *host    = ConfigGet (&p.config, "host");
        Str *api_key = ConfigGet (&p.config, "api_key");
        if (!host || !api_key) {
            DISPLAY_ERROR ("Config does not specify 'host' and 'api_key' required entries.");
            pluginDeinit (&p);
            return NULL;
        }
        p.connection.api_key = StrInitFromStr (api_key);
       p.connection.host    = StrInitFromStr (host);

        // Get AI models, this way we also perform an implicit auth-check
        p.models = GetAiModelInfos (&p.connection);
        if (!p.models.length) {
            DISPLAY_ERROR ("Failed to get AI models. Please check host and API key in config.");
            pluginDeinit (&p);
            return NULL;
        }

        is_inited = true;
        return &p;
    }
}

void ReloadPluginData() {
    getPlugin (true);
}

Config *GetConfig() {
    if (getPlugin (false)) {
        return &getPlugin (false)->config;
    } else {
        return NULL;
    }
}

Connection *GetConnection() {
    if (getPlugin (false)) {
        return &getPlugin (false)->connection;
    } else {
        static Connection empty_conn = {0};
        return &empty_conn;
    }
}

BinaryId GetBinaryId() {
    if (getPlugin (false)) {
        return getPlugin (false)->binary_id;
    } else {
        return 0;
    }
}

void SetBinaryId (BinaryId binary_id) {
    if (getPlugin (false)) {
        getPlugin (false)->binary_id = binary_id;
    }
}

ModelInfos *GetModels() {
    if (getPlugin (false)) {
        return &getPlugin (false)->models;
    } else {
        static ModelInfos empty_models_vec =
            VecInitWithDeepCopy (ModelInfoInitClone, ModelInfoDeinit);
        return &empty_models_vec;
    }
}

AnnSymbol *getMostSimilarFunctionSymbol (AnnSymbols *symbols, FunctionId origin_fn_id) {
    if (!symbols) {
        LOG_FATAL ("Function matches are invalid. Cannot proceed.");
    }

    if (!origin_fn_id) {
        LOG_FATAL ("Origin function ID is invalid. Cannot proceed.");
    }

    AnnSymbol *most_similar_fn = NULL;
    VecForeachPtr (symbols, fn, {
        if (fn->source_function_id == origin_fn_id &&
            (!most_similar_fn || (fn->distance < most_similar_fn->distance))) {
            most_similar_fn = fn;
        }
    });

    return most_similar_fn;
}

FunctionInfos getFunctionBoundaries (RCore *core) {
    if (!core) {
        DISPLAY_FATAL ("Invalid argument: Invalid radare2 core provided.");
    }

    // We send addresses in "base + offset" and get back in "offset" only

    RList *fns = core->anal->fcns;

    FunctionInfos fv = VecInitWithDeepCopy (NULL, FunctionInfoDeinit);

    RListIter     *fn_iter = NULL;
    RAnalFunction *fn      = NULL;
    r_list_foreach (fns, fn_iter, fn) {
        FunctionInfo fi = {
            .symbol = (SymbolInfo) {.name        = StrInitFromZstr (fn->name),
                                    .is_external = false,
                                    .is_addr     = true,
                                    .value       = {.addr = fn->addr}},
            .size   = r_anal_function_linear_size (fn)
        };
        VecPushBack (&fv, fi);
    }

    return fv;
}

void rApplyAnalysis (RCore *core, BinaryId binary_id) {
    rClearMsg();
    if (!core || !binary_id) {
        LOG_FATAL ("Invalid arguments: invalid Radare2 core or binary id.");
    }

    if (rCanWorkWithAnalysis (binary_id, true)) {
        FunctionInfos functions = GetBasicFunctionInfoUsingBinaryId (GetConnection(), binary_id);
        if (!functions.length) {
            DISPLAY_ERROR ("Failed to get functions from RevEngAI analysis.");
            return;
        }

        u64  base_addr = rGetCurrentBinaryBaseAddr (core);
        bool failed    = false;
        VecForeachPtr (&functions, function, {
            u64            addr = function->symbol.value.addr + base_addr;
            RAnalFunction *fn   = r_anal_get_function_at (core->anal, addr);
            if (!fn) {
                LOG_ERROR ("No Radare2 function exists at address '0x%08llx'", addr);
                failed = true;
                continue;
            }
            r_anal_function_rename(fn, function->symbol.name.data);
        });

        SetBinaryId (binary_id);

        if (!failed) {
            DISPLAY_INFO ("All functions renamed successfully");
        } else {
            DISPLAY_INFO (
                "Analyses applied, but some rename operations failed. Check logs.\n"
                "Check renamed functions by `afl` command."
            );
        }

        VecDeinit (&functions);
    }
}

FunctionId radare2FunctionToId (FunctionInfos *functions, RAnalFunction *fn, u64 base_addr) {
    VecForeach (functions, function, {
        if (function.symbol.value.addr + base_addr == fn->addr) {
            return function.id;
        }
    });

    return 0;
}

void rAutoRenameFunctions (
    RCore *core,
    size   max_results_per_function,
    u32    min_similarity,
    bool   debug_symbols_only
) {
    rClearMsg();
    if (GetBinaryId() && rCanWorkWithAnalysis (GetBinaryId(), true)) {
        BatchAnnSymbolRequest batch_ann = BatchAnnSymbolRequestInit();

        batch_ann.debug_symbols_only = debug_symbols_only;
        batch_ann.limit              = max_results_per_function;
        batch_ann.distance           = 1. - (min_similarity / 100.);
        batch_ann.analysis_id        = AnalysisIdFromBinaryId (GetConnection(), GetBinaryId());
        if (!batch_ann.analysis_id) {
            DISPLAY_ERROR ("Failed to convert binary id to analysis id.");
            return;
        }

        AnnSymbols map = GetBatchAnnSymbols (GetConnection(), &batch_ann);
        BatchAnnSymbolRequestDeinit (&batch_ann);
        if (!map.length) {
            DISPLAY_ERROR ("Failed to get similarity matches.");
            return;
        }

        u64           base_addr = rGetCurrentBinaryBaseAddr (core);
        FunctionInfos functions =
            GetBasicFunctionInfoUsingBinaryId (GetConnection(), GetBinaryId());

        RListIter     *it = NULL;
        RAnalFunction *fn = NULL;
        r_list_foreach (core->anal->fcns, it, fn) {
            FunctionId id = radare2FunctionToId (&functions, fn, base_addr);
            if (!id) {
                LOG_ERROR (
                    "Failed to get a function ID for function with name = '%s' at address = 0x%llx",
                    fn->name,
                    (u64)fn->addr
                );
                continue;
            }

            AnnSymbol *best_match = getMostSimilarFunctionSymbol (&map, id);
            if (best_match) {
                LOG_INFO ("Renamed '%s' to '%s'", fn->name, best_match->function_name.data);
                r_anal_function_rename(fn, best_match->function_name.data);
            }
        }

        VecDeinit (&functions);
        VecDeinit (&map);
    } else {
        DISPLAY_ERROR (
            "Please apply an existing and complete analysis or\n"
            "       create a new one and wait for it's completion."
        );
    }

    // TODO: upload renamed functions name to reveng.ai as well
}

bool rCanWorkWithAnalysis (BinaryId binary_id, bool display_messages) {
    if (!binary_id) {
        APPEND_ERROR ("Invalid arguments: Invalid binary ID");
        return false;
    }

    Status status = GetAnalysisStatus (GetConnection(), binary_id);
    if (!display_messages) {
        return ((status & STATUS_MASK) == STATUS_COMPLETE);
    } else {
        switch (status & STATUS_MASK) {
            case STATUS_ERROR : {
                DISPLAY_ERROR (
                    "The RevEngAI analysis has errored out.\n"
                    "I need a complete analysis. Please restart analysis."
                );
                return false;
            }
            case STATUS_QUEUED : {
                DISPLAY_ERROR (
                    "The RevEngAI analysis is currently in queue.\n"
                    "Please wait for the analysis to be analyzed."
                );
                return false;
            }
            case STATUS_PROCESSING : {
                DISPLAY_ERROR (
                    "The RevEngAI analysis is currently being processed (analyzed).\n"
                    "Please wait for the analysis to complete."
                );
                return false;
            }
            case STATUS_COMPLETE : {
                LOG_INFO ("Analysis for binary ID %llu is COMPLETE.", binary_id);
                return true;
            }
            default : {
                DISPLAY_ERROR (
                    "Oops... something bad happened :-(\n"
                    "I got an invalid value for RevEngAI analysis status.\n"
                    "Consider\n"
                    "\t- checking the binary ID, reapply the correct one if wrong\n"
                    "\t- retrying the command\n"
                    "\t- restarting the plugin\n"
                    "\t- checking logs in $TMPDIR or $TMP or $PWD (reai_<pid>)\n"
                    "\t- checking the connection with RevEngAI host.\n"
                    "\t- contacting support if the issue persists\n"
                );
                return false;
            }
        }
    }
}

FunctionId rLookupFunctionId (RCore *core, RAnalFunction *r_fn) {
    if (!core || !r_fn || !r_fn->name) {
        DISPLAY_FATAL ("Invalid arguments: Invalid Radare2 core or analysis function.");
    }

    if (!GetBinaryId()) {
        APPEND_ERROR (
            "Please create a new analysis or apply an existing analysis. "
            "I need an existing analysis to get function information."
        );
        return 0;
    }

    FunctionInfos functions = GetBasicFunctionInfoUsingBinaryId (GetConnection(), GetBinaryId());
    if (!functions.length) {
        APPEND_ERROR (
            "Failed to get function info list for opened binary file from RevEng.AI servers."
        );
        return 0;
    }

    u64 base_addr = rGetCurrentBinaryBaseAddr (core);

    FunctionId id = 0;
    VecForeachPtr (&functions, fn, {
        if (r_fn->addr == fn->symbol.value.addr + base_addr) {
            LOG_INFO (
                "Radare2Function -> [FunctionName, FunctionID] :: \"%s\" -> [\"%s\", %llu]",
                r_fn->name,
                fn->symbol.name.data,
                fn->id
            );
            id = fn->id;
            break;
        }
    });

    VecDeinit (&functions);

    if (!id) {
        APPEND_ERROR ("Function ID not found\"%s\"", r_fn->name);
    }

    return id;
}

FunctionId rLookupFunctionIdForFunctionWithName (RCore *core, const char *name) {
    if (!core || !name) {
        LOG_FATAL ("Invalid arguments: invalid Radare2 core or function name");
    }

    RAnalFunction *rfn = r_anal_get_function_byname (core->anal, name);
    if (!rfn) {
        APPEND_ERROR ("A function with given name '%s' does not exist in Radare2.\n", name);
        return 0;
    }

    return rLookupFunctionId (core, rfn);
}

FunctionId rLookupFunctionIdForFunctionAtAddr (RCore *core, u64 addr) {
    if (!core || !addr) {
        LOG_FATAL ("Invalid arguments: invalid Radare2 core or function name");
    }

    RAnalFunction *rfn = r_anal_get_function_at (core->anal, addr);
    if (!rfn) {
        APPEND_ERROR ("A function at given address '%llx' does not exist in Radare2.\n", addr);
        return 0;
    }

    return rLookupFunctionId (core, rfn);
}

RBin *getCurrentBinary (RCore *core) {
    if (!core) {
        LOG_FATAL ("Invalid argument: Invalid radare2 core provided.");
    }

    if (!core->bin) {
        APPEND_ERROR (
            "Seems like no binary file is opened yet. Binary container object is invalid. Cannot "
            "get opened binary file."
        );
        return NULL;
    }

    return core->bin;
}

Str rGetCurrentBinaryPath (RCore *core) {
    if (!core) {
        LOG_FATAL ("Invalid arguments: Invalid Radare2 core provided.");
    }
    RBin *binfile = getCurrentBinary (core);
    return binfile ? StrInitFromZstr (r_file_abspath(binfile->file)) : (Str) {0};
}

u64 rGetCurrentBinaryBaseAddr (RCore *core) {
    if (!core) {
        LOG_FATAL ("Invalid arguments: Invalid Radare2 core provided.");
    }

    RBin *binfile = getCurrentBinary (core);
    return binfile ? r_bin_get_baddr(binfile) : 0;
}
