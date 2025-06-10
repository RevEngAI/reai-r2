/**
 * @file : Plugin.h
 * @date : 4th Dec 2024
 * @author : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright: Copyright (c) 2024 RevEngAI. All Rights Reserved.
 *
 * @b Global plugin state management. This defines a singleton class
 * that needs to be accessed using the get method only.
 * */

#ifndef REAI_RADARE_PLUGIN
#define REAI_RADARE_PLUGIN


/* libc */
#include <stdio.h>

/* revenai */
#include <Reai/Api.h>
#include <Reai/Config.h>
#include <Reai/Log.h>

/* radare */
#include <r_bin.h>
#include <r_core.h>

#ifdef __cplusplus
extern "C" {
#endif


    ///
    /// Reinit plugin by deiniting current internal state and reloading config
    ///
    void ReloadPluginData();

    ///
    /// Get loaded config.
    /// Don't ever deinit returned `Config`.
    ///
    /// SUCCESS : Valid `Config` pointer.
    /// FAILURE : `NULL`
    ///
    Config* GetConfig();

    ///
    /// Get connection information used by this plugin.
    /// Don't ever deinit anything inside returned object.
    ///
    /// SUCCESS : Connection object filled with valid data.
    /// FAILURE : Empty object.
    ///
    Connection* GetConnection();

    ///
    /// Get current binary ID (if any set).
    ///
    /// SUCCESS : A non-zero binary if it's set by user, 0 otherwise.
    /// FAILURE : 0.
    ///
    BinaryId GetBinaryId();
    void     SetBinaryId (BinaryId binary_id);

    ///
    /// Get all available AI models.
    ///
    /// SUCCESS : Vector of ModelInfo objects filled with valid data.
    /// FAILURE : Empty vector otherwise.
    ///
    ModelInfos* GetModels();

    ///
    /// Check whether or not we can work with analysis associated with given binary ID.
    ///
    /// binary_id[in] : Binary ID to check for.
    /// display_messages[in] : Whether to display popup messages if analysis is not workable with.
    ///
    /// SUCCESS : `true`/`false` depending on whether we can continue working with analysis.
    /// FAILURE : `false` with log messages
    ///
    bool rCanWorkWithAnalysis (BinaryId binary_id, bool display_messages);

    ///
    /// Apply an existing analysis to currently opened binary.
    ///
    /// p[in]         : RCore
    /// binary_id[in] : Binary ID to fetch analysis for and apply.
    ///
    void rApplyAnalysis (RCore* core, BinaryId binary_id);

    ///
    /// Get similar functions for each function and perform an auto-rename
    /// operation for functions that cross similarity level threshold
    ///
    /// core[in]                     : radare core.
    /// max_results_per_function[in] : Number of results to get per function.
    /// min_confidence[in]           : Minimum similarity threshold to cross before candidacy for a rename.
    /// debug_symbols_only[in]       : Suggests symbols extracted from debug information only.
    ///
    void rAutoRenameFunctions (
        RCore* core,
        size   max_results_per_function,
        u32    min_similarity,
        bool   debug_symbols_only
    );

    ///
    /// Search for function ID corresponding to given radare function.
    ///
    /// p[in]    : Plugin
    /// core[in] : radare core.
    /// fn[in]   : Function to get RevEngAI function ID for.
    ///
    /// SUCCESS : Non-zero function ID.
    /// FAILURE : Zero.
    ///
    FunctionId rLookupFunctionId (RCore* core, RAnalFunction* fn);
    FunctionId rLookupFunctionIdForFunctionWithName (RCore* core, const char* name);
    FunctionId rLookupFunctionIdForFunctionAtAddr (RCore* core, u64 addr);

    ///
    /// Get path to opened binary file.
    /// Deinit returned string after use.
    ///
    /// core[in] : RCore
    ///
    /// SUCCESS : `Str` object containing absolute path of currently opened binary.
    /// FAILURE : Empty `Str` object if no file opened.
    ///
    Str rGetCurrentBinaryPath (RCore* core);

    ///
    /// Get base address of opened binary.
    ///
    /// core[in] : RCore
    ///
    /// SUCCESS : base address if binary file opened (can be 0)
    /// FAILURE : 0
    ///
    u64 rGetCurrentBinaryBaseAddr (RCore* core);

    void rDisplayMsg (LogLevel level, Str* msg);
    void rAppendMsg (LogLevel level, Str* msg);
    void rClearMsg();

#ifdef __cplusplus
}
#endif

#define DISPLAY_MSG(level, ...)                                                                    \
    do {                                                                                           \
        Str msg = StrInit();                                                                       \
        StrPrintf (&msg, __VA_ARGS__);                                                             \
        rDisplayMsg (level, &msg);                                                                 \
        StrDeinit (&msg);                                                                          \
    } while (0)

#define APPEND_MSG(level, ...)                                                                     \
    do {                                                                                           \
        Str msg = StrInit();                                                                       \
        StrPrintf (&msg, __VA_ARGS__);                                                             \
        rAppendMsg (level, &msg);                                                                  \
        StrDeinit (&msg);                                                                          \
    } while (0)

#define DISPLAY_INFO(...)  DISPLAY_MSG (LOG_LEVEL_INFO, __VA_ARGS__)
#define DISPLAY_ERROR(...) DISPLAY_MSG (LOG_LEVEL_ERROR, __VA_ARGS__)
#define DISPLAY_FATAL(...)                                                                         \
    DISPLAY_MSG (LOG_LEVEL_FATAL, __VA_ARGS__);                                                    \
    abort()

#define APPEND_INFO(...)  APPEND_MSG (LOG_LEVEL_INFO, __VA_ARGS__)
#define APPEND_ERROR(...) APPEND_MSG (LOG_LEVEL_ERROR, __VA_ARGS__)
#define APPEND_FATAL(...) APPEND_MSG (LOG_LEVEL_FATAL, __VA_ARGS__)
#endif // REAI_RADARE_PLUGIN
