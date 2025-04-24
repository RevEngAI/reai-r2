/**
 * @file : Override.h
 * @date : 4th Dec 2024
 * @author : Siddharth Mishra (admin@brightprogrammer.in)
 * @copyright: Copyright (c) 2024 RevEngAI. All Rights Reserved.
 *
 * @b Override default macros.
 * */

#ifndef REAI_PLUGIN_OVERRIDE_H
#define REAI_PLUGIN_OVERRIDE_H

#include <r_util/r_log.h>

/**
 * Following macros are defined to make use of "eprintf" instead of
 * fprintf. This or otherwise radare does not allow using stderr for output.
 * */

#ifdef RETURN_VALUE_IF
#    undef RETURN_VALUE_IF
#endif

#ifdef RETURN_IF
#    undef RETURN_IF
#endif

#ifdef GOTO_HANDLER_IF_REACHED
#    undef GOTO_HANDLER_IF_REACHED
#endif

#ifdef GOTO_HANDLER_IF
#    undef GOTO_HANDLER_IF
#endif

#ifdef CALL_HANDLER_IF
#    undef CALL_HANDLER_IF
#endif

#ifdef ABORT_IF
#    undef ABORT_IF
#endif

#ifdef RETURN_VALUE_IF_REACHED
#    undef RETURN_VALUE_IF_REACHED
#endif

#ifdef RETURN_IF_REACHED
#    undef RETURN_IF_REACHED
#endif

#ifdef ABORT_IF_REACHED
#    undef ABORT_IF_REACHED
#endif

#ifdef PRINT_ERR
#    undef PRINT_ERR
#endif


#define RETURN_VALUE_IF(cond, value, ...)                                                          \
    do {                                                                                           \
        if ((cond)) {                                                                              \
            eprintf (__VA_ARGS__);                                                                 \
            eprintf ("\n");                                                                        \
            REAI_LOG_ERROR (__VA_ARGS__);                                                          \
            return value;                                                                          \
        }                                                                                          \
    } while (0)

#define RETURN_IF(cond, ...)                                                                       \
    do {                                                                                           \
        if ((cond)) {                                                                              \
            eprintf (__VA_ARGS__);                                                                 \
            eprintf ("\n");                                                                        \
            REAI_LOG_ERROR (__VA_ARGS__);                                                          \
            return;                                                                                \
        }                                                                                          \
    } while (0)

#define GOTO_HANDLER_IF_REACHED(handler, ...)                                                      \
    do {                                                                                           \
        eprintf (__VA_ARGS__);                                                                     \
        eprintf ("\n");                                                                            \
        REAI_LOG_ERROR (__VA_ARGS__);                                                              \
        goto handler;                                                                              \
    } while (0)
#define GOTO_HANDLER_IF(cond, handler, ...)                                                        \
    do {                                                                                           \
        if ((cond)) {                                                                              \
            eprintf (__VA_ARGS__);                                                                 \
            eprintf ("\n");                                                                        \
            REAI_LOG_ERROR (__VA_ARGS__);                                                          \
            goto handler;                                                                          \
        }                                                                                          \
    } while (0)

#define CALL_HANDLER_IF(cond, handler, ...)                                                        \
    do {                                                                                           \
        if ((cond)) {                                                                              \
            eprintf (__VA_ARGS__);                                                                 \
            eprintf ("\n");                                                                        \
            REAI_LOG_ERROR (__VA_ARGS__);                                                          \
            handler;                                                                               \
        }                                                                                          \
    } while (0)

#define ABORT_IF(cond, ...)                                                                        \
    do {                                                                                           \
        if ((cond)) {                                                                              \
            eprintf (__VA_ARGS__);                                                                 \
            eprintf ("\n");                                                                        \
            REAI_LOG_FATAL (__VA_ARGS__);                                                          \
            abort();                                                                               \
        }                                                                                          \
    } while (0)

#define RETURN_VALUE_IF_REACHED(val, ...)                                                          \
    do {                                                                                           \
        eprintf ("unreachable code reached : ");                                                   \
        eprintf (__VA_ARGS__);                                                                     \
        eprintf ("\n");                                                                            \
        REAI_LOG_ERROR (__VA_ARGS__);                                                              \
        return val;                                                                                \
    } while (0)

#define RETURN_IF_REACHED(...)                                                                     \
    do {                                                                                           \
        eprintf ("unreachable code reached : ");                                                   \
        eprintf (__VA_ARGS__);                                                                     \
        eprintf ("\n");                                                                            \
        REAI_LOG_ERROR (__VA_ARGS__);                                                              \
        return;                                                                                    \
    } while (0)

#define ABORT_IF_REACHED(...)                                                                      \
    do {                                                                                           \
        eprintf ("unreachable code reached : ");                                                   \
        eprintf (__VA_ARGS__);                                                                     \
        eprintf ("\n");                                                                            \
        REAI_LOG_FATAL (__VA_ARGS__);                                                              \
        abort();                                                                                   \
    } while (0)

#define PRINT_ERR(...)                                                                             \
    do {                                                                                           \
        eprintf (__VA_ARGS__);                                                                     \
        eprintf ("\n");                                                                            \
        REAI_LOG_ERROR (__VA_ARGS__);                                                              \
    } while (0)


#endif // REAI_PLUGIN_OVERRIDE_H
