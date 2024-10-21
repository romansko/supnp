/*!
 * \addtogroup OpenSSL
 *
 * \file openssl_error.h
 *
 * \brief Header file for OpenSSL Wrapper errors handling.
 *
 * \author Roman Koifman
 */
#ifndef OPENSSL_ERROR_H
#define OPENSSL_ERROR_H

#include "upnpconfig.h"  /* UPNP_ENABLE_OPEN_SSL */
#include <openssl/err.h> /* Open SSL Error string & code */
#include "ithread.h"

#if UPNP_ENABLE_OPEN_SSL

#ifdef __cplusplus
extern "C" {
#endif

#define OPENSSL_SUCCESS (1)

#define OPENSSL_FAILURE (0)

/*!
 * \brief Get the last error from OpenSSL. No free is required.
 * Make sure OpenSslInitializeWrapper() was called before.
 * Function implemented at openssl_wrapper.c
 *
 * \return a string describing the last error.
 */
extern const char *OpenSslGetLastError();

/*!
 * \brief Report an error to stderr.
 */
#define w_error(...) \
{ \
    fprintf(stderr, \
        "[SSL_W Error] [tid %lu] %s::%s(%d): ", \
        ithread_self(), \
        __FILE__, \
        __func__, \
        __LINE__); \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\t%s\n", OpenSslGetLastError()); \
}

/*!
 * \brief Prints to stdout.
 */
#define w_log(...) \
{ \
    fprintf(stdout, "[SSL_W] [tid %lu] %s(%d): ", \
        ithread_self(), \
        __func__, \
        __LINE__); \
    fprintf(stdout, __VA_ARGS__); \
}

/*!
 * \brief Internal verification macro.
 *
 * \param test test to verify.
 * \param label label to jump to if test fails.
 */
#define w_verify(test, label, ...) \
{ \
    if (!(test)) { \
        w_error(__VA_ARGS__); \
        goto label; \
    } \
}

/*!
 * \brief Free a pointer if it is not NULL with a given function.
 *
 * \param ptr pointer to free.
 * \param free_func the freeing function.
 */
#define w_freeif(ptr, free_func) \
{ \
    if (ptr != NULL) { \
        free_func(ptr); \
        ptr = NULL; \
    } \
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* UPNP_ENABLE_OPEN_SSL */

#endif // OPENSSL_ERROR_H
