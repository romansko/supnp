/*!
 * \addtogroup OpenSSL
 *
 * \file openssl_nonce.h
 *
 * \brief Header file for wrapping nonce logics - required by SUPnP.
 *
 * \author Roman Koifman
 */
#ifndef OPENSSL_NONCE_H
#define OPENSSL_NONCE_H

#include "UpnpGlobal.h" /* UPNP_EXPORT_SPEC */
#include "upnpconfig.h" /* UPNP_ENABLE_OPEN_SSL */
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#if UPNP_ENABLE_OPEN_SSL

/* Default OpenSSL CSPRNG 256 bits */
#define OPENSSL_CSPRNG_SIZE (32)

typedef struct NonceEntry
{
    unsigned char *nonce;
    size_t size;
    struct NonceEntry *next;
}NonceEntry;

/*!
 * \brief Free a nonce entry.
 */
void OpenSslFreeNonceEntry(
    /*! [IN] nonce entry to free */
    NonceEntry *entry);

/*!
 * \brief Free the global nonce list.
 */
void OpenSslFreeNonceList();

/*!
 * \brief Generate a nonce of a given size.
 *
 * \note Remember to free the returned nonce.
 *
 * \return a nonce on success, NULL on failure.
 */
UPNP_EXPORT_SPEC unsigned char *OpenSslGenerateNonce(
    /*! [IN] size of the requested nonce */
    size_t size);

/*!
 * \brief Insert a nonce into the nonce list. If nonce already exists, return
 * error.
 *
 * \return OPENSSL_SUCCESS on success, OPENSSL_FAILURE on failure.
 */
UPNP_EXPORT_SPEC int OpenSslInsertNonce(
    /*! [IN] nonce to insert */
    const unsigned char *nonce,
    /*! [IN] size of the nonce */
    size_t size);

#endif /* UPNP_ENABLE_OPEN_SSL */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // OPENSSL_NONCE_H
