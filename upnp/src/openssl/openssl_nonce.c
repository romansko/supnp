/*!
 * \addtogroup OpenSSL
 *
 * \file openssl_wrapper.c
 *
 * \brief source file for wrapping OpenSSL logics - required by SUPnP.
 * developed with libssl-dev v3.0
 * https://www.openssl.org/docs/man3.0/index.html
 *
 * \author Roman Koifman
 */
#include "openssl_nonce.h"
#include "openssl_error.h"
#include "upnpconfig.h" /* UPNP_ENABLE_OPEN_SSL */

#include <ithread.h>
#include <openssl/rand.h>  /* RAND_bytes */
#include <string.h>        /* memcpy */

#if UPNP_ENABLE_OPEN_SSL

#ifdef __cplusplus
extern "C" {
#endif

ithread_mutex_t gNonceMutex = PTHREAD_MUTEX_INITIALIZER;
NonceEntry *gNonceList = NULL;

void OpenSslFreeNonceEntry(NonceEntry *entry)
{
    if(entry) {
        w_freeif(entry->nonce, free);
        entry->size = 0;
        entry->next = NULL;
        free(entry);
    }
}

void OpenSslFreeNonceList()
{
    ithread_mutex_lock(&gNonceMutex);
    NonceEntry *itr = gNonceList;
    while (itr != NULL) {
        NonceEntry *next = itr->next;
        OpenSslFreeNonceEntry(itr);
        itr = next;
    }
    gNonceList = NULL;
    ithread_mutex_unlock(&gNonceMutex);
}

unsigned char *OpenSslGenerateNonce(const size_t size)
{
    unsigned char *nonce = NULL;

    // Allocate memory
    nonce = malloc(size);
    w_verify(nonce, cleanup, "Error allocating memory for nonce.\n");

    // Generate random bytes for nonce
    w_verify(RAND_bytes(nonce, size) == OPENSSL_SUCCESS,
        cleanup,
        "Error generating random nonce.\n");
    goto success;

    cleanup:
        w_freeif(nonce, free);

    success:
        return nonce;
}


int OpenSslInsertNonce(const unsigned char *nonce, const size_t size)
{
    ithread_mutex_lock(&gNonceMutex);
    NonceEntry *entry = NULL;
    w_verify((nonce != NULL) && (size > 0), error_handler, "Invalid arguments.\n");
    entry = malloc(sizeof(NonceEntry));
    w_verify(entry, error_handler, "Error allocating memory for nonce entry.\n");
    entry->size = size;
    entry->nonce = malloc(size);
    entry->next = NULL;
    w_verify(entry->nonce, error_handler, "Error allocating memory for nonce.\n");
    memcpy(entry->nonce, nonce, size);

    /* First entry */
    if (gNonceList == NULL) {
        gNonceList = entry;
        ithread_mutex_unlock(&gNonceMutex);
        return OPENSSL_SUCCESS;
    }

    /* Iterate through the list */
    NonceEntry *itr = gNonceList;
    while (itr != NULL) {
        /* Check if the nonce already exists */
        if ((itr->size == size) && (memcmp(itr->nonce, nonce, size) == 0)) {
            goto error_handler;
        }

        /* Insert at the end */
        if (itr->next == NULL) {
            itr->next = entry;
            ithread_mutex_unlock(&gNonceMutex);
            return OPENSSL_SUCCESS;
        }

        /* Keep iterating */
        itr = itr->next;
    }

error_handler:
    OpenSslFreeNonceEntry(entry);
    ithread_mutex_unlock(&gNonceMutex);
    return OPENSSL_FAILURE;
}



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* UPNP_ENABLE_OPEN_SSL */
