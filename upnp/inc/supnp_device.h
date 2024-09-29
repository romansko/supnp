/*!
* \addtogroup SUPnP
 *
 * \file supnp_device.h
 *
 * \brief Header file for SUPnP device logics.
 *
 * \author Roman Koifman
 */
#ifndef SUPNP_DEVICE_H
#define SUPNP_DEVICE_H

#include "UpnpGlobal.h" /* for UPNP_EXPORT_SPEC */
#include "upnpconfig.h"
#include <stddef.h>

#if ENABLE_SUPNP

/* Forward decleration */
typedef struct x509_st X509;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct cJSON cJSON;
typedef struct _IXML_Document IXML_Document;

#ifdef __cplusplus
extern "C" {
#endif

/* Simulate boolean */
#define SUPNP_DEV_OK  (1)
#define SUPNP_DEV_ERR (0)

typedef enum EDeviceType
{
    DEVICE_TYPE_SD = 0x5D,
    DEVICE_TYPE_CP = 0xC9
} EDeviceType;

typedef struct _supnp_device_t
{
    char* id;                  /* Device ID */
    EDeviceType type;
    EVP_PKEY *pk;              /* Public Key */
    EVP_PKEY *sk;              /* Private Key */
    X509 *dev_cert;            /* Device Certificate issued by UCA */
    X509 *uca_cert;            /* UCA Certificate */
    char *desc_uri;            /* Device Description URI - SD Only */
    IXML_Document *desc_doc;   /* Device Description Document - SD Only  */
    cJSON *supnp_doc;
    char *cap_token_uri;
    struct _supnp_device_t *next;
    struct _supnp_device_t *prev;
} supnp_device_t;

UPNP_EXPORT_SPEC supnp_device_t* new_supnp_device(const char* spec_doc, const char* cert, const char* uca_cert);

UPNP_EXPORT_SPEC const char* supnp_device_type_str(EDeviceType type);

UPNP_EXPORT_SPEC void supnp_free_device_content(supnp_device_t* p_dev);

UPNP_EXPORT_SPEC void supnp_free_device(supnp_device_t** pp_dev);

UPNP_EXPORT_SPEC void add_list_device(supnp_device_t** head, supnp_device_t *p_dev);

UPNP_EXPORT_SPEC void remove_list_device(supnp_device_t** head, supnp_device_t *p_dev);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */

#endif /* SUPNP_DEVICE_H */
