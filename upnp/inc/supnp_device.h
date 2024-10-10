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

#include <openssl_wrapper.h>
#include <supnp_captoken.h>

#if ENABLE_SUPNP

/* Forward declaration */
typedef struct x509_st X509;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct cJSON cJSON;
typedef struct _IXML_Document IXML_Document;

#ifdef __cplusplus
extern "C" {
#endif

#define SUPNP_DEV_OK (0)
#define SUPNP_DEV_ERR (-1)

typedef enum _EDeviceType
{
    eDeviceType_SD = 0,
    eDeviceType_CP
} EDeviceType;

static const char *const device_type_str[] = {
    "SD",
    "CP",
};

typedef struct _supnp_device_t
{
    int verified;            /* Device verified */
    char *name;              /* Device Name */
    EDeviceType type;        /* Device Type */
    X509 *dev_cert;          /* Device Certificate issued by UCA */
    X509 *uca_cert;          /* UCA Certificate */
    EVP_PKEY *dev_pkey;      /* Device Public Key */
    EVP_PKEY *uca_pkey;      /* UCA Public Key */
    char *device_url;        /* Device URL */
    char *desc_doc_name;     /* Device Description URI - SD Only */
    IXML_Document *desc_doc; /* Device Description Document - SD Only  */
    cJSON *supnp_doc;
    captoken_t *cap_token;
    char *cap_token_name;
    unsigned char nonce[OPENSSL_CSPRNG_SIZE];
    struct _supnp_device_t *next;
    struct _supnp_device_t *prev;
} supnp_device_t;

UPNP_EXPORT_SPEC supnp_device_t *SupnpNewDevice(
    const char *spec_doc, const char *cert, const char *uca_cert);

UPNP_EXPORT_SPEC const char *SupnpDeviceTypeStr(EDeviceType type);

UPNP_EXPORT_SPEC void SupnpFreeDeviceContent(supnp_device_t *p_dev);

UPNP_EXPORT_SPEC void SupnpFreeDevice(supnp_device_t **pp_dev);

UPNP_EXPORT_SPEC void SupnpAddListDevice(
    supnp_device_t **head, supnp_device_t *p_dev);

UPNP_EXPORT_SPEC void SupnpRemoveListDevice(
    supnp_device_t **head, supnp_device_t *p_dev);

UPNP_EXPORT_SPEC supnp_device_t *SupnpFindDeviceByPublicKey(
    supnp_device_t *head, const EVP_PKEY *pkey);

UPNP_EXPORT_SPEC void SupnpRemoveDevice(
    supnp_device_t **head, supnp_device_t *p_dev);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */

#endif /* SUPNP_DEVICE_H */
