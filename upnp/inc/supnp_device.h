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

#include "upnpconfig.h"
#include "UpnpGlobal.h" /* for UPNP_EXPORT_SPEC */
#include "openssl_nonce.h"
#include "openssl_wrapper.h"
#include "supnp_captoken.h"
#include "supnp_common.h"

#if ENABLE_SUPNP

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration */
typedef struct x509_st X509;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct _IXML_Document IXML_Document;

#define SUPNP_DEV_OK (0)
#define SUPNP_DEV_ERR (-1)

typedef enum _EDeviceType
{
    eDeviceType_SD = 0,
    eDeviceType_CP,
    eDeviceType_RA,

    eDeviceTypesCount
} EDeviceType;


typedef struct _supnp_device_t
{
    int verified;           /* Is device verified */
    char *name;             /* Device Name */
    EDeviceType type;       /* Device Type */
    X509 *certDevice;       /* Device Certificate issued by UCA */
    X509 *certUCA;          /* UCA Certificate */
    EVP_PKEY *pkeyDevice;   /* Device Public Key */
    EVP_PKEY *pkeyUCA;      /* UCA Public Key */
    char descDocLocation[LOCATION_SIZE]; /* Device Description URI - SD Only */
    IXML_Document *descDocument; /* Device Description Document - SD Only  */
    struct cJSON *specDocument;
    captoken_t *capToken;
    char capTokenLocation[LOCATION_SIZE];
    unsigned char nonce[OPENSSL_CSPRNG_SIZE];
    struct _supnp_device_t *next;
    struct _supnp_device_t *prev;
} supnp_device_t;


/*!
 * \brief Create a new SUPnP device.
 * To be used by Registration Authority (RA).
 */
UPNP_EXPORT_SPEC supnp_device_t * SupnpNewDevice(
    /*! [IN] Device specification document (DSD) for SD or
     * Service Action Document (SAD) for CP */
    const char *specDocument,
    /*! [IN] Device Certificate */
    const char *certDevice,
    /*! [IN] UCA Certificate */
    const char *certUCA);


/*!
 * \brief retrieve string representation of device type.
 *
 * \return string representation of device type or
 * Empty string if type is invalid.
 */
UPNP_EXPORT_SPEC const char *SupnpDeviceTypeStr(
    /*! [IN] SUPnP Device */
    const supnp_device_t *dev);


/*!
 * \brief Free SUPnP device.
 */
UPNP_EXPORT_SPEC void SupnpFreeDevice(
    /*! [IN] SUPnP Device to free */
    supnp_device_t **p_dev);

/*!
 * \brief Add device to list.
 */
UPNP_EXPORT_SPEC void SupnpAddListDevice(
    /*! [IN] Head of list */
    supnp_device_t **p_head,
    /*! [IN] Device to add */
    supnp_device_t *dev);


/*!
 * \brief Remove device from list. Search by pointers.
 */
UPNP_EXPORT_SPEC void SupnpRemoveListDevice(
    /*! [IN] Head of list */
    supnp_device_t **p_head,
    /*! [IN] Device pointer to remove */
    supnp_device_t *dev);


/*!
 * \brief Find device by its public key which should be unique.
 */
UPNP_EXPORT_SPEC supnp_device_t *SupnpFindDeviceByPublicKey(
    /*! [IN] Head of list */
    supnp_device_t *head,
    /*! [IN] Public key to search for */
    const EVP_PKEY *pkey);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */

#endif /* SUPNP_DEVICE_H */
