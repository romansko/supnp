/*!
* \addtogroup SUPnP
 *
 * \file supnp_captoken.h
 *
 * \brief Header file for SUPnP CapToken algorithms.
 *
 * \author Roman Koifman
 */
#ifndef SUPNP_CAPTOKEN_H
#define SUPNP_CAPTOKEN_H

#include "UpnpGlobal.h" /* for UPNP_EXPORT_SPEC */
#include "upnpconfig.h"

#include <stddef.h>

#if ENABLE_SUPNP

typedef struct cJSON captoken_t;

/* Forward decleration */
typedef struct evp_pkey_st EVP_PKEY;
typedef struct cJSON cJSON;
typedef struct _supnp_device_t supnp_device_t;

typedef enum ECapTokenFieldType
{
    eCapTokenID = 0,
    eCapTokenDeviceType,
    eCapTokenIssuerInstant,
    eCapTokenPublicKeyRA,
    eCapTokenPublicKeySD,
    eCapTokenPublicKeyCP,
    eCapTokenSignatureRA,
    eCapTokenSignatureAdvertisement,
    eCapTokenSignatureDescription,
    eCapTokenSignatureLocation,
    eCapTokenServices,

    eCatTokenFieldTypesCount
}ECapTokenFieldType;

#ifdef __cplusplus
extern "C" {
#endif

UPNP_EXPORT_SPEC captoken_t *loadCapTokenString(const char *capTokenStr);

UPNP_EXPORT_SPEC cJSON* stringToJsonString(char *string);

UPNP_EXPORT_SPEC cJSON* bytesToJsonString(unsigned char *bytes, size_t size);

UPNP_EXPORT_SPEC cJSON* getTimestamp();

UPNP_EXPORT_SPEC captoken_t* generateCapToken(const supnp_device_t *dev,
  EVP_PKEY *pkey);

UPNP_EXPORT_SPEC void freeCapToken(captoken_t **cap_token);

UPNP_EXPORT_SPEC char *capTokenToString(const captoken_t *cap_token);

UPNP_EXPORT_SPEC char *capTokenToHexString(const captoken_t *cap_token);

UPNP_EXPORT_SPEC captoken_t *capTokenFromString(const char *cap_token_str);

UPNP_EXPORT_SPEC captoken_t *capTokenFromHexString(const char *hex);

UPNP_EXPORT_SPEC int storeCapToken(const captoken_t *capToken, const char *filepath);

UPNP_EXPORT_SPEC int downloadCapToken(const char *capTokenUrl, captoken_t **ppCapToken);

UPNP_EXPORT_SPEC char *extractCapTokenFieldValue(const captoken_t *cap_token, ECapTokenFieldType type);

UPNP_EXPORT_SPEC char *extractCapTokenFieldValue2(const char *capTokenUrl, ECapTokenFieldType type);

UPNP_EXPORT_SPEC int verifyCapToken(const captoken_t *cap_token, EVP_PKEY *ra_pk, const char *desc_doc_content);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */

#endif /* SUPNP_CAPTOKEN_H */
