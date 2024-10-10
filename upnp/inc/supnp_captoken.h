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

/* Cap Token related */
#define ID_SIZE       11  /* As presented by the paper */
#define SD_TYPE_STR   "SERVICE-DEVICE"
#define CP_TYPE_STR   "CONTROL-POINT"
#define CT_ID         "ID"
#define CT_TIMESTAMP  "ISSUER-INSTANT"
#define RA_PK         "RA-PK"
#define SD_PK         "SD-PK"
#define CP_PK         "CP-PK"
#define RA_SIG        "RA-SIG"
#define CT_TYPE       "TYPE"
#define CT_ADV_SIG    "ADVERTISEMENT-SIG"
#define CT_DESC_SIG   "DESCRIPTION-SIG"
#define CT_SERVICES   "SERVICES"
#define CT_URI_SIG    "LOCATION-SIG"

#ifdef __cplusplus
extern "C" {
#endif

UPNP_EXPORT_SPEC cJSON* stringToJsonString(char *string);

UPNP_EXPORT_SPEC cJSON* bytesToJsonString(unsigned char *bytes, size_t size);

UPNP_EXPORT_SPEC cJSON* getTimestamp();

UPNP_EXPORT_SPEC captoken_t* generateCapToken(const supnp_device_t *dev, EVP_PKEY *sk_ra);

UPNP_EXPORT_SPEC void freeCapToken(captoken_t **cap_token);

UPNP_EXPORT_SPEC char *capTokenToString(const captoken_t *cap_token);

UPNP_EXPORT_SPEC char *capTokenToHexString(const captoken_t *cap_token);

UPNP_EXPORT_SPEC captoken_t *capTokenFromString(const char *cap_token_str);

UPNP_EXPORT_SPEC captoken_t *capTokenFromHexString(const char *hex);

UPNP_EXPORT_SPEC int storeCapToken(const captoken_t *capToken, const char *filepath);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */

#endif /* SUPNP_CAPTOKEN_H */
