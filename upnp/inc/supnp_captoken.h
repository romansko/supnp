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

#include "upnpconfig.h"
#include "UpnpGlobal.h" /* for UPNP_EXPORT_SPEC */

#if ENABLE_SUPNP

#ifdef __cplusplus
extern "C" {
#endif


/* Forward declaration */
typedef struct evp_pkey_st EVP_PKEY;
typedef struct _supnp_device_t supnp_device_t;
typedef struct cJSON captoken_t;

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


/*!
 * \brief Generate a CapToken for a Device which consists of:
 *   ID               - Random Token ID
 *   ISSUER_INSTANT   - Current time
 *   RA_PK            - RA Public Key
 *   SD_PK | CP_PK    - Device Public Key
 *   RA_SIG           - RA Signature on Cap Token's content
 *   TYPE             - "SERVICE-DEVICE" or "CONTROL-POINT"
 *   ADV_SIG          - RA Signature for (description uri || cap token uri).
 *   SERVICES         - List of service types and corresponding signature by RA
 *                      on their ID. Note: This differs from the paper,
 *                      where the signature is on the description.
 *
 * \note The caller is responsible for freeing the returned CapToken with
 *       SUpnpFreeCapToken().
 *
 * \return CapToken for the device.
 */
UPNP_EXPORT_SPEC captoken_t* SUpnpGenerateCapToken(
    /*! [IN] Device for which CapToken is generated. */
    const supnp_device_t *dev,
    /*! [IN] RA Public Key. */
    EVP_PKEY *pkeyRA);


/*!
 * \brief Free a CapToken.
 */
UPNP_EXPORT_SPEC void SUpnpFreeCapToken(
    /*! [IN] CapToken to free. */
    captoken_t **p_capToken);


/*!
 * \brief Convert CapToken to string representation.
 *
 * \note The caller is responsible for freeing the returned string.
 *
 * \return String representation of CapToken.
 */
UPNP_EXPORT_SPEC char *SUpnpCapTokenToString(
    /*! [IN] CapToken to convert. */
    const captoken_t *capToken);


/*!
 * \brief Convert CapToken to hex string representation.
 *
 * \note The caller is responsible for freeing the returned string.
 *
 * \return Hex string representation of CapToken.
 */
UPNP_EXPORT_SPEC char *SUpnpCapTokenToHexString(
    /*! [IN] CapToken to convert. */
    const captoken_t *capToken);


/*!
 * \brief Convert hex string to CapToken.
 *
 * \note The caller is responsible for freeing the returned CapToken with
 *       SUpnpFreeCapToken().
 *
 * \return CapToken object.
 */
UPNP_EXPORT_SPEC captoken_t *SUpnpCapTokenFromHexString(
    /*! [IN] Hex string to convert. */
    const char *hex);


/*!
 * \brief Store CapToken to a file.
 *
 * \return SUPNP_E_SUCCESS on success, ret code on failure.
 */
UPNP_EXPORT_SPEC int SUpnpStoreCapToken(
    /*! [IN] CapToken to store. */
    const captoken_t *capToken,
    /*! [IN] File path to store the CapToken. */
    const char *filepath);


/*!
 * \brief Download a CapToken from a URL.
 *
 * \note The caller is responsible for freeing the returned CapToken with
 *       SUpnpFreeCapToken().
 *
 * \return CapToken object.
 */
UPNP_EXPORT_SPEC int SUpnpDownloadCapToken(
    /*! [IN] URL to download CapToken from. */
    const char *capTokenUrl,
    /*! [OUT] CapToken object. */
    captoken_t **p_capToken);


/*!
 * \brief Extract a field value from a CapToken.
 *
 * \note The caller is responsible for freeing the returned string.
 *
 * \return Field value.
 */
UPNP_EXPORT_SPEC char *SUpnpExtractCapTokenFieldValue(
    /*! [IN] CapToken to extract field value from. */
    const captoken_t *capToken,
    /*! [IN] Field type to extract. */
    ECapTokenFieldType type);


/*!
 * \brief Download a CapToken and extract a field value from it.
 *
 * \note The caller is responsible for freeing the returned string.
 *
 * \return Field value.
 */
UPNP_EXPORT_SPEC char *SUpnpExtractCapTokenFieldValue2(
    /*! [IN] URL to download CapToken from. */
    const char *capTokenUrl,
    /*! [IN] Field type to extract. */
    ECapTokenFieldType type);

/*!
 * \brief Verify a CapToken. Required by Secure Device Description.
 */
UPNP_EXPORT_SPEC int SUpnpVerifyCapToken(
    /*! [IN] CapToken to verify. */
    const captoken_t *capToken,
    /*! [IN] RA Public Key. */
    EVP_PKEY *pkeyRA,
    /*! [IN] Description Document Content. */
    const char *descDocContent);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */

#endif /* SUPNP_CAPTOKEN_H */
