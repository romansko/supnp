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
    /*! [in] Device for which CapToken is generated. */
    const supnp_device_t *dev,
    /*! [in] RA Public Key. */
    EVP_PKEY *pkeyRA);


/*!
 * \brief Free a CapToken.
 */
UPNP_EXPORT_SPEC void SUpnpFreeCapToken(
    /*! [in] CapToken to free. */
    captoken_t **p_capToken);


/*!
 * \brief Convert CapToken to string representation.
 *
 * \note The caller is responsible for freeing the returned string.
 *
 * \return String representation of CapToken.
 */
UPNP_EXPORT_SPEC char *SUpnpCapTokenToString(
    /*! [in] CapToken to convert. */
    const captoken_t *capToken);


/*!
 * \brief Convert CapToken to hex string representation.
 *
 * \note The caller is responsible for freeing the returned string.
 *
 * \return Hex string representation of CapToken.
 */
UPNP_EXPORT_SPEC char *SUpnpCapTokenToHexString(
    /*! [in] CapToken to convert. */
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
    /*! [in] Hex string to convert. */
    const char *hex);


/*!
 * \brief Store CapToken to a file.
 *
 * \return SUPNP_E_SUCCESS on success, ret code on failure.
 */
UPNP_EXPORT_SPEC int SUpnpStoreCapToken(
    /*! [in] CapToken to store. */
    const captoken_t *capToken,
    /*! [in] File path to store the CapToken. */
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
    /*! [in] URL to download CapToken from. */
    const char *capTokenUrl,
    /*! [out] CapToken object. */
    captoken_t **p_capToken);


/*!
 * \brief Extract a field value from a CapToken.
 *
 * \note The caller is responsible for freeing the returned string.
 *
 * \return Field value.
 */
UPNP_EXPORT_SPEC char *SUpnpExtractCapTokenFieldValue(
    /*! [in] CapToken to extract field value from. */
    const captoken_t *capToken,
    /*! [in] Field type to extract. */
    ECapTokenFieldType type);


/*!
 * \brief Download a CapToken and extract a field value from it.
 *
 * \note The caller is responsible for freeing the returned string.
 *
 * \return Field value.
 */
UPNP_EXPORT_SPEC char *SUpnpExtractCapTokenFieldValue2(
    /*! [in] URL to download CapToken from. */
    const char *capTokenUrl,
    /*! [in] Field type to extract. */
    ECapTokenFieldType type);

/*!
 * \brief Verify a CapToken. Required by Secure Device Description.
 */
UPNP_EXPORT_SPEC int SUpnpVerifyCapToken(
    /*! [in] CapToken to verify. */
    const captoken_t *capToken,
    /*! [in] RA Public Key. */
    EVP_PKEY *pkeyRA,
    /*! [in] Description Document Content. */
    const char *descDocContent);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */

#endif /* SUPNP_CAPTOKEN_H */
