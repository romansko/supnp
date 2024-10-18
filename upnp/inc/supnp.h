/*!
 * \addtogroup SUPnP
 *
 * \file supnp.h
 *
 * \brief Header file for SUPnP secure layer method. Implementing logics from
 * the paper "Kayas, G., Hossain, M., Payton, J., & Islam, S. R. (2021). SUPnP:
 * Secure Access and Service Registration for UPnP-Enabled Internet of Things.
 * IEEE Internet of Things Journal, 8(14), 11561-11580."
 *
 * \author Roman Koifman
 */
#ifndef SUPNP_H
#define SUPNP_H

#include "UpnpGlobal.h" /* for UPNP_EXPORT_SPEC */
#include "upnpconfig.h"
#include "supnp_common.h"
#include "supnp_device.h"
#include "ixml.h"

#if ENABLE_SUPNP

#ifdef __cplusplus
extern "C" {
#endif


/* Forward declaration */
typedef struct evp_pkey_st EVP_PKEY;
typedef struct x509_st X509;
typedef struct cJSON cJSON;

/*!
 * \name SUPnP Document keys
 *
 * @{
 */
#define SUPNP_DOC_TYPE "TYPE"
#define SUPNP_DOC_NAME "NAME"
#define SUPNP_DOC_PUBLIC_KEY "PK"
#define SUPNP_DOC_SERVICES "SERVICES"
#define SUPNP_DOC_SIG_OWNER "SIG-OWNER"
#define SUPNP_DOC_SIG_UCA "SIG-UCA"
#define SUPNP_DOC_SIG_CON "SIG-VER-CON" /* Signature Verification Conditions */
#define SUPNP_DOC_SIGNATURES "SIGS"
#define SUPNP_HARDWARE_DESC "HW"
#define SUPNP_SOFTWARE_DESC "SW"
/* @} SUPnPDocumentkeys */


/*!
 * \brief Initialize [S]UPnP SDK. Invoking UpnpInit2.
 *
 * \return SUPNP_E_SUCCESS on success, ret code on failure.
 */
UPNP_EXPORT_SPEC int SUpnpInit(
 	/*! [in] The interface name to use by the [S]UPnP SDK operations.
	 * Examples: "eth0", "xl0", "Local Area Connection", \c NULL to
	 * use the first suitable interface. */
	const char *IfName,
	/*! [in] Local Port to listen for incoming connections.
	 * \c NULL will pick an arbitrary free port. */
	unsigned short DestPort,
	/*! [in] Private key path (PEM format), for loading device key pair */
    const char *privateKeyPath,
    /*! [in] Device Type */
    int devType);


/*!
 * \brief Terminates the Linux SDK for SUPnP Devices.
 * This function must be the last API function called. It should be called only
 * once.
 *
 *  \return An integer representing one of the following:
 *      \li \c UPNP_E_SUCCESS: The operation completed successfully.
 *      \li \c UPNP_E_FINISH: The SDK is already terminated or
 *		it is not initialized.
 */
UPNP_EXPORT_SPEC int SUpnpFinish();


/*!
 * \brief Retrieve the first element item by name.
 *
 * \return The element item's value as a string.
 */
UPNP_EXPORT_SPEC char *SUpnpGetFirstElementItem(IXML_Element *element, const char *item);

/*!
 * \brief Verify DSD / SAD document.
 *
 * \return SUPNP_E_SUCCESS on success, SUPNP_E_INVALID_CERTIFICATE on failure.
 */
UPNP_EXPORT_SPEC int SUpnpVerifyDocument(EVP_PKEY *ca_pkey, supnp_device_t *dev);

/*!
 * \brief Register device with RA. Handles both Register & Challenge actions.
 *
 * \param RegistrationDocsPath Array of paths to the registration documents.
 * \param capTokenFilename CapToken filename.
 * \param device_url The device URL.
 * \param desc_doc_name The description document name.
 * \param timeout The timeout value.
 * \param callback The callback function.
 * \param callback_cookie The callback cookie.
 *
 * \return SUPNP_E_SUCCESS on success, SUPNP_E_INTERNAL_ERROR on failure.
 */
UPNP_EXPORT_SPEC int SUpnpRegisterDevice(
    const char *RegistrationDocsPath[],
    const char *capTokenFilename,
    char *device_url,      /* Expected heap allocated string */
    char *desc_doc_name,   /* Expected heap allocated string */
    int timeout,
    SUpnp_FunPtr callback,
    void *callback_cookie);

/*! \brief Free registration parameters content. */
UPNP_EXPORT_SPEC void SUpnpFreeRegistrationParamsContent(RegistrationParams *params);

/*! \brief Free registration parameters. */
UPNP_EXPORT_SPEC void SUpnpFreeRegistrationParams(RegistrationParams **params);

/*!
 * \brief Verify advertisement signature.
 *
 * \return SUPNP_E_SUCCESS on success, SUPNP_E_INVALID_SIGNATURE on failure.
 */
UPNP_EXPORT_SPEC int SUpnpSecureServiceAdvertisementVerify(
	/* [in] Advertisement signature in hex format */
	const char *hexSignature,
	/* [in] Description document URL */
	const char *descDocUrl,
	/* [in] Target Device (SD) CapToken URL */
	const char *capTokenUrl,
	/* [in] Current Device (CP) Cap Token */
    const char *deviceCapTokenString);


/*!
 * \brief Secure Service Discovery logics CP.
 * This function will invoke UpnpSearchAsync. See its description for more details.
 *
 * \return UPNP_E_SUCCESS on success, ret code on failure.
 */
UPNP_EXPORT_SPEC int SUpnpSecureServiceDiscoverySend(
	/*! The handle of the client performing the search. */
	int handle,
	/*! The time, in seconds, to wait for responses. */
	int searchTime,
	/*! Search Target (ST) */
    const char *target,
    /*! CapToken string */
    const char *capTokenString,
    /*! Cap Token relative location */
    const char *capTokenLocation);

/*!
 * \brief Secure Service Discovery logics SD. This function is called by multiple threads. Hence, some errors are silent.
 * The function that invokes SUpnpSecureServiceDiscoveryVerify will simply discard the thread upon failure.
 * Verify the discovery request and send the response.
 *
 * \return UPNP_E_SUCCESS on success, ret code on failure.
 */
int SUpnpSecureServiceDiscoveryVerify(
    /*! [in] CapToken Location string */
    const char *capTokenLocation,
    /*! [in] CapToken Location Hex String Signature */
    const char *capTokenLocationSignature,
    /*! [in] hex string nonce */
    const char *hexNonce,
    /*! [in] hex string discovery signature */
    const char *discoverySignature);

/*!
 * \brief returns current device type.
 */
int SUpnpGetDeviceType();

/* Internal */
int sendRAActionRegister(RegistrationParams *params, const char *controlUrl);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */

#endif // SUPNP_H
