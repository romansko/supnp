/*!
 * \addtogroup SUPnP
 *
 * \file supnp.h
 *
 * \author Roman Koifman
 *
 * \brief Header file for SUPnP secure layer method. Implementing logics from
 * the paper "Kayas, G., Hossain, M., Payton, J., & Islam, S. R. (2021). SUPnP:
 * Secure Access and Service Registration for UPnP-Enabled Internet of Things.
 * IEEE Internet of Things Journal, 8(14), 11561-11580."
 *
 * Copyright (c) 2000-2003 Intel Corporation
 * All rights reserved.
 * Copyright (C) 2011-2012 France Telecom All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * * Neither name of Intel Corporation nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL INTEL OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 ******************************************************************************/
#ifndef SUPNP_H
#define SUPNP_H

#include "UpnpGlobal.h" /* for UPNP_EXPORT_SPEC */
#include "upnpconfig.h"
#include "supnp_common.h"
#include "supnp_device.h"
#include "ixml.h"
#include "ithread.h"

#if ENABLE_SUPNP

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration */
typedef struct evp_pkey_st EVP_PKEY;
typedef struct x509_st X509;
typedef struct cJSON cJSON;

/* Globals */
extern int gCurrentDeviceType;
extern EVP_PKEY *gDevicePKey;  /* Device's private & public key pair */
extern EVP_PKEY *gRAPublicKey; /* Registration Authority Public Key */
extern char gCapTokenLocation[LOCATION_SIZE];
extern ithread_rwlock_t gDeviceTypeLock;
extern ithread_rwlock_t gDeviceKeyLock;
extern ithread_rwlock_t gRAKeyLock;
extern ithread_rwlock_t gCapTokenLocationLock;
/**/


/* Helper macro */
#define SUPNP_PARAM_STRNCPY(dst, src) { \
    if (src) { \
        strncpy(dst, src, (sizeof(dst) - 1)); \
    } \
}

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
 * \brief Set Device Type global variable.
 */
UPNP_EXPORT_SPEC void SUpnpSetDeviceType(
	/*! [IN] Device Type to set */
	EDeviceType devType);

/*!
 * \brief Retrieve Device Type global variable.
 *
 * \return Device Type.
 */
UPNP_EXPORT_SPEC EDeviceType SUpnpGetDeviceType();

/*!
 * \brief Set Device PKey global variable.
 * given pkey is copied to the global variable.
 * User responsible for freeing the given pkey with OpenSslFreePKey.
 */
UPNP_EXPORT_SPEC void SUpnpSetDevicePKey(
	/*! [IN] Device PKey to set */
	EVP_PKEY *pkey);

/*!
 * \brief Retrieve a copy of the Device's Public & Private Key pair copy.
 * Caller is responsible for freeing the returned key.
 *
 * \return Device's Public Key.
 */
UPNP_EXPORT_SPEC EVP_PKEY *SUpnpGetDevicePKey();

/*!
 * \brief Set RA Public Key global variable.
 * given pkey is copied to the global variable.
 * User responsible for freeing the given pkey with OpenSslFreePKey.
 */
UPNP_EXPORT_SPEC void SUpnpSetRAPublicKey(
	/*! [IN] RA Public Key to set */
	EVP_PKEY *pkey);

/*!
 * \brief Retrieve a copy of the RA's Public Key.
 * Caller is responsible for freeing the returned key.
 *
 * \return RA's Public Key.
 */
UPNP_EXPORT_SPEC EVP_PKEY *SUpnpGetRAPKey();

/*!
 * \brief Set CapToken location global variable.
 */
UPNP_EXPORT_SPEC void SUpnpSetCapTokenLocation(
	/*! [IN] Address Family to use */
	int AF,
	/*! [IN] CapToken Name */
	const char *CapTokenLocation);

/*!
 * \brief Retrieve CapToken location.
 */
UPNP_EXPORT_SPEC void SUpnpGetCapTokenLocation(
	/*! [OUT] CapToken location */
	char CapTokenLocation[LOCATION_SIZE]);

/*!
 * \brief Build CapToken location.
 */
UPNP_EXPORT_SPEC int SUpnpBuildLocation(
	/*! [OUT] The constructed URL */
	char url[LOCATION_SIZE],
	/*! [IN] Address Family to use */
	int AF,
	/*! [IN] Filename */
	const char *filename);

/*!
 * \brief Initialize [S]UPnP SDK. Invoking UpnpInit2.
 *
 * \return SUPNP_E_SUCCESS on success, ret code on failure.
 */
UPNP_EXPORT_SPEC int SUpnpInit(
 	/*! [IN] The interface name to use by the [S]UPnP SDK operations.
	 * Examples: "eth0", "xl0", "Local Area Connection", \c NULL to
	 * use the first suitable interface. */
	const char *IfName,
	/*! [IN] Local Port to listen for incoming connections.
	 * \c NULL will pick an arbitrary free port. */
	unsigned short DestPort,
	/*! [IN] Private key path (PEM format), for loading device key pair */
    const char *privateKeyPath,
    /*! [IN] Device Type */
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
 * \note return value must be freed by caller.
 *
 * \return The element item's value as a string, or NULL on failure.
 */
UPNP_EXPORT_SPEC char *SUpnpGetFirstElementItem(
	/*! [IN] The element to search for the item. */
	IXML_Element *element,
	/*! [IN] The name of the item to retrieve. */
	const char *item);

/*!
 * \brief Download Description Document from given location and retrieve the first element item by name.
 *
 * \note return value must be freed by caller.
 *
 * \return The element item's value as a string, or NULL on failure.
 */
UPNP_EXPORT_SPEC char *SUpnpGetFirstElementItem2(
	/*! [IN] The location of the description document. */
	const char *location,
	/*! [IN] The name of the item to retrieve. */
	const char *item);

/*!
 * \brief Retrieve CapTokenLocation & AdvertisementSig.
 */
int SUpnpGetSecureAdvertisementParams(
	/*! [OUT] CapToken Location buffer */
	char CapTokenLocation[LOCATION_SIZE],
	/*! [OUT] Advertisement Signature buffer */
    char AdvertisementSig[HEXSIG_SIZE]);

/*!
 * \brief Prepare secure parameters to be used for Secure operations.
 *
 * \return SUPNP_E_SUCCESS on success, return code on failure.
 */
UPNP_EXPORT_SPEC int SUpnpPrepareSecureParams(
	/*! [OUT] SecureParams to populate */
	SecureParams *Params);

/*!
 * \brief Verify secure parameters. To be used by SD device for
 *  Secure Discovery or Secure Control verifications.
 */
UPNP_EXPORT_SPEC int SUpnpVerifySecureParams(
	/*! [IN] Signature Name */
	const char *name,
	/*! [IN] SecureParams to verify */
	const SecureParams *SParams,
	/*! [IN] Appended string for signature verification */
	const char *append);


/******************************************************************************
 ******************************************************************************
 *                                                                            *
 *                          REGISTRATION PROCESS                              *
 *                                                                            *
 ******************************************************************************
 ******************************************************************************/

/*!
 * \name Registration Process
 *
 * @{
 */

/*!
 * \brief Verify DSD / SAD document.
 *
 * \return SUPNP_E_SUCCESS on success, error code on failure.
 */
UPNP_EXPORT_SPEC int SUpnpVerifyDocument(
	/*! [IN] CA's Public Key */
	EVP_PKEY *PublicKeyCA,
	/*! [IN] Device details */
	supnp_device_t *Dev);

/*!
 * \brief Register device with RA. Handles both Register & Challenge actions.
 *
 * \return SUPNP_E_SUCCESS on success, error code on failure.
 */
UPNP_EXPORT_SPEC int SUpnpRegisterDevice(
	/*! [IN] Array of file paths to the registration documents. */
    const char *RegistrationDocsPath[],
    /*! [IN] CapToken Filename */
    const char *CapTokenFilename,
    /*! [IN] Address Family to use for CapToken Location */
    int AF,
    /*! [IN] Description Document Name */
    const char *DescDocName,
    /*! [IN] Timeout value */
    int Timeout,
    /*! [IN] Callback function after registration */
    SUpnp_FunPtr Callback,
    /*! [IN] Callback cookie */
    void *callback_cookie);

/* Internal */
int sendRAActionRegister(RegistrationParams *Params, const char *ControlUrl);

/*! \brief Free registration parameters content. */
UPNP_EXPORT_SPEC void SUpnpFreeRegistrationParamsContent(RegistrationParams *Params);

/*! \brief Free registration parameters. */
UPNP_EXPORT_SPEC void SUpnpFreeRegistrationParams(RegistrationParams **Params);

/*! @} Registration Process */

/******************************************************************************
 ******************************************************************************
 *                                                                            *
 *                     SECURE SERVICE ADVERTISEMENT                           *
 *                                                                            *
 ******************************************************************************
 ******************************************************************************/

/*!
 * \name Secure Service Advertisement
 *
 * @{
 */

/*!
 * \brief Secure Service Advertisement sending (SD -> CP).
 *        Wrapper to UpnpSendAdvertisement function.
 *
 * \return UPNP_E_SUCCESS on success, ret code on failure.
 */
UPNP_EXPORT_SPEC int SUpnpSendAdvertisement(
	/*! The device handle for which to send out the announcements. */
	int Hnd,
	/*! The expiration age, in seconds, of the announcements. */
	int Exp);

/*!
 * \brief Handles Secure Service Advertisement verification which includes:
 *    1. Secure Advertisement Verification.
 *    2. Secure Device Description Verification.
 *
 * \return SUPNP_E_SUCCESS on success, ret code on failure.
 */
UPNP_EXPORT_SPEC int SUpnpSecureServiceAdvertisementVerify(
	/*! [IN] Description document URL */
	const char *descDocLocation,
	/*! [IN] Target Device (SD) CapToken URL */
	const char *capTokenLocation,
	/*! [IN] Advertisement signature in hex format */
	const char *AdvertisementSig);

/*!
 * \brief Unregisters an SD device. The function sends secure advertisement.
 *       Wrapper to UpnpUnRegisterRootDevice function.
 */
UPNP_EXPORT_SPEC int SUpnpUnRegisterRootDevice(
	/*! [IN] The handle of the root device instance to unregister. */
	int Hnd);


/*! @} Secure Service Advertisement */

/******************************************************************************
 ******************************************************************************
 *                                                                            *
 *                       SECURE SERVICE DISCOVERY                             *
 *                                                                            *
 ******************************************************************************
 ******************************************************************************/

/*!
 * \name Secure Service Discovery
 *
 * @{
 */

/*!
 * \brief Secure Service Discovery sending (CP -> SD).
 *        Wrapper to UpnpSearchAsync function.
 *
 * \return UPNP_E_SUCCESS on success, ret code on failure.
 */
UPNP_EXPORT_SPEC int SUpnpSearchAsync(
	/*! The handle of the client performing the search. */
	int Hnd,
	/*! The time, in seconds, to wait for responses. */
	int Mx,
	/*! Search Target (ST) */
    const char *Target,
    /*! The user data to pass when the callback function is invoked. */
    const char *Cookie);


/*!
 * \brief Secure Service Discovery logics SD. This function is called by multiple threads. Hence, some errors are silent.
 * The function that invokes SUpnpSecureServiceDiscoveryVerify will simply discard the thread upon failure.
 * Verify the discovery request and send the response.
 *
 * \return UPNP_E_SUCCESS on success, ret code on failure.
 */
int SUpnpSecureServiceDiscoveryVerify(
	/*! [IN] SUPnP Secure Params */
	const SecureParams *SParams);

/*! @} Secure Service Discovery */



/******************************************************************************
 ******************************************************************************
 *                                                                            *
 *                           SECURE CONTROL                                   *
 *                                                                            *
 ******************************************************************************
 ******************************************************************************/

/*!
 * \name Secure Control
 *
 * @{
 */


/*!
 * \brief Secure Control sending (CP -> SD).
 *        Wrapper to UpnpSendAction function.
 */
UPNP_EXPORT_SPEC int SUpnpSendAction(
	/*! [IN] The handle of the control point sending the action. */
	int Hnd,
	/*! [IN] The action URL of the service. */
	const char *ActionURL,
	/*! [IN] The type of the service. */
	const char *ServiceType,
	/*! [IN] This parameter is ignored and must be \c NULL. */
	const char *DevUDN,
	/*! [IN] The DOM document for the action. */
	IXML_Document *Action,
	/*! [OUT] The DOM document for the response to the action. The SDK
	 * allocates this document and the caller needs to free it. */
	IXML_Document **RespNode);

/*!
 * \brief Secure Control sending (CP -> SD).
 *        Wrapper to UpnpSendActionEx function.
 */
UPNP_EXPORT_SPEC int SUpnpSendActionEx(
	/*! [IN] The handle of the control point sending the action. */
	int Hnd,
	/*! [IN] The action URL of the service. */
	const char *ActionURL,
	/*! [IN] The type of the service. */
	const char *ServiceType,
	/*! [IN] This parameter is ignored and must be \c NULL. */
	const char *DevUDN,
	/*! [IN] The DOM document for the SOAP header. This may be \c NULL if
	 * the header is not required. */
	IXML_Document *Header,
	/*! [IN] The DOM document for the action. */
	IXML_Document *Action,
	/*! [OUT] The DOM document for the response to the action. The SDK
	 * allocates this document and the caller needs to free it. */
	IXML_Document **RespNode);

/*!
 * \brief Secure Control async sending (CP -> SD).
 *        Wrapper to UpnpSendActionAsync function.
 */
UPNP_EXPORT_SPEC int SUpnpSendActionAsync(
	/*! [IN] The handle of the control point sending the action. */
	int Hnd,
	/*! [IN] The action URL of the service. */
	const char *ActionURL,
	/*! [IN] The type of the service. */
	const char *ServiceType,
	/*! [IN] This parameter is ignored and must be \c NULL. */
	const char *DevUDN,
	/*! [IN] The DOM document for the action to perform on this device. */
	IXML_Document *Action,
	/*! [IN] Pointer to a callback function to be invoked when the operation
	 * completes. */
	void* Fun,
	/*! [IN] Pointer to user data that to be passed to the callback when
	 * invoked. */
	const void *Cookie);

/*!
 * \brief Secure Control async sending (CP -> SD).
 *        Wrapper to UpnpSendActionExAsync function.
 */
UPNP_EXPORT_SPEC int SUpnpSendActionExAsync(
	/*! [IN] The handle of the control point sending the action. */
	int Hnd,
	/*! [IN] The action URL of the service. */
	const char *ActionURL,
	/*! [IN] The type of the service. */
	const char *ServiceType,
	/*! [IN] This parameter is ignored and must be \c NULL. */
	const char *DevUDN,
	/*! [IN] The DOM document for the SOAP header. This may be \c NULL if
	 * the header is not required. */
	IXML_Document *Header,
	/*! [IN] The DOM document for the action to perform on this device. */
	IXML_Document *Action,
	/*! [IN] Pointer to a callback function to be invoked when the operation
	 * completes. */
	void* Fun,
	/*! [IN] Pointer to user data that to be passed to the callback when
	 * invoked. */
	const void *Cookie);

/*!
 * \brief Secure Control verify.
 * This function is to be called by SD device to verify Secure control message from CP device.
 *
 * \return SUPNP_E_SUCCESS on success, ret code on failure.
 */
UPNP_EXPORT_SPEC int SUpnpSecureControlVerify(
	/*! [IN] SUPnP Secure Params */
	const SecureParams *SParams);

/*! @} Secure Control */


/******************************************************************************
 ******************************************************************************
 *                                                                            *
 *                           SECURE EVENTING                                  *
 *                                                                            *
 ******************************************************************************
 ******************************************************************************/

/*!
 * \name Secure Eventing
 *
 * @{
 */


UPNP_EXPORT_SPEC int SUpnpSubscribe(
	/*! [in] The handle of the control point. */
	int Hnd,
	/*! [in] The URL of the service to subscribe to. */
	const char *PublisherUrl,
	/*! [in,out]Pointer to a variable containing the requested subscription
	 * time. Upon return, it contains the actual subscription time returned
	 * from the service. */
	int *TimeOut,
	/*! [out] Pointer to a variable to receive the subscription ID (SID). */
	char *SubsId);


UPNP_EXPORT_SPEC int SUpnpSubscribeAsync(
	/*! The handle of the control point that is subscribing. */
	int Hnd,
	/*! The URL of the service to subscribe to. */
	const char *PublisherUrl,
	/*! The requested subscription time. Upon return, it contains the actual
	 * subscription time returned from the service. */
	int TimeOut,
	/*! Pointer to the callback function for this subscribe request. */
	void *Fun,
	/*! A user data value passed to the callback function when invoked. */
	const void *Cookie);


/*!
 * \brief Calculate Event Signature as sign_cp(callback||nonce)
 */
UPNP_EXPORT_SPEC int SUpnpCalculateEventSignature(
	/*! [OUT] The calculated signature */
	char *signature,
	/*! [IN] hex nonce */
    const char *hexNonce,
    /*! [IN] callback string */
    const char *callback);

/*!
 * \brief Secure Eventing verify.
 */
UPNP_EXPORT_SPEC int SUpnpSecureEventingVerify(
	/*! [IN] SUPnP Secure Params */
    const SecureParams *SParams,
    /*! [IN] callback string */
    const char *callback);


/*! @} Secure Eventing */


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */

#endif // SUPNP_H
