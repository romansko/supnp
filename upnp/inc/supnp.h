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

#if ENABLE_SUPNP

#ifdef __cplusplus
extern "C" {
#endif

#include "supnp_err.h"
#include "supnp_device.h"

/*! Number of common documents on device (CertUCA, CertDevice, SpecDoc) */
#define SUPNP_DOCS_ON_DEVICE (3)

typedef int (*SUpnp_FunPtr)(void *Cookie);

/*! Registration status */
typedef enum _ERegistrationStatus
{
	eRegistrationStatus_DeviceUnregistered = 0,
	eRegistrationStatus_DeviceRegistered
}ERegistrationStatus;

/*! Registration Authority services. */
typedef enum _ERAServiceType
{
	/*! Registration Services. */
	eRegistrationAuthorityService_Register = 0,

	/*! Number of services. */
	eRegistrationAuthorityServiceCount
}ERAServiceType;

typedef enum _ERARegisterServiceActions
{
	/*! Register action. */
	eRegisterServiceAction_Register = 0,

	/*! Challenge action. */
	eRegisterServiceAction_Challenge,

	/*! Number of actions. */
	eRegisterServiceActionCount
}ERARegisterServiceActions;

/*! Registration service action Register variables. */
typedef enum _ERARegisterActionVariables
{
	/*! Specification Document hex string */
	eRegisterActionVar_SpecDoc = 0,

	/*! Device Certificate hex string */
	eRegisterActionVar_CertDevice,

	/*! UCA Certificate hex string */
	eRegisterActionVar_CertUCA,

	/*! Device URL */
	eRegisterActionVar_DeviceURL,

	/*! Description document URI, applicable only for SD */
	eRegisterActionVar_DescDocFileName,

	eRegisterActionVar_CapTokenFilename,

	/*! Number of variables. */
	eRegisterActionVarCount

}ERARegisterActionVariables;

/*! Registration service action Challenge variables. */
typedef enum _ERAChallengeActionVariables
{
	/*! Challenge response hex string */
	eChallengeActionVar_Challenge = 0,

	/*! Public key hex string */
	eChallengeActionVar_PublicKey,

	/*! Number of variables. */
	eChallengeActionVarCount

}ERAChallengeActionVariables;

/*! Registration Params */
typedef struct _RegistrationParams
{
	int handle; /* Registration handle */
	SUpnp_FunPtr callback;  /* To call upon successful registration */
	void *callback_cookie;
    const char *publicKeyPath;
    const char *privateKeyPath;
    const char *RegistrationDocsPath[SUPNP_DOCS_ON_DEVICE];
	char *deviceUrl;
	char *descDocFilename;       /* Only for SD */
	const char *capTokenFilename;
}RegistrationParams;

static const char *RaDeviceType = "urn:schemas-upnp-org:device:ra:1";
static const char *RaServiceType[eRegistrationAuthorityServiceCount] = {
	"urn:schemas-upnp-org:service:registration:1"
};
static const char *RaRegistrationAction[eRegisterServiceActionCount] = {
	"Register",
	"Challenge"
};
static const char *RaRegisterActionVarName[eRegisterActionVarCount] = {
	"SpecificationDocument",
	"CertificateDevice",
	"CertificateUCA",
	"DeviceURL",
	"DescriptionDocumentName", /* Applicable only for SD */
	"CapTokenFilename"
};
static const char *RaChallengeActionVarName[eChallengeActionVarCount] = {
	"Challenge",
	"PublicKey"
};
static const char *ActionResponseVarName = "ActionResponse";
static const char *CapTokenResponseVarName = "CapToken";
static const char *ActionSuccess = "1";

/* Forward declaration */
typedef struct evp_pkey_st EVP_PKEY;
typedef struct x509_st X509;
typedef struct cJSON cJSON;
typedef struct _IXML_Document IXML_Document;
typedef struct _IXML_NodeList IXML_NodeList;

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
 * \brief Initialize SUPnP secure layer.
 *
 * \return SUPNP_E_SUCCESS on success, SUPNP_E_INTERNAL_ERROR on failure.
 */
UPNP_EXPORT_SPEC int SUpnpInit();

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
 * \param pk_path Path to the public key file.
 * \param sk_path Path to the private key file.
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
UPNP_EXPORT_SPEC int SUpnpRegisterDevice(const char *pk_path,
	const char *sk_path,
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

 * \return SUPNP_E_SUCCESS on success, SUPNP_E_INVALID_SIGNATURE on failure.
 */
UPNP_EXPORT_SPEC int SUpnpSecureServiceAdvertisement(
	/* [in] Advertisement signature in hex format */
	const char *hexSignature,
	/* [in] Description document URL */
	const char *descDocUrl,
	/* [in] Target Device (SD) CapToken URL */
	const char *capTokenUrl,
	/* [in] Current Device (CP) Cap Token */
    const char *deviceCapTokenString);


/* Internal */
int sendRAActionRegister(RegistrationParams *params, const char *controlUrl);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */

#endif // SUPNP_H
