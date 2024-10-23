/*******************************************************************************
 *
 * Copyright (c) 2000-2003 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * - Neither name of Intel Corporation nor the names of its contributors
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

/*!
 * \addtogroup UpnpSamples
 *
 * @{
 *
 * \name Device Sample Module
 *
 * @{
 *
 * \file
 */

#include "registration_authority.h"

#include "upnp.h"
#include "upnpdebug.h"

#include <openssl_wrapper.h>
#include <openssl_error.h>
#include <supnp.h>

#include <assert.h>
#include <supnp_captoken.h>
#include <supnp_common.h>

#if OPENSSL_CSPRNG_SIZE != SHA256_DIGEST_LENGTH
#error "Hash size mismatch"
#endif

#define MAX_SUPNP_DOC_SIZE      4096

/*! Relative to upnp/sample */
#define DEFAULT_PATH_PUBLIC_KEY_CA   "../../simulation/CA/public_key.pem"
#define DEFAULT_PATH_PRIVATE_KEY_RA  "../../simulation/RA/private_key.pem"
#define DEFAULT_WEB_DIR              "./web"
#define DEFAULT_DESC_DOC_NAME        "radesc.xml";

char PublicKeyPathCA[LOCATION_SIZE]  = {0};
char PrivateKeyPathRA[LOCATION_SIZE] = {0};
char DescDocLocation[LOCATION_SIZE]  = {0}; /* URL */

supnp_device_t * SUPnPDeviceList = NULL;

ra_action RAActionFunctions[eRegisterServiceActionCount] = {
    RegisterDevice,
    VerifyChallenge};

const int RAServiceVariableCount[eRegistrationAuthorityServiceCount] = { eRegisterActionVarCount };

char RegistrationDocs[eRegisterActionVarCount][MAX_SUPNP_DOC_SIZE] = { 0 };

/*! The amount of time (in seconds) before advertisements will expire. */
int default_advr_expire = 100;

/*! Global structure for storing the state table for this device. */
struct RAService ra_service_table[eRegistrationAuthorityServiceCount];

/*! Device handle supplied by UPnP SDK. */
UpnpDevice_Handle device_handle = -1;

/*! Mutex for protecting the global state table data
 * in a multithreaded, asynchronous environment.
 * All functions should lock this mutex before reading
 * or writing the state table data. */
ithread_mutex_t RAMutex;

/*!
 * \brief Initializes the service table for the specified service.
 */
static int SetServiceTable(
	/*! [in] one of TV_SERVICE_CONTROL or, TV_SERVICE_PICTURE. */
	int serviceType,
	/*! [in] UDN of device containing service. */
	const char *UDN,
	/*! [in] serviceId of service. */
	const char *serviceId,
	/*! [in] service type (as specified in Description Document) . */
	const char *serviceTypeS,
	/*! [in,out] service containing table to be set. */
	struct RAService *out)
{
    sample_verify(serviceType < eRegistrationAuthorityServiceCount, error_label, "Invalid serviceType\n");
    sample_verify(UDN, error_label, "NULL UDN\n");
    sample_verify(serviceId, error_label, "NULL serviceId\n");
    sample_verify(serviceTypeS, error_label, "NULL serviceTypeS\n");
    sample_verify(out, error_label, "NULL RAService\n");

    out->VariableCount = RAServiceVariableCount[serviceType];
	strcpy(out->UDN, UDN);
	strcpy(out->ServiceId, serviceId);
	strcpy(out->ServiceType, serviceTypeS);

    for (int i = 0; i < out->VariableCount; ++i) {
        out->VariableName[i] = SUpnpRaRegisterActionVarName[i];
        out->VariableStrVal[i] = RegistrationDocs[i];
    }

	return SetActionTable(serviceType, out);

error_label:
    return UPNP_E_INVALID_SERVICE;
}

int SetActionTable(const ERAServiceType serviceType, struct RAService *out)
{
    int ret = UPNP_E_INVALID_SERVICE;
    switch(serviceType) {
    case eRegistrationAuthorityService_Register:
    {
        memset(out->ActionNames, 0, sizeof(out->ActionNames));
        memset(out->actions, 0, sizeof(out->actions));
        for (int i=0; i<eRegisterServiceActionCount; ++i) {
            out->ActionNames[i] = SUpnpRaRegistrationActionString[i];
            out->actions[i] = RAActionFunctions[i];
        }
		ret = UPNP_E_SUCCESS;
        break;
	}
        default:
            /* Do Nothing */
	}

	return ret;
}


int RAStateTableInit(char *DescDocURL)
{
	IXML_Document *DescDoc = NULL;
	int ret = UPNP_E_SUCCESS;
    char *udn = NULL;
    char *servid[eRegistrationAuthorityServiceCount] = {NULL};
    char *evnturl[eRegistrationAuthorityServiceCount] = {NULL};
    char *ctrlurl[eRegistrationAuthorityServiceCount] = {NULL};

	/*Download description document */
	if (UpnpDownloadXmlDoc(DescDocURL, &DescDoc) != UPNP_E_SUCCESS) {
		SampleUtil_Print("RAStateTableInit -- Error Parsing %s\n", DescDocURL);
		ret = UPNP_E_INVALID_DESC;
		goto error_handler;
	}
    udn = SampleUtil_GetFirstDocumentItem(DescDoc, "UDN");
    for (int srvType=0; srvType<eRegistrationAuthorityServiceCount; ++srvType) {
        if (!SampleUtil_FindAndParseService(DescDoc,
            DescDocURL,
            SUpnpRaServiceTypeStrings[srvType],
            &servid[srvType],
            &evnturl[srvType],
            &ctrlurl[srvType])) {
            SampleUtil_Print("RAStateTableInit -- Error: Could not "
                     "find Service: %s\n", SUpnpRaServiceTypeStrings[srvType]);
            ret = UPNP_E_INVALID_DESC;
            break;
        }

        ret = SetServiceTable(srvType,
            udn,
            servid[srvType],
            SUpnpRaServiceTypeStrings[srvType],
            &ra_service_table[srvType]);
        if (ret != UPNP_E_SUCCESS)
            break;
    }

error_handler:
    freeif(udn);
    for (int srvType=0; srvType<eRegistrationAuthorityServiceCount; ++srvType) {
        freeif(servid[srvType]);
        freeif(evnturl[srvType]);
        freeif(ctrlurl[srvType]);
    }
	freeif2(DescDoc, ixmlDocument_free);
	return ret;
}

int RAHandleGetVarRequest(UpnpStateVarRequest *cgv_event)
{
	unsigned int i = 0;
    int getvar_succeeded = 0;

	UpnpStateVarRequest_set_CurrentVal(cgv_event, NULL);

	ithread_mutex_lock(&RAMutex);

	for (i = 0; i < eRegistrationAuthorityServiceCount; i++) {
		/* check udn and service id */
        const struct RAService * pRaSrvc = &ra_service_table[i];
		const char *devUDN = UpnpString_get_String(
			UpnpStateVarRequest_get_DevUDN(cgv_event));
		const char *serviceID = UpnpString_get_String(
			UpnpStateVarRequest_get_ServiceID(cgv_event));
		if (strcmp(devUDN, pRaSrvc->UDN) == 0 &&
			strcmp(serviceID, pRaSrvc->ServiceId) == 0) {
			/* check variable name */
			for (int j = 0; j < pRaSrvc->VariableCount;	j++) {
				const char *stateVarName = UpnpString_get_String(
					UpnpStateVarRequest_get_StateVarName(cgv_event));
				if (strcmp(stateVarName, pRaSrvc->VariableName[j]) == 0) {
					getvar_succeeded = 1;
					UpnpStateVarRequest_set_CurrentVal(
						cgv_event,
						pRaSrvc->VariableStrVal[j]);
					break;
				}
			}
		}
	}
	if (getvar_succeeded) {
		UpnpStateVarRequest_set_ErrCode(cgv_event, UPNP_E_SUCCESS);
	} else {
		SampleUtil_Print(
			"Error in UPNP_CONTROL_GET_VAR_REQUEST callback:\n"
			"   Unknown variable name = %s\n",
			UpnpString_get_String(
				UpnpStateVarRequest_get_StateVarName(cgv_event)));
		UpnpStateVarRequest_set_ErrCode(cgv_event, 404);
		UpnpStateVarRequest_strcpy_ErrStr(cgv_event, "Invalid Variable");
	}

	ithread_mutex_unlock(&RAMutex);

	return UpnpStateVarRequest_get_ErrCode(cgv_event) == UPNP_E_SUCCESS;
}

int RAHandleActionRequest(UpnpActionRequest *ca_event)
{
	/* Defaults if action not found. */
	int action_found = 0;
	int i = 0;
	int retCode = 0;
    struct RAService *pRaSrvc = NULL;
	const char *errorString = NULL;
	const char *devUDN = NULL;
	const char *serviceID = NULL;
	const char *actionName = NULL;
	IXML_Document *actionResult = NULL;

	UpnpActionRequest_set_ErrCode(ca_event, 0);
	UpnpActionRequest_set_ActionResult(ca_event, NULL);

	devUDN = UpnpString_get_String(UpnpActionRequest_get_DevUDN(ca_event));
	serviceID = UpnpString_get_String(UpnpActionRequest_get_ServiceID(ca_event));
	actionName = UpnpString_get_String(	UpnpActionRequest_get_ActionName(ca_event));

    sample_verify(devUDN, cleanup, "devUDN is NULL\n");
    sample_verify(serviceID, cleanup, "serviceID is NULL\n");
    sample_verify(actionName, cleanup, "actionName is NULL\n");

    for (i=0; i<eRegistrationAuthorityServiceCount; ++i) {
        if (strcmp(devUDN, ra_service_table[i].UDN) != 0 ||
            strcmp(serviceID, ra_service_table[i].ServiceId) != 0) {
            continue;
        }
        pRaSrvc = &ra_service_table[i];
        sample_verify(pRaSrvc, cleanup, "pRaSrvc is NULL\n");

        /* Find and call appropriate procedure based on action name.
         * Each action name has an associated procedure stored in the
         * service table. These are set at initialization. */
        for (i = 0; (i < RA_MAXACTIONS) && pRaSrvc->ActionNames[i]; ++i) {
            if (!strcmp(actionName, pRaSrvc->ActionNames[i])) {
                retCode = pRaSrvc->actions[i](
                        UpnpActionRequest_get_ActionRequest(ca_event),
                        &actionResult,
                        &errorString);
                UpnpActionRequest_set_ActionResult(ca_event, actionResult);
                action_found = 1;
                break;
            }
        }
    }

	if (!action_found) {
		UpnpActionRequest_set_ActionResult(ca_event, NULL);
		UpnpActionRequest_strcpy_ErrStr(ca_event, "Invalid Action");
		UpnpActionRequest_set_ErrCode(ca_event, 401);
	} else {
		if (retCode == UPNP_E_SUCCESS) {
			UpnpActionRequest_set_ErrCode(ca_event, UPNP_E_SUCCESS);
		} else {
			/* copy the error string */
			UpnpActionRequest_strcpy_ErrStr(ca_event, errorString);
			switch (retCode) {
			case UPNP_E_INVALID_PARAM:
				UpnpActionRequest_set_ErrCode(ca_event, 402);
				break;
			case UPNP_E_INTERNAL_ERROR:
			default:
				UpnpActionRequest_set_ErrCode(ca_event, 501);
				break;
			}
		}
	}

cleanup:
	return UpnpActionRequest_get_ErrCode(ca_event);
}

/**
 * Handles Device Registration process. For more details refer to
 * SUPnP Paper - Fig. 15 DSD/SAD verification process.
 */
int RegisterDevice(IXML_Document *in, IXML_Document **out, const char **errorString)
{
    supnp_device_t *dev = NULL;
    int ret = UPNP_E_INVALID_PARAM;
    char* hex[SUPNP_DOCS_ON_DEVICE]  = {NULL};
    char* docs[SUPNP_DOCS_ON_DEVICE] = {NULL};
    size_t doc_size[SUPNP_DOCS_ON_DEVICE] = {0};
    EVP_PKEY* ca_pk  = NULL;
    unsigned char *nonce = NULL;
    unsigned char* enc_nonce = NULL;
    char * challenge_str = NULL;
    size_t enc_len = 0;
    char retVal[5] = {0};

    sample_verify_ex(in && out && errorString, cleanup, errorString, "NULL arguments.\n");
    (*out) = NULL;

    ithread_mutex_lock(&RAMutex);

    /* Step 1 - Receive and Load DSD/SAD, Device Certificate, UCA Certificate */
    for (int i=0; i<SUPNP_DOCS_ON_DEVICE; ++i) {
        hex[i] = SampleUtil_GetFirstDocumentItem(in,
            SUpnpRaRegisterActionVarName[i]);
        docs[i] = (char * )OpenSslHexStringToBinary(hex[i], &doc_size[i]);
        sample_verify_ex(docs[i], cleanup, errorString,
            "Invalid Registration parameters.\n");
    }

    ca_pk = OpenSslLoadPublicKeyFromPEM(PublicKeyPathCA);
    sample_verify_ex(ca_pk, cleanup, errorString,
        "Error loading CA Public Key.\n");

    dev = SupnpNewDevice(docs[eRegisterActionVar_SpecDoc],
        docs[eRegisterActionVar_CertDevice],
        docs[eRegisterActionVar_CertUCA]);
    sample_verify_ex(dev, cleanup, errorString,
        "Unable to initialize new device.\n");

    /* Retrieve CapToken Location */
    memset(dev->capTokenLocation, 0, sizeof(dev->capTokenLocation));
    char *capTokenLocation = SampleUtil_GetFirstDocumentItem(in,
        SUpnpRaRegisterActionVarName[eRegisterActionVar_CapTokenLocation]);
    sample_verify_ex(capTokenLocation, cleanup, errorString,
        "NULL CapToken Location.\n");
    strncpy(dev->capTokenLocation, capTokenLocation, LOCATION_SIZE);
    freeif(capTokenLocation);

    /* Applicable only for SD */
    memset(dev->descDocLocation, 0, sizeof(dev->descDocLocation));
    char *descDocLocation = SampleUtil_GetFirstDocumentItemSilent(in,
        SUpnpRaRegisterActionVarName[eRegisterActionVar_DescDocFileLocation]);
    if (descDocLocation != NULL) {
        strncpy(dev->descDocLocation, descDocLocation, LOCATION_SIZE);
        ret = UpnpDownloadXmlDoc(descDocLocation, &(dev->descDocument));
        sample_verify_ex(ret == UPNP_E_SUCCESS, cleanup, errorString,
            "Error in UpnpDownloadXmlDoc.\n");
        free(descDocLocation);
    }

    /* Fig.15 - Step 2 + 3
     * Verify UCA Certificate using CA's public key.
     * Verify Device Certificate using UCA's public key.
     * Verify DSD / SAD Using Device public key & UCA public key.
     */
    ret = SUpnpVerifyDocument(ca_pk, dev);
    sample_verify_ex(ret == SUPNP_E_SUCCESS, cleanup, errorString,
        "Unable to verify device\n");

    ret = SUPNP_E_INTERNAL_ERROR;

    /* Fig. 15 - step 4 - Generates nonce  */
    nonce = OpenSslGenerateNonce(OPENSSL_CSPRNG_SIZE);
    sample_verify_ex(nonce, cleanup, errorString, "Error generating nonce.\n");

    /* Save nonce for later */
    memcpy(dev->nonce, nonce, OPENSSL_CSPRNG_SIZE);

    /* Fig. 15 - step 5 - Encrypt and send the challenge. */
    enc_nonce = OpenSslAsymmetricEncryption(dev->pkeyDevice, &enc_len, nonce, OPENSSL_CSPRNG_SIZE);
    sample_verify_ex(enc_nonce, cleanup, errorString, "Error encrypting nonce challenge.\n");
    challenge_str = OpenSslBinaryToHexString(enc_nonce, enc_len);
    sample_verify_ex(challenge_str, cleanup, errorString, "Error converting challenge to hex string.\n");
    ret = UpnpAddToActionResponse(out,
            SUpnpRaRegistrationActionString[eRegisterServiceAction_Register],
            SUpnpRaServiceTypeStrings[eRegistrationAuthorityService_Register],
            SUpnpRaChallengeActionVarName[eChallengeActionVar_Challenge],
            challenge_str);
    sample_verify_ex(ret == UPNP_E_SUCCESS, cleanup, errorString, "Unable to add response\n");

    /* Save Device - Phase B will verify if device challenge is correct */
    SupnpAddListDevice(&SUPnPDeviceList, dev);

    ret = UPNP_E_SUCCESS;

cleanup:
    if (ret != SUPNP_E_SUCCESS) {
        SupnpFreeDevice(&dev);
        sprintf(retVal, "%d", ret);
        (void) UpnpAddToActionResponse(out,
            SUpnpRaRegistrationActionString[eRegisterServiceAction_Register],
            SUpnpRaServiceTypeStrings[eRegistrationAuthorityService_Register],
            "ErrorCode",
            retVal);
    }
    for (int i=0; i<SUPNP_DOCS_ON_DEVICE; ++i) {
        freeif(hex[i]);
        freeif(docs[i]);
    }
    freeif(challenge_str);
    freeif(nonce);
    freeif(enc_nonce);
    OpenSslFreePKey(&ca_pk);
    ithread_mutex_unlock(&RAMutex);
    return ret;
}

/**
 * Completes Device Registration Challenge Verification process.
 * Steps 9-11 in SUPnP Paper - Fig. 15 DSD/SAD verification process,
 * are actually signature verification.
 */
int VerifyChallenge(IXML_Document *in, IXML_Document **out, const char **errorString)
{
    int ret = SUPNP_DEV_ERR;
    char *hex = NULL;
    char *response = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *raPkey = NULL;
    char retVal[5] = {0};
    supnp_device_t *p_dev = NULL;
    char *capToken = NULL;

    sample_verify_ex(in && out && errorString, cleanup, errorString, "NULL arguments.\n");
    (*out) = NULL;

    ithread_mutex_lock(&RAMutex);

    raPkey = OpenSslLoadPrivateKeyFromPEM(PrivateKeyPathRA);
    sample_verify_ex(raPkey, cleanup, errorString, "Unable to load RA Private Key.\n");

    /* Extract public key */
    hex = SampleUtil_GetFirstDocumentItem(in,
        SUpnpRaChallengeActionVarName[eChallengeActionVar_PublicKey]);
    pkey = OpenSslLoadPublicKeyFromHex(hex);
    sample_verify_ex(pkey, cleanup, errorString, "Unable to load Public Key.\n");

    /* Search for the device by the given public key */
    p_dev = SupnpFindDeviceByPublicKey(SUPnPDeviceList, pkey);
    sample_verify_ex(p_dev, cleanup, errorString, "Device by public key not found.\n");

    if (p_dev->verified == 1) {
        ret = SUPNP_E_SUCCESS;
        goto verified;
    }

    /* Extract challenge response */
    response = SampleUtil_GetFirstDocumentItem(in,
        SUpnpRaChallengeActionVarName[eChallengeActionVar_Challenge]);

    /* Verify Signature  */
    ret = OpenSslVerifySignature("nonce challenge", pkey, response, p_dev->nonce, OPENSSL_CSPRNG_SIZE);
    sample_verify_ex(ret == OPENSSL_SUCCESS, cleanup, errorString, "Error verifying nonce challenge signature.\n");

    /* Verification successful */
    p_dev->verified = 1;
    SampleUtil_Print("Device %s challenge successfully verified\n", p_dev->name);

    /* Since device is verified, it's time to generate a Cap Token */
    ret = SUPNP_E_CAPTOKEN_ERROR;
    p_dev->capToken = SUpnpGenerateCapToken(p_dev, raPkey);
    sample_verify_ex(p_dev->capToken, cleanup, errorString, "Error generating Cap Token.\n");

verified:
    capToken = SUpnpCapTokenToHexString(p_dev->capToken);
    sample_verify_ex(capToken, cleanup, errorString, "Error converting CapToken to hex string.\n");

    ret = UpnpAddToActionResponse(out,
   SUpnpRaRegistrationActionString[eRegisterServiceAction_Challenge],
   SUpnpRaServiceTypeStrings[eRegistrationAuthorityService_Register],
   SUpnpCapTokenResponseVarName,
   capToken);
    sample_verify_ex(ret == UPNP_E_SUCCESS, cleanup, errorString, "Unable to add CapToken to response.\n");

    /* Status OK */
    ret = SUPNP_E_SUCCESS;

cleanup:
    if (ret == SUPNP_E_SUCCESS) {
        (void) UpnpAddToActionResponse(out,
           SUpnpRaRegistrationActionString[eRegisterServiceAction_Challenge],
           SUpnpRaServiceTypeStrings[eRegistrationAuthorityService_Register],
           SUpnpActionResponseVarName,
           SUpnpActionSuccessString);
    } else {
        SupnpRemoveListDevice(&SUPnPDeviceList, p_dev); /* Remove device from list */
        sprintf(retVal, "%d", ret);
        (void) UpnpAddToActionResponse(out,
            SUpnpRaRegistrationActionString[eRegisterServiceAction_Challenge],
            SUpnpRaServiceTypeStrings[eRegistrationAuthorityService_Register],
            SUpnpActionResponseVarName,
            retVal);
    }
    freeif(hex);
    freeif(response);
    OpenSslFreePKey(&pkey);
    OpenSslFreePKey(&raPkey);
    freeif(capToken);
    ithread_mutex_unlock(&RAMutex);
    return ret;
}

int RACallbackEventHandler(Upnp_EventType EventType, const void *Event, void *Cookie)
{
	(void)Cookie;
	switch (EventType) {
	case UPNP_CONTROL_GET_VAR_REQUEST:
		RAHandleGetVarRequest((UpnpStateVarRequest *)Event);
		break;
	case UPNP_CONTROL_ACTION_REQUEST:
		RAHandleActionRequest((UpnpActionRequest *)Event);
		break;
	/* Ignore */
	case UPNP_EVENT_SUBSCRIPTION_REQUEST:
	case UPNP_DISCOVERY_ADVERTISEMENT_ALIVE:
	case UPNP_DISCOVERY_SEARCH_RESULT:
	case UPNP_DISCOVERY_SEARCH_TIMEOUT:
	case UPNP_DISCOVERY_ADVERTISEMENT_BYEBYE:
	case UPNP_CONTROL_ACTION_COMPLETE:
	case UPNP_CONTROL_GET_VAR_COMPLETE:
	case UPNP_EVENT_RECEIVED:
	case UPNP_EVENT_RENEWAL_COMPLETE:
	case UPNP_EVENT_SUBSCRIBE_COMPLETE:
	case UPNP_EVENT_UNSUBSCRIBE_COMPLETE:
	case UPNP_EVENT_AUTORENEWAL_FAILED:
	case UPNP_EVENT_SUBSCRIPTION_EXPIRED:
	    break;
	default:
		SampleUtil_Print("Error in RACallbackEventHandler: "
				 "unknown event type %d\n",
			EventType);
	}
	/* Print a summary of the event received */
	SampleUtil_PrintEvent(EventType, Event);

	return 0;
}

int RAStart(char *iface,
	unsigned short port,
	const char *desc_doc_name,
	const char *public_key_ca,
    const char *private_key_ra,
	const char *web_dir_path,
	int ip_mode,
	print_string pfun)
{
	int ret = UPNP_E_SUCCESS;
	char desc_doc_url[MAX_URL_SIZE];
	char *ip_address = NULL;
	int address_family = AF_INET;

    ithread_mutex_init(&RAMutex, NULL);
	UpnpSetLogFileNames(NULL, NULL);
	UpnpSetLogLevel(UPNP_ERROR);
	UpnpInitLog();
	SampleUtil_Initialize(pfun);

	SampleUtil_Print("Initializing [S]UPnP Sdk with\n"
			 "\tinterface = %s port = %u\n", iface ? iface : "{NULL}", port);

    if (!desc_doc_name) {
        desc_doc_name = DEFAULT_DESC_DOC_NAME;
    }
    if (public_key_ca) {
        strncpy(PublicKeyPathCA, public_key_ca, LOCATION_SIZE);
    } else {
        strncpy(PublicKeyPathCA, DEFAULT_PATH_PUBLIC_KEY_CA, LOCATION_SIZE);
    }
    if (private_key_ra) {
        strncpy(PrivateKeyPathRA, private_key_ra, LOCATION_SIZE);
    } else {
        strncpy(PrivateKeyPathRA, DEFAULT_PATH_PRIVATE_KEY_RA, LOCATION_SIZE);
    }
    if (!web_dir_path) {
        web_dir_path = DEFAULT_WEB_DIR;
    }

    /* Initialize SUPnP & UPnP SDK */
	ret = SUpnpInit(iface, port, PrivateKeyPathRA, eDeviceType_RA, web_dir_path, "");
    sample_verify(ret == UPNP_E_SUCCESS, error_handler, "Error with UpnpInit2 -- %d\n", ret);

	switch (ip_mode) {
	case IP_MODE_IPV4:
		ip_address = UpnpGetServerIpAddress();
		port = UpnpGetServerPort();
		address_family = AF_INET;
		break;
	case IP_MODE_IPV6_LLA:
		ip_address = UpnpGetServerIp6Address();
		port = UpnpGetServerPort6();
		address_family = AF_INET6;
		break;
	case IP_MODE_IPV6_ULA_GUA:
		ip_address = UpnpGetServerUlaGuaIp6Address();
		port = UpnpGetServerUlaGuaPort6();
		address_family = AF_INET6;
		break;
	default:
		SampleUtil_Print("Invalid ip_mode : %d\n", ip_mode);
		return UPNP_E_INTERNAL_ERROR;
	}
	SampleUtil_Print("UPnP Initialized\n\tipaddress = %s port = %u\n",
		ip_address ? ip_address : "{NULL}",	port);

    ret = SampleUtil_BuildUrl(desc_doc_url,
        sizeof(desc_doc_url),
        address_family,
        ip_address,
        port,
        desc_doc_name);
	sample_verify(ret == UPNP_E_SUCCESS, error_handler,
	    "Error building URL -- %s: %d\n", desc_doc_name, ret);

    strncpy(DescDocLocation, desc_doc_url, LOCATION_SIZE);

	SampleUtil_Print("Specifying the webserver root directory -- %s\n",
		web_dir_path);
	ret = UpnpSetWebServerRootDir(web_dir_path);
    sample_verify(ret == UPNP_E_SUCCESS, error_handler,
        "Error specifying webserver root directory -- %s: %d\n",
        web_dir_path, ret);

	SampleUtil_Print("Registering the RootDevice\n"
			 "\t with desc_doc_url: %s\n",	desc_doc_url);
	ret = UpnpRegisterRootDevice3(desc_doc_url,
		RACallbackEventHandler,
		&device_handle,
		&device_handle,
		address_family);
    sample_verify(ret == UPNP_E_SUCCESS, error_handler,
        "Error registering the rootdevice : %d\n", ret);

    SampleUtil_Print("RootDevice Registered\nInitializing State Table\n");
    RAStateTableInit(desc_doc_url);
    SampleUtil_Print("State Table Initialized\n");
    SampleUtil_Print("State Table Initialized\n");
    ret = UpnpSendAdvertisement(device_handle,
        NULL,
        NULL,
        default_advr_expire);
    sample_verify(ret == UPNP_E_SUCCESS, error_handler, "Error sending advertisements : %d\n", ret);
    SampleUtil_Print("Advertisements Sent\n");
    return UPNP_E_SUCCESS;

error_handler:
    SUpnpFinish();
    return ret;
}

/**
 * Registration Authority Stop
 */
int RAStop(void)
{
    /* RA Advertisement doesn't have CapTokenLocation & sig */
    unsigned char *sig = NULL;
    char *hexsig = NULL;
    size_t sigsize;
    EVP_PKEY *raPkey = OpenSslLoadPrivateKeyFromPEM(PrivateKeyPathRA);
    char concat[LOCATION_SIZE * 2] = {0};
    if (raPkey == NULL) {
        supnp_error("Error loading RA Private Key\n");
    } else if (strlen(DescDocLocation) == 0) {
        supnp_error("Description Document not loaded\n");
    }else {
        strncpy(concat, DescDocLocation, LOCATION_SIZE);
        strncat(concat, "ra", LOCATION_SIZE);
        sig = OpenSslSign(raPkey,  /* sign(DescDoc || "") */
            (unsigned char *)concat,
            strlen(concat),
            &sigsize);
        if (sig != NULL) {
            hexsig = OpenSslBinaryToHexString(sig, sigsize);
        }
    }
    if (hexsig == NULL) {
        UpnpUnRegisterRootDevice(device_handle,
            NULL, NULL);
    } else {
        UpnpUnRegisterRootDevice(device_handle,
           "ra", hexsig);
    }
    OpenSslFreePKey(&raPkey);
    freeif(sig);
    freeif(hexsig);
	SUpnpFinish();
	SampleUtil_Finish();
	ithread_mutex_destroy(&RAMutex);

	return UPNP_E_SUCCESS;
}

/**
 * Registration Authority Command Loop
 */
void *RACommandLoop(void *args)
{
	char cmdline[100];
	char cmd[100];
	char *s;
	(void)args;

	while (1) {
		sprintf(cmdline, " ");
		sprintf(cmd, " ");
		SampleUtil_Print("\n>> ");
		/* Get a command line */
		s = fgets(cmdline, 100, stdin);
		if (!s)
			break;
#ifdef _WIN32
		sscanf_s(cmdline, "%s", cmd, (unsigned)_countof(cmd));
#else
		sscanf(cmdline, "%s", cmd);
#endif
		if (strcasecmp(cmd, "exit") == 0) {
			SampleUtil_Print("Shutting down...\n");
			RAStop();
			exit(0);
		} else {
			SampleUtil_Print("\n   Unknown command: %s\n\n", cmd);
			SampleUtil_Print("   Valid Commands:\n"
					 "     Exit\n\n");
		}
	}

	return NULL;
}

int ra_main(int argc, char *argv[])
{
	unsigned int portTemp = 0;
	char *iface = NULL;
	char *desc_doc_name = NULL;
    char *public_key_ca = NULL;
    char *private_key_ra = NULL;
	char *web_dir_path = NULL;
	unsigned short port = 0;
	int ip_mode = IP_MODE_IPV4;
	int i = 0;

	SampleUtil_Initialize(linux_print);
	/* Parse options */
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-i") == 0) {
			iface = argv[++i];
		} else if (strcmp(argv[i], "-port") == 0) {
#ifdef WIN32
			sscanf_s(argv[++i], "%u", &portTemp);
#else
			sscanf(argv[++i], "%u", &portTemp);
#endif
		} else if (strcmp(argv[i], "-desc") == 0) {
			desc_doc_name = argv[++i];
		} else if (strcmp(argv[i], "-ca_pkey") == 0) {
		    public_key_ca = argv[++i];
		} else if (strcmp(argv[i], "-ra_pkey") == 0) {
		    private_key_ra = argv[++i];
		} else if (strcmp(argv[i], "-webdir") == 0) {
			web_dir_path = argv[++i];
		} else if (strcmp(argv[i], "-m") == 0) {
#ifdef _WIN32
			sscanf_s(argv[++i], "%d", &ip_mode);
#else
			sscanf(argv[++i], "%d", &ip_mode);
#endif
		} else if (strcmp(argv[i], "-help") == 0) {
			SampleUtil_Print(
				"Usage: %s -i interface -port port"
				" -desc desc_doc_name "
				" -ca_pkey public_key_ca"
				" -ra_pkey private_key_ra"
				" -webdir web_dir_path"
				" -m ip_mode -help (this message)\n",
				argv[0]);
			SampleUtil_Print(
				"\tinterface:      interface address of the  device"
				" (must match desc. doc)\n"
				"\t\t\te.g.: eth0\n"
				"\tport:           Port number to use for"
				" receiving UPnP messages (must match desc. "
				"doc)\n"
				"\t\t\te.g.: 5431\n"
				"\tdesc_doc_name:  name of device description document\n"
				"\t\t\te.g.: radesc.xml\n"
				"\tpublic_key_ca:  PEM filepath of CA public key\n"
				"\t\t\te.g.: public_key.pem\n"
				"\tprivate_key_ra: PEM filepath of RA private key\n"
				"\t\t\te.g.: private_key.pem\n"
				"\tweb_dir_path:   Filesystem path where web files"
				" related to the device are stored\n"
				"\t\t\te.g.: /upnp/sample/web\n"
				"\tip_mode:        set to 1 for IPv4 (default), "
				"2 for IPv6 LLA and 3 for IPv6 ULA or GUA\n");
			return 1;
		}
	}
	port = (unsigned short)portTemp;
	return RAStart(iface,
		port,
		desc_doc_name,
		public_key_ca,
		private_key_ra,
		web_dir_path,
		ip_mode,
		linux_print);
}

/*! @} Device Sample Module */

/*! @} UpnpSamples */
