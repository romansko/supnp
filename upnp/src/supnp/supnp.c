/*!
 * \addtogroup SUPnP
 *
 * \file supnp.c
 *
 * \brief source file for SUPnP secure layer method. Implementing logics from
 * the paper "Kayas, G., Hossain, M., Payton, J., & Islam, S. R. (2021). SUPnP:
 * Secure Access and Service Registration for UPnP-Enabled Internet of Things.
 * IEEE Internet of Things Journal, 8(14), 11561-11580."
 *
 * \author Roman Koifman
 */
#include "upnpconfig.h"

#if ENABLE_SUPNP

#include "file_utils.h"
#include "openssl_wrapper.h"
#include "service_table.h"
#include "upnptools.h"
#include <cJSON/cJSON.h>
#include <ixml.h>
#include "supnp.h"
#include "supnp_device.h"
#include "supnp_common.h"
#include "openssl_error.h"
#include "stdio.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Globals */
int gCurrentDeviceType = -1;
EVP_PKEY *gDevicePKey = NULL;  /* Device's private & public key pair */
EVP_PKEY *gRAPublicKey = NULL; /* Registration Authority Public Key */
ithread_rwlock_t gDeviceTypeLock;
ithread_rwlock_t gDeviceKeyLock;
ithread_rwlock_t gRAKeyLock;
/**/

#define supnp_extract_json_string(doc, key, value, label) \
{ \
    value = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(doc, key)); \
    supnp_verify(value, label, "Unexpected '%s'\n", key); \
}

void setDeviceType(const EDeviceType devType)
{
    ithread_rwlock_wrlock(&gDeviceTypeLock);
    gCurrentDeviceType = devType;
    ithread_rwlock_unlock(&gDeviceTypeLock);
}

int SUpnpGetDeviceType()
{
    ithread_rwlock_rdlock(&gDeviceTypeLock);
    const int type = gCurrentDeviceType;
    ithread_rwlock_unlock(&gDeviceTypeLock);
    return type;
}

/*!
 * \brief Get the Device's Public & Private Key pair copy.
 * Caller is responsible for freeing the returned key.
 *
 * \return Device's Public Key.
 */
EVP_PKEY *getDevicePKey()
{
    EVP_PKEY *pkey = NULL;
    ithread_rwlock_rdlock(&gDeviceKeyLock);
    if (gDevicePKey) {
        pkey = EVP_PKEY_dup(gDevicePKey);
    }
    ithread_rwlock_unlock(&gDeviceKeyLock);
    return pkey;
}

/*!
 * \brief Get the RA's Public Key copy.
 * Caller is responsible for freeing the returned key.
 *
 * \return RA's Public Key.
 */
EVP_PKEY *getRAPKey()
{
    EVP_PKEY *pkey = NULL;
    ithread_rwlock_rdlock(&gRAKeyLock);
    if (gRAPublicKey) {
        pkey = EVP_PKEY_dup(gRAPublicKey);
    }
    ithread_rwlock_unlock(&gRAKeyLock);
    return pkey;
}

void setDevicePKey(EVP_PKEY *pkey)
{
    ithread_rwlock_wrlock(&gDeviceKeyLock);
    if (gDevicePKey && (gDevicePKey != pkey)) {
        EVP_PKEY_free(gDevicePKey);
    }
    gDevicePKey = pkey;
    ithread_mutex_unlock(&gDeviceKeyLock);
}

void setRAPublicKey(EVP_PKEY *pkey)
{
    ithread_rwlock_wrlock(&gRAKeyLock);
    if (gRAPublicKey && (gRAPublicKey != pkey)) {
        EVP_PKEY_free(gRAPublicKey);
    }
    gRAPublicKey = pkey;
    ithread_mutex_unlock(&gRAKeyLock);
}


int SUpnpInit(const char *IfName, const unsigned short DestPort,
    const char *privateKeyPath, const int devType)
{
    supnp_log("Initializing SUPnP secure layer..\n");

    switch(devType) {
        case eDeviceType_SD:
        case eDeviceType_CP:
        case eDeviceType_RA:
            setDeviceType(devType);
            break;
        default:
            supnp_error("Invalid device type %d.\n", devType);
            goto cleanup;;
    }

    /* Initialize OpenSSL Wrapper */
    // todo maybe UpnpInitSslContext ?
    supnp_verify(OpenSslInitializeWrapper() == OPENSSL_SUCCESS, cleanup,
        "Error initializing OpenSSL.\n");

    /* Load key pair (public key is generated from private key) */
    EVP_PKEY *pkey = OpenSslLoadPrivateKeyFromPEM(privateKeyPath);
    supnp_verify(pkey, cleanup, "Error loading private key from '%s'.\n",
        privateKeyPath);
    setDevicePKey(pkey); /* Set global, no free */

    return UpnpInit2(IfName, DestPort);

cleanup:
    return SUPNP_E_INTERNAL_ERROR;
}

int SUpnpFinish()
{
    ithread_mutex_lock(&gDeviceKeyLock);
    freeif(gDevicePKey);
    ithread_mutex_unlock(&gDeviceKeyLock);
    ithread_mutex_lock(&gRAKeyLock);
    freeif(gRAPublicKey);
    ithread_mutex_unlock(&gRAKeyLock);
    return UpnpFinish();
}


char *SUpnpGetFirstElementItem(IXML_Element *element, const char *item)
{
	IXML_NodeList *nodeList = NULL;
	IXML_Node *textNode = NULL;
	IXML_Node *tmpNode = NULL;
	char *ret = NULL;

	nodeList = ixmlElement_getElementsByTagName(element, (char *)item);
    supnp_verify(nodeList, cleanup, "Error finding %s in XML Node\n", item);

	tmpNode = ixmlNodeList_item(nodeList, 0);
    supnp_verify(tmpNode, cleanup, "Error finding %s value in XML Node\n", item);

	textNode = ixmlNode_getFirstChild(tmpNode);
	ret = strdup(ixmlNode_getNodeValue(textNode));
    supnp_verify(ret, cleanup, "Error allocating memory for %s in XML Node\n", item);

cleanup:
    freeif2(nodeList, ixmlNodeList_free);
	return ret;
}

/**
 * DSD/SAD Verification process. Figure 15, SUPnP paper.
 * Steps 2-3.
 * @param ca_pkey CA public key
 * @param p_dev Device info
 * @return SUPNP_E_SUCCESS on success. Error code otherwise.
 */
int SUpnpVerifyDocument(EVP_PKEY* ca_pkey, supnp_device_t* p_dev)
{
    int ret = SUPNP_E_INVALID_ARGUMENT;
    int x, y;
    char* dev_name = NULL;
    char* dev_type = NULL;
    char* in_doc_pkey = NULL; /* Device public key within the document */
    char* sig_ver_con = NULL; /* Signatures Verification Conditions */
    char* data = NULL;
    EVP_PKEY* pkey = NULL;
    EVP_PKEY* doc_pk = NULL;
    service_table services;

    /* Arguments Verification */
    supnp_verify(ca_pkey, cleanup,  "NULL CA public key provided.\n");
    supnp_verify(p_dev, cleanup, "NULL device provided.\n");

    /* Read SUPnP document name & type */
    ret = SUPNP_E_INVALID_DOCUMENT;
    supnp_verify(p_dev->supnp_doc, cleanup, "NULL SAD/DSD provided.\n");
    supnp_extract_json_string(p_dev->supnp_doc, SUPNP_DOC_NAME, dev_name, cleanup);
    supnp_extract_json_string(p_dev->supnp_doc, SUPNP_DOC_TYPE, dev_type, cleanup);
    if (!strcmp("CP", dev_type)) {
        p_dev->type = eDeviceType_CP;
    } else if (!strcmp("SD", dev_type)) {
        p_dev->type = eDeviceType_SD;
    } else {
        supnp_verify(NULL, cleanup, "Invalid device type '%s'.\n", dev_type);
    }
    supnp_log("Verifying %s document. Type: '%s'.\n", dev_name, dev_type);

    /* Fig.15 step 2 - Verify UCA Certificate using CA's public key */
    ret = SUPNP_E_INVALID_CERTIFICATE;
    supnp_verify(p_dev->uca_cert, cleanup, "NULL UCA Certificate provided.\n");
    supnp_verify(OpenSslVerifyCertificate("UCA", p_dev->uca_cert, ca_pkey) == OPENSSL_SUCCESS, cleanup, "Invalid UCA cert.\n");

    /* Fig.15 step 2 - Verify Device Certificate using UCA's public key */
    supnp_verify(OpenSslVerifyCertificate(dev_name, p_dev->dev_cert, p_dev->uca_pkey) == OPENSSL_SUCCESS, cleanup, "Invalid Device cert.\n");

    /* Verify Device Public Key */
    ret = SUPNP_E_INVALID_DOCUMENT;
    supnp_extract_json_string(p_dev->supnp_doc, SUPNP_DOC_PUBLIC_KEY, in_doc_pkey, cleanup);
    doc_pk = OpenSslLoadPublicKeyFromHex(in_doc_pkey);
    supnp_verify(doc_pk, cleanup, "Error loading public key from '%s'.\n", SUPNP_DOC_PUBLIC_KEY);
    supnp_verify(EVP_PKEY_eq(doc_pk, p_dev->dev_pkey) == OPENSSL_SUCCESS, cleanup,
                 "Document's device public key doesn't match Device certificate's public key.\n");

    /* Retrieve signature verification conditions */
    supnp_extract_json_string(p_dev->supnp_doc, SUPNP_DOC_SIG_CON, sig_ver_con, cleanup);
    supnp_verify(sscanf(sig_ver_con, "%d-of-%d", &x, &y) == 2, cleanup,
                 "Error parsing Signature Verification Conditions '%s'.\n", SUPNP_DOC_SIG_CON);
    supnp_verify(x >= 0 && y >= 0 && x <= y, cleanup, "Invalid Signature Verification Conditions '%s'.\n",
                 SUPNP_DOC_SIG_CON);
    supnp_log("Signature Verification Conditions: %d-of-%d\n", x, y);

    /* Retrieve Signatures */
    const cJSON* sigs = cJSON_GetObjectItemCaseSensitive(p_dev->supnp_doc, SUPNP_DOC_SIGNATURES);
    supnp_verify(cJSON_IsArray(sigs), cleanup, "Unexpected '%s'\n", SUPNP_DOC_SIGNATURES);
    supnp_verify(cJSON_GetArraySize(sigs) == y, cleanup,
                 "Unexpected number of signatures in '%s'\n", SUPNP_DOC_SIGNATURES);
    if (x == 0)
    {
        ret = SUPNP_E_SUCCESS;
        supnp_log("Signatures verification is not required.\n");
        goto cleanup; /* Done */
    }

    /* Delete signatures from document, leaving only the content. */
    cJSON* doc_content = cJSON_Duplicate(p_dev->supnp_doc, 1);
    cJSON_DeleteItemFromObjectCaseSensitive(doc_content, SUPNP_DOC_SIG_OWNER);
    cJSON_DeleteItemFromObjectCaseSensitive(doc_content, SUPNP_DOC_SIG_UCA);
    data = cJSON_PrintUnformatted(doc_content);

    /* Verify Signatures */
    for (int sig_index = 0; sig_index < cJSON_GetArraySize(sigs); ++sig_index)
    {
        char* sig_name = cJSON_GetStringValue(cJSON_GetArrayItem(sigs, sig_index));
        if (strcmp(sig_name, SUPNP_DOC_SIG_OWNER) == 0)
        {
            pkey = p_dev->dev_pkey;
        }
        else if (strcmp(sig_name, SUPNP_DOC_SIG_UCA) == 0)
        {
            pkey = p_dev->uca_pkey;
        }
        else
        {
            supnp_error("Unexpected signature name '%s'\n", sig_name);
            ret = SUPNP_E_INVALID_DOCUMENT;
            break;
        }
        /* Extract the hex string signature and convert it to bytes */
        const char* signature = cJSON_GetStringValue(
            cJSON_GetObjectItemCaseSensitive(p_dev->supnp_doc, sig_name));
        if (OpenSslVerifySignature(sig_name, pkey, signature, (unsigned char*)data, strlen(data)) != OPENSSL_SUCCESS)
        {
            ret = SUPNP_E_INVALID_DOCUMENT;
            break;
        }
        supnp_log("'%s' signature ok.\n", sig_name);
    }

    /* Done verification for CP */
    if (p_dev->type == eDeviceType_CP)
    {
        supnp_log("Control Point's SAD ok.\n");
        ret = SUPNP_E_SUCCESS;
        goto cleanup;
    }

    /**
     * Verify Services ONLY for SD.
     * The RA retrieves the device description document of the SD.
     * The RA matches the services provided by the SD with its HW and SW specification included in the DSD.
     * The RA uses an attribute ledger to perform the validation.
     * The ledger maintains a mapping between a service type and the HW and SW attributes require to provide the service.
     * todo: verify that the capability of an SD matches its DDD. Maintain Ledger.
     */
    supnp_verify(p_dev->desc_doc_name, cleanup, "NULL description URI.\n");
    supnp_verify(p_dev->desc_doc, cleanup, "NULL description document.\n");
    const cJSON* json_services = cJSON_GetObjectItemCaseSensitive(p_dev->supnp_doc, SUPNP_DOC_SERVICES);
    supnp_verify(json_services, cleanup, "Couldn't find services tagname '%s' in SUPnP Document.\n", SUPNP_DOC_SERVICES);

    ret = getServiceTable((IXML_Node*)p_dev->desc_doc, &services, p_dev->desc_doc_name);
    supnp_verify(ret, cleanup, "Couldn't fill service table.\n");
    const int json_count = cJSON_GetArraySize(json_services);
    const int services_number = CountServices(&services);
    supnp_verify(services_number == json_count, cleanup,
                 "Number of services in SUPnP Document (%d) doesn't match the number of services in description document (%d).\n",
                 json_count, services_number);

    ret = SUPNP_E_SUCCESS;
    for (const service_info * service = services.serviceList; service != NULL; service = service->next)
    {
        cJSON* _json_service = cJSON_GetObjectItemCaseSensitive(json_services, service->serviceId);
        supnp_verify(_json_service, error, "Couldn't find service id '%s' in SUPnP Document.\n", service->serviceId);
        supnp_verify(strcmp(_json_service->valuestring, service->serviceType) == 0, error,
                     "Unexpected service type for service id '%s': '%s' vs '%s'\n", service->serviceId,
                     _json_service->valuestring, service->serviceType);
        continue;
    error:
        ret = SUPNP_E_INVALID_DOCUMENT;
        break;
    }
    supnp_verify(ret == SUPNP_E_SUCCESS, cleanup, "Services verification failed (SD).\n");
    supnp_log("SD Services ok.\n");
    supnp_log("Service Device's DSD ok.\n");

    /* SD Verification Done */
    ret = SUPNP_E_SUCCESS;

cleanup:
    freeif(data);
    freeif2(doc_pk, EVP_PKEY_free);
    if (p_dev && p_dev->type == eDeviceType_SD) {
        /* freeServiceTable, with protection */
        freeif2(services.URLBase, ixmlFreeDOMString)
        freeif2(services.endServiceList, freeServiceList);
    }
    return ret;
}



/**
* @brief Send a RA Action Register request to the RA service.
* The logics correspond to figure 15 in the SUPnP paper.
* Steps 7+8 are actually singing process. signature = E(sk, H(nonce))
*/
int sendRAActionRegister(RegistrationParams *params, const char *controlUrl)
{
    int rc = SUPNP_E_INTERNAL_ERROR;
    char *pk_hex = NULL; /* Public key hex string */
    IXML_Document *actionNode = NULL;
    IXML_Document *respNode = NULL;
    char *docs[SUPNP_DOCS_ON_DEVICE] = {NULL};
    char *docs_hex[SUPNP_DOCS_ON_DEVICE] = {NULL};
    size_t docs_size[SUPNP_DOCS_ON_DEVICE] = {0};
    char *response = NULL;
    unsigned char *challenge = NULL;
    unsigned char *nonce = NULL;
    unsigned char *signature = NULL;
    char *hex_sig = NULL;
    size_t size;
    size_t nonce_len = 0;
    size_t sig_len = 0;
    cJSON *capToken = NULL;
    EVP_PKEY *device_pkey = NULL;
    char *ra_pk = NULL;

    supnp_verify(params, cleanup, "NULL Registration Params.\n");
    supnp_verify(controlUrl, cleanup, "NULL Control URL.\n");

    size_t pkb_size;     /* Public key bytes size */
    device_pkey = getDevicePKey();
    unsigned char * pkb = OpenSslPublicKeyToBytes(device_pkey, &pkb_size);
    pk_hex = OpenSslBinaryToHexString(pkb, pkb_size);
    freeif(pkb);
    supnp_verify(pk_hex, cleanup, "Error converting public key to hex string.\n");

    for (int i = 0; i < SUPNP_DOCS_ON_DEVICE; ++i) {
        docs[i] = read_file(params->RegistrationDocsPath[i], "rb", &docs_size[i]);
        supnp_verify(docs[i] != NULL, cleanup, "Error reading Registration Document ID %d\n", i);
        docs_hex[i] = OpenSslBinaryToHexString((unsigned char *)docs[i], docs_size[i]);
        supnp_verify(docs_hex[i] != NULL, cleanup, "Error converting to hex string Registration Document ID %d\n", i);
        rc = UpnpAddToAction(&actionNode,
            RaRegistrationAction[eRegisterServiceAction_Register],
            RaServiceType[eRegistrationAuthorityService_Register],
            RaRegisterActionVarName[i],
            docs_hex[i]);
        supnp_verify(rc == UPNP_E_SUCCESS, cleanup, "Error trying to add registration action param\n");
    }

    /* Add Device URL */
    supnp_verify(params->deviceUrl, cleanup, "NULL Device URL.\n");
    rc = UpnpAddToAction(&actionNode,
        RaRegistrationAction[eRegisterServiceAction_Register],
        RaServiceType[eRegistrationAuthorityService_Register],
        RaRegisterActionVarName[eRegisterActionVar_DeviceURL],
        params->deviceUrl);
    supnp_verify(rc == UPNP_E_SUCCESS, cleanup, "Error trying to add de description document url\n");

    /* Add Description Document Name, if applicable. */
    if (params->descDocFilename) {
        rc = UpnpAddToAction(&actionNode,
            RaRegistrationAction[eRegisterServiceAction_Register],
            RaServiceType[eRegistrationAuthorityService_Register],
            RaRegisterActionVarName[eRegisterActionVar_DescDocFileName],
            params->descDocFilename);
        supnp_verify(rc == UPNP_E_SUCCESS, cleanup, "Error trying to add Description Document Filename\n");
    }

    /* Add CapToken Filename */
    supnp_verify(params->capTokenFilename, cleanup, "NULL CapToken Filename.\n");
    rc = UpnpAddToAction(&actionNode,
        RaRegistrationAction[eRegisterServiceAction_Register],
        RaServiceType[eRegistrationAuthorityService_Register],
        RaRegisterActionVarName[eRegisterActionVar_CapTokenFilename],
        params->capTokenFilename);
    supnp_verify(rc == UPNP_E_SUCCESS, cleanup, "Error trying to add CapToken Filename\n");

    rc = UpnpSendAction(params->handle,
        controlUrl,
        RaServiceType[eRegistrationAuthorityService_Register],
        NULL, /* UDN ignored & Must be NULL */
        actionNode,
        &respNode);
    supnp_verify(rc == UPNP_E_SUCCESS, cleanup, "Error in UpnpSendAction -- %d\n", rc);

    rc = SUPNP_E_INTERNAL_ERROR;

    /* Extract Challenge from respNode */
    response = SUpnpGetFirstElementItem((IXML_Element*)respNode,
        RaChallengeActionVarName[eChallengeActionVar_Challenge]);
    challenge = OpenSslHexStringToBinary(response, &size);
    supnp_verify(challenge, cleanup, "Error extracting challenge.\n");

    /* Decrypt the challenge using the participant's private key */
    nonce = OpenSslAsymmetricDecryption(device_pkey, &nonce_len, challenge, size);
    supnp_verify(nonce, cleanup, "Error decrypting nonce.\n");
    supnp_verify(nonce_len == SHA256_DIGEST_LENGTH, cleanup, "Unexpected nonce length.\n");

    /* Signature = E(sk, H(nonce)) */
    signature = OpenSslSign(device_pkey, nonce, nonce_len, &sig_len);
    supnp_verify(signature, cleanup, "Error signing nonce E(sk, H(nonce)).\n");

    /* To Hex String */
    hex_sig = OpenSslBinaryToHexString(signature, sig_len);

    /* Send E(sk,H(n)) to RA */
    freeif2(actionNode, ixmlDocument_free);
    freeif2(respNode, ixmlDocument_free);
    rc = UpnpAddToAction(&actionNode,
        RaRegistrationAction[eRegisterServiceAction_Challenge],
        RaServiceType[eRegistrationAuthorityService_Register],
        RaChallengeActionVarName[eChallengeActionVar_Challenge],
        hex_sig);
    supnp_verify(rc == UPNP_E_SUCCESS, cleanup, "Error trying to add challenge action challenge param.\n");

    rc = UpnpAddToAction(&actionNode,
        RaRegistrationAction[eRegisterServiceAction_Challenge],
        RaServiceType[eRegistrationAuthorityService_Register],
        RaChallengeActionVarName[eChallengeActionVar_PublicKey],
        pk_hex);
    supnp_verify(rc == UPNP_E_SUCCESS, cleanup, "Error trying to add challenge action public key param.\n");

    rc = UpnpSendAction(params->handle,
            controlUrl,
            RaServiceType[eRegistrationAuthorityService_Register],
            NULL, /* UDN ignored & Must be NULL */
            actionNode,
            &respNode);
    supnp_verify(rc == UPNP_E_SUCCESS, cleanup, "Error in UpnpSendAction -- %d\n", rc);

    /* Check Challenge Response Status */
    freeif(response);
    response = SUpnpGetFirstElementItem((IXML_Element*)respNode, ActionResponseVarName);
    supnp_verify(response, cleanup, "Error extracting response.\n");
    if (strcmp(response, ActionSuccess) == 0) {
        rc = eRegistrationStatus_DeviceRegistered;
    } else {
        rc = (int)strtol(response, NULL, 10);
    }
    supnp_verify(rc == eRegistrationStatus_DeviceRegistered, cleanup, "Registration Failed: %s\n", response);

    /* Extract Cap Token */
    rc = SUPNP_E_CAPTOKEN_ERROR;
    freeif(response);
    response = SUpnpGetFirstElementItem((IXML_Element*)respNode, CapTokenResponseVarName);
    supnp_verify(response, cleanup, "Error extracting CapToken.\n");
    capToken = capTokenFromHexString(response);
    supnp_verify(capToken, cleanup, "Error converting CapToken from hex string.\n");
    char filepath[256];
    sprintf(filepath, "web/%s", params->capTokenFilename); // todo: configure filepath in SUPnP init
    supnp_verify(storeCapToken(capToken, filepath) == FILE_OP_OK, cleanup, "Error storing CapToken.\n");

    /* Load RA Public Key */
    supnp_verify(ra_pk == NULL, cleanup, "RA Public Key already loaded! "
        "Registering should be performed only once.\n");
    ra_pk = extractCapTokenFieldValue(capToken, eCapTokenPublicKeyRA);
    supnp_verify(ra_pk, cleanup, "Error extracting RA Public Key.\n");

    EVP_PKEY *ra_pkey = OpenSslLoadPublicKeyFromHex(ra_pk);
    supnp_verify(ra_pkey, cleanup, "Error loading RA Public Key.\n");
    setRAPublicKey(ra_pkey);  /* RA is set in global, hence no free */

    rc = eRegistrationStatus_DeviceRegistered;

cleanup:
    OpenSslFreePKey(&device_pkey);
    freeif(ra_pk);
    freeif(pk_hex);
    freeif2(actionNode, ixmlDocument_free);
    freeif2(respNode, ixmlDocument_free);
    for (int i = 0; i < SUPNP_DOCS_ON_DEVICE; ++i) {
        freeif(docs[i]);
        freeif(docs_hex[i]);
    }
    freeif(response);
    freeif(challenge);
    freeif(nonce);
    freeif(signature);
    freeif(hex_sig);
    return rc;
}

int RegistrationCallbackEventHandler(Upnp_EventType eventType, const void *event, void *cookie)
{
    service_table services;
    static ERegistrationStatus status = eRegistrationStatus_DeviceUnregistered;
    int errCode = SUPNP_E_SUCCESS;
    IXML_Document *ra_desc_doc = NULL;
    const UpnpDiscovery *d_event = (UpnpDiscovery *)event;
    const char *location = NULL;
    RegistrationParams *params = cookie;

    if (eventType != UPNP_DISCOVERY_SEARCH_RESULT)
        return SUPNP_E_SUCCESS;  /* Ignore */

    if (status == eRegistrationStatus_DeviceRegistered)
        return SUPNP_E_SUCCESS;  /* Ignore */

    supnp_verify(d_event, cleanup, "NULL Discovery event.\n");
    supnp_verify(params, cleanup, "NULL params.\n");

    /* Retrieve RA Description Document */
    errCode = UpnpDiscovery_get_ErrCode(d_event);
    supnp_verify(errCode == UPNP_E_SUCCESS, cleanup, "Error in Discovery Callback -- %d\n", errCode);
    location = UpnpString_get_String(UpnpDiscovery_get_Location(d_event));
    errCode = UpnpDownloadXmlDoc(location, &ra_desc_doc);
    supnp_verify(errCode == UPNP_E_SUCCESS, cleanup, "Error in UpnpDownloadXmlDoc -- %d\n", errCode);

    /* Register the device if it is not already registered */
    errCode = strcmp(SUpnpGetFirstElementItem((IXML_Element*)ra_desc_doc, "deviceType"), RaDeviceType);
    supnp_verify(errCode == 0, cleanup, "Unexpected device type.\n");

    if (status != eRegistrationStatus_DeviceRegistered) {
        /* Extract Services List */
        errCode = getServiceTable((IXML_Node*)ra_desc_doc, &services, location);
        supnp_verify(errCode, cleanup, "Couldn't fill service table.\n");

        /* Iterate Services and parse registration service */
        for (const service_info * service = services.serviceList; service != NULL; service = service->next) {
            char* controlURL = NULL;
            if (UpnpResolveURL2(location, service->controlURL, &controlURL) != UPNP_E_SUCCESS) {
                supnp_error("Error generating controlURL from %s + %s\n", location, service->controlURL);
            } else if (strcmp(service->serviceType, RaServiceType[eRegistrationAuthorityService_Register]) == 0) {
                // Send the DSD to the RA
                errCode = sendRAActionRegister(params, controlURL);
                break;
            }
            freeif(controlURL);
            service = service->next;
        }

        if (errCode == eRegistrationStatus_DeviceRegistered) {
            supnp_log("SUPnP Device Registered\n");
            status = eRegistrationStatus_DeviceRegistered;
            UpnpUnRegisterClient(params->handle);
            params->callback(params->callback_cookie);
        } else {
            supnp_error("Error registering SUPnP device. Code: (%d).\n", errCode);
        }
    }
cleanup:
    freeServiceTable(&services);
    freeif2(ra_desc_doc, ixmlDocument_free);
    SUpnpFreeRegistrationParamsContent(params);
    return errCode;
}


/**
 * Register a device with RA. Handles Register & Challenge actions.
 * @param RegistrationDocsPath Array of paths to the device's registration documents.
 * @param capTokenFilename CapToken filename.
 * @param device_url The device's URL.
 * @param desc_doc_name The device's description document name.
 * @param timeout The timeout for the registration process.
 * @param callback The callback function to be called upon registration completion.
 * @param callback_cookie The cookie to be passed to the callback function.
 * @return SUPNP_E_SUCCESS on success. Error code otherwise.
 */
int SUpnpRegisterDevice(
    const char *RegistrationDocsPath[],
    const char *capTokenFilename,
    char *device_url,     /* Expected heap allocated string */
    char *desc_doc_name,  /* Expected heap allocated string */
    int timeout,
    SUpnp_FunPtr callback,
    void *callback_cookie)
{
    int ret = SUPNP_E_SUCCESS;

    /* Verify Params */
    supnp_verify(RegistrationDocsPath, cleanup, "NULL Registration Docs Paths.\n");
    supnp_verify(capTokenFilename, cleanup, "NULL CapToken Filename.\n");
    supnp_verify(device_url, cleanup, "NULL device URL.\n");

    /* Set Registration Params */
    RegistrationParams *params = malloc(sizeof(RegistrationParams));
    supnp_verify(params, cleanup, "Error allocating memory for registration params.\n");
    params->handle = -1;
    params->callback = callback;
    params->callback_cookie = callback_cookie;
    for (int i = 0; i < SUPNP_DOCS_ON_DEVICE; ++i) {
        supnp_verify(RegistrationDocsPath[i], cleanup, "NULL %s.\n", RaRegisterActionVarName[i]);
        params->RegistrationDocsPath[i] = RegistrationDocsPath[i];
    }
    params->capTokenFilename = capTokenFilename;

    /* Expected heap allocated strings */
    params->deviceUrl = device_url;
    params->descDocFilename = desc_doc_name; /* Applicable only for SD, for CP set NULL */

    /* Register registration handle with UPnP SDK */
    ret = UpnpRegisterClient(RegistrationCallbackEventHandler, params, &(params->handle));
    supnp_verify(ret == UPNP_E_SUCCESS, cleanup, "Error registering registration handle with sdk: %d\n", ret);

    /* Send RA Discovery Message */
    ret = UpnpSearchAsync(params->handle, timeout, RaDeviceType,
        NULL, NULL, NULL, NULL, /* Secure Discovery Not Applicable */
        params);
    supnp_verify(ret == UPNP_E_SUCCESS, cleanup, "Error sending RA discovery message (%d)\n", ret);

    return SUPNP_E_SUCCESS; /* Success */

cleanup:
    SUpnpFreeRegistrationParams(&params);
    if (params->handle != -1)
        (void) UpnpUnRegisterClient(params->handle);
    return ret;
}

/**
 * Free Registration Params Content
 * @param params Registration Params
 */
void SUpnpFreeRegistrationParamsContent(RegistrationParams *params)
{
    if (!params)
        return;
    // todo consider strdup instead of const paths
#if 0
    freeif(params->publicKeyPath);
    freeif(params->privateKeyPath);
    for (int i = 0; i < SUPNP_DOCS_ON_DEVICE; ++i) {
        freeif(params->RegistrationDocsPath[i]);
    }
#endif
    freeif(params->deviceUrl);
    freeif(params->descDocFilename);
}

/**
 * Free Registration Params
 * @param params Registration Params
 */
void SUpnpFreeRegistrationParams(RegistrationParams **params)
{
    SUpnpFreeRegistrationParamsContent(*params);
    freeif(*params);
}

/**
 * Handles Secure Service Advertisement verifications. Fig 17, SUPnP paper.
 * This function should be called by a Control Point.
 * @param hexSignature The Advertisement signature in hex string format.
 * @param descDocUrl The description document URL.
 * @param capTokenUrl Target Device CapToken URL.
 * @param deviceCapTokenString Current Device CapToken.
 * @return SUPNP_E_SUCCESS on success. Error code otherwise.
 */
int SUpnpSecureServiceAdvertisementVerify(const char *hexSignature,
    const char *descDocUrl,
    const char *capTokenUrl,
    const char *deviceCapTokenString)
{
    int ret = SUPNP_E_INVALID_ARGUMENT;
    char *concatenate_url = NULL;
    char *ra_pk_hex = NULL;
    EVP_PKEY *ra_pk = NULL;
    IXML_Document *pDescDoc = NULL;
    captoken_t *pDeviceCapToken = NULL;
    captoken_t *pTargetCapToken = NULL;
    char *desc_doc_content = NULL;

    supnp_log("Verifying Secure Service Advertisement ..\n");

    supnp_verify(hexSignature != NULL, cleanup, "NULL hexSignature\n");
    supnp_verify(descDocUrl != NULL, cleanup, "NULL descDocUrl\n");
    supnp_verify(capTokenUrl != NULL, cleanup, "NULL capTokenUrl\n");
    supnp_verify(deviceCapTokenString != NULL, cleanup, "NULL deviceCapTokenString\n");

    /* Load RA Public Key from current Device Cap Token */
    pDeviceCapToken = loadCapTokenString(deviceCapTokenString);
    supnp_verify(pDeviceCapToken, cleanup, "Error converting Device CapToken from string.\n");
    ra_pk_hex = extractCapTokenFieldValue(pDeviceCapToken, eCapTokenPublicKeyRA);
    ra_pk = OpenSslLoadPublicKeyFromHex(ra_pk_hex);
    supnp_verify(ra_pk, cleanup, "Error loading RA Public Key\n");

    /* Concatenate (description url || cap token url) */
    concatenate_url = malloc(strlen(descDocUrl) + strlen(capTokenUrl) + 1);
    supnp_verify(concatenate_url, cleanup, "concatenate_url memory allocation failed\n");
    strcpy(concatenate_url, descDocUrl);
    strcat(concatenate_url, capTokenUrl);

    /* Verify the Advertisement Signature (Fig 17 - Secure Advertisement) */
    supnp_log("Verifying Secure Service Advertisement..\n");
    ret = OpenSslVerifySignature("Advertisement Signature", ra_pk, hexSignature, (const unsigned char*)concatenate_url, strlen(concatenate_url));
    supnp_verify(ret == OPENSSL_SUCCESS, cleanup, "!!! Advertisement signature is forged !!!\n");
    supnp_log("Advertisement Signature verified successfully.\n");

    /* Download Description Document */
    ret = UpnpDownloadXmlDoc(descDocUrl, &pDescDoc);
    supnp_verify(ret == UPNP_E_SUCCESS, cleanup, "Error in UpnpDownloadXmlDoc -- %d\n", ret);

    /* Download CapToken */
    ret = downloadCapToken(capTokenUrl, &pTargetCapToken);
    supnp_verify(ret == UPNP_E_SUCCESS, cleanup, "Error in downloadCapToken -- %d\n", ret);

    /* Secure Device Description - Fig17, SUPnP paper. */
    desc_doc_content = ixmlDocumenttoString(pDescDoc);
    ret = verifyCapToken(pTargetCapToken, ra_pk, desc_doc_content);
    supnp_verify(ret == SUPNP_E_SUCCESS, cleanup, "!!! Secure Device Description failed !!! Error in verifyCapToken -- %d\n", ret);
    supnp_log("Secure Device Description successful.\n");

    ret = SUPNP_E_SUCCESS;

cleanup:
    freeif(ra_pk_hex);
    freeif(desc_doc_content);
    freeif(concatenate_url);
    freeif2(ra_pk, EVP_PKEY_free);
    freeif2(pDescDoc, ixmlDocument_free);
    freeCapToken(&pTargetCapToken);
    freeCapToken(&pDeviceCapToken);
    return ret;
}

/* Fig 18 - CP Side */
int SUpnpSecureServiceDiscoverySend(const int handle,
    const int searchTime,
    const char *target,
    const char *capTokenString,
    const char *capTokenLocation)
{
    unsigned char *nonce = NULL;
    char *nonce_hex = NULL;
    captoken_t *cap_token = NULL;
    char *capTokenLocationSig = NULL;
    unsigned char *nonce_sig = NULL;
    size_t sig_len = 0;
    char *nonce_sig_hex = NULL;
    EVP_PKEY *device_pkey = NULL;
    int ret = SUPNP_E_INVALID_ARGUMENT;

    supnp_log("Sending Secure Service Discovery..\n");

    supnp_verify(target, cleanup, "NULL Target\n");
    supnp_verify(capTokenString, cleanup, "NULL CapToken\n");
    supnp_verify(capTokenLocation, cleanup, "NULL CapToken Location\n");

    ret = SUPNP_E_INTERNAL_ERROR;

    /* Load Cap Token */
    cap_token = loadCapTokenString(capTokenString);
    supnp_verify(cap_token, cleanup, "Error converting CapToken from string.\n");

    /* Extract Cap Token Location Signature (HEX String) */
    capTokenLocationSig = extractCapTokenFieldValue(cap_token, eCapTokenSignatureLocation);
    supnp_verify(capTokenLocationSig, cleanup, "Error extracting CapToken Location Signature.\n");

    /* Nonce */
    nonce = OpenSslGenerateNonce(OPENSSL_CSPRNG_SIZE);
    supnp_verify(nonce, cleanup, "Error generating nonce of size %d.\n", OPENSSL_CSPRNG_SIZE);
    nonce_hex = OpenSslBinaryToHexString(nonce, OPENSSL_CSPRNG_SIZE);
    supnp_verify(nonce_hex, cleanup, "Error converting nonce to hex string.\n");

    /* Nonce signature */
    device_pkey = getDevicePKey();
    nonce_sig = OpenSslSign(device_pkey, nonce, OPENSSL_CSPRNG_SIZE, &sig_len);
    supnp_verify(nonce_sig, cleanup, "Error signing nonce.\n");
    nonce_sig_hex = OpenSslBinaryToHexString(nonce_sig, sig_len);
    supnp_verify(nonce_sig_hex, cleanup, "Error converting nonce signature to hex string.\n");

    /* Invoke Secure Discovery */
    ret = UpnpSearchAsync(handle, searchTime, target,
        capTokenLocation,
        capTokenLocationSig,
        nonce_hex,
        nonce_sig_hex,
        NULL);

cleanup:
    OpenSslFreePKey(&device_pkey);
    freeif(nonce_sig_hex);
    freeif(nonce_sig);
    freeif(capTokenLocationSig);
    freeCapToken(&cap_token);
    freeif(nonce_hex);
    freeif(nonce);
    return ret;
}


int SUpnpSecureServiceDiscoveryVerify(
    const char *capTokenLocation,
    const char *capTokenLocationSignature,
    const char *hexNonce,
    const char *discoverySignature)
{
    int ret = SUPNP_E_INVALID_ARGUMENT;
    unsigned char *nonce = NULL;
    size_t nonce_len;
    captoken_t *CapToken = NULL;
    char *cp_pk = NULL;
    EVP_PKEY *cp_pkey = NULL;
    EVP_PKEY *ra_pkey = NULL;

    supnp_log("Secure Service Discovery verification..\n");

    supnp_verify(capTokenLocation, cleanup, "NULL capTokenLocation\n");
    supnp_verify(capTokenLocationSignature, cleanup, "NULL capTokenLocationSignature\n");
    supnp_verify(hexNonce, cleanup, "NULL hexNonce\n");
    supnp_verify(discoverySignature, cleanup, "NULL discoverySignature\n");

    ra_pkey = getRAPKey();
    supnp_verify(discoverySignature, cleanup, "NULL RA PKEY - Threading issue\n");

    /* nonce validation */
    nonce = OpenSslHexStringToBinary(hexNonce, &nonce_len);
    supnp_verify(nonce, cleanup, "Error converting nonce to binary\n");
    ret = OpenSslInsertNonce(nonce, nonce_len);
    if (ret != OPENSSL_SUCCESS) {
        goto cleanup; /* Silent Error. Previous thread might've added nonce.  */
    }

    /* CapToken location validation */
    ret = OpenSslVerifySignature("CapTokenLocationSignature",
        ra_pkey,
        capTokenLocationSignature,
        (const unsigned char *)capTokenLocation,
        strlen(capTokenLocation));
    supnp_verify(ret == OPENSSL_SUCCESS, cleanup,
        "Error verifying CapToken Location Signature\n");

    /* Retrieve CP Public Key */
    ret = downloadCapToken(capTokenLocation, &CapToken);
    supnp_verify(ret == SUPNP_E_SUCCESS, cleanup,
        "Error retrieving CapToken from %s\n", capTokenLocation);
    cp_pk = extractCapTokenFieldValue(CapToken, eCapTokenPublicKeyCP);
    supnp_verify(cp_pk, cleanup, "Error extracting CP Public Key\n");
    cp_pkey = OpenSslLoadPublicKeyFromHex(cp_pk);
    supnp_verify(cp_pkey, cleanup, "Error loading CP Public Key\n");

    /* Verify Discovery Signature */
    ret = OpenSslVerifySignature("DiscoverySignature",
        cp_pkey,
        discoverySignature,
        nonce,
        nonce_len);
    supnp_verify(ret == OPENSSL_SUCCESS, cleanup,
        "Error verifying Discovery Signature\n");

    supnp_log("Secure Service Discovery successful.\n");

    ret = SUPNP_E_SUCCESS;

cleanup:
    OpenSslFreePKey(&ra_pkey);
    OpenSslFreePKey(&cp_pkey);
    freeif(cp_pk);
    freeif(nonce);
    freeCapToken(&CapToken);
    return ret;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */
