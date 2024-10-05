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
#include "stdio.h"
#include "upnpconfig.h"

#if ENABLE_SUPNP

#include "file_utils.h"
#include "openssl_wrapper.h"
#include "service_table.h"
#include "upnptools.h"
#include <cJSON/cJSON.h>
#include <ixml.h>
#include "supnp.h"
#include "supnp_captoken.h"
#include "supnp_device.h"
#include "supnp_err.h"

#ifdef __cplusplus
extern "C" {
#endif


#define supnp_extract_json_string(doc, key, value, label) \
{ \
    value = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(doc, key)); \
    supnp_verify(value, label, "Unexpected '%s'\n", key); \
}

char *GetFirstElementItem(IXML_Element *element, const char *item)
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
 * Initialize SUPnP secure layer.
 * @return SUPNP_E_SUCCESS on success, SUPNP_E_INTERNAL_ERROR on failure.
 */
int SUpnpInit()
{
    supnp_log("Initializing SUPnP secure layer..\n");
    supnp_verify(init_openssl_wrapper() == OPENSSL_SUCCESS, cleanup, "Error initializing OpenSSL.\n");

    return SUPNP_E_SUCCESS;
cleanup:
    return SUPNP_E_INTERNAL_ERROR;
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
        p_dev->type = DEVICE_TYPE_CP;
    } else if (!strcmp("SD", dev_type)) {
        p_dev->type = DEVICE_TYPE_SD;
    } else {
        supnp_verify(NULL, cleanup, "Invalid device type '%s'.\n", dev_type);
    }
    supnp_log("Verifying %s document. Type: '%s'.\n", dev_name, dev_type);

    /* Fig.15 step 2 - Verify UCA Certificate using CA's public key */
    ret = SUPNP_E_INVALID_CERTIFICATE;
    supnp_verify(p_dev->uca_cert, cleanup, "NULL UCA Certificate provided.\n");
    supnp_verify(verify_certificate("UCA", p_dev->uca_cert, ca_pkey) == OPENSSL_SUCCESS, cleanup, "Invalid UCA cert.\n");

    /* Fig.15 step 2 - Verify Device Certificate using UCA's public key */
    supnp_verify(verify_certificate(dev_name, p_dev->dev_cert, p_dev->uca_pkey) == OPENSSL_SUCCESS, cleanup, "Invalid Device cert.\n");

    /* Verify Device Public Key */
    ret = SUPNP_E_INVALID_DOCUMENT;
    supnp_extract_json_string(p_dev->supnp_doc, SUPNP_DOC_PUBLIC_KEY, in_doc_pkey, cleanup);
    doc_pk = load_public_key_from_hex(in_doc_pkey);
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
        if (verify_signature(sig_name, pkey, signature, (unsigned char*)data, strlen(data)) != OPENSSL_SUCCESS)
        {
            ret = SUPNP_E_INVALID_DOCUMENT;
            break;
        }
        supnp_log("'%s' signature ok.\n", sig_name);
    }

    /* Done verification for CP */
    if (p_dev->type == DEVICE_TYPE_CP)
    {
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
    supnp_verify(p_dev->desc_uri, cleanup, "NULL description URI.\n");
    supnp_verify(p_dev->desc_doc, cleanup, "NULL description document.\n");
    const cJSON* json_services = cJSON_GetObjectItemCaseSensitive(p_dev->supnp_doc, SUPNP_DOC_SERVICES);
    supnp_verify(json_services, cleanup, "Couldn't find services tagname '%s' in SUPnP Document.\n", SUPNP_DOC_SERVICES);

    ret = getServiceTable((IXML_Node*)p_dev->desc_doc, &services, p_dev->desc_uri);
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

    /* SD Verification Done */
    ret = SUPNP_E_SUCCESS;

cleanup:
    freeif(data);
    freeif2(doc_pk, EVP_PKEY_free);
    if (p_dev && p_dev->type == DEVICE_TYPE_SD)
        freeServiceTable(&services);  // applicable only for SD
    return ret;
}




/**
* @brief Send a RA Action Register request to the RA service.
* The logics correspond to figure 15 in the SUPnP paper.
* Steps 7+8 are actually singing process. signature = E(sk, H(nonce))
*/
int SendRAActionRegister(RegistrationParams *params, const char *controlUrl)
{
    int rc = SUPNP_E_INTERNAL_ERROR;
    EVP_PKEY *sk = NULL; /* Private key */
    EVP_PKEY *pk = NULL; /* Public key */
    char *pk_hex = NULL; /* Public key hex string */
    IXML_Document *actionNode = NULL;
    IXML_Document *respNode = NULL;
    char *docs[RA_REGISTER_VARCOUNT] = {NULL};
    char *docs_hex[RA_REGISTER_VARCOUNT] = {NULL};
    size_t docs_size[RA_REGISTER_VARCOUNT] = {0};
    char *response = NULL;
    unsigned char *challenge = NULL;
    unsigned char *nonce = NULL;
    unsigned char *signature = NULL;
    char *hex_sig = NULL;
    size_t challenge_size;
    size_t nonce_len = 0;
    size_t sig_len = 0;

    supnp_verify(params, cleanup, "NULL Registration Params.\n");
    supnp_verify(controlUrl, cleanup, "NULL Control URL.\n");

    pk = load_public_key_from_pem(params->publicKeyPath);
    supnp_verify(pk, cleanup, "Error loading public key.\n");

    sk = load_private_key_from_pem(params->privateKeyPath);
    supnp_verify(sk, cleanup, "Error loading private key.\n");

    size_t pkb_size;
    unsigned char * pkb = public_key_to_bytes(pk, &pkb_size);
    pk_hex = binary_to_hex_string(pkb, pkb_size);
    freeif(pkb);
    supnp_verify(pk_hex, cleanup, "Error converting public key to hex string.\n");

    for (int i = 0; i < RA_REGISTER_VARCOUNT; ++i) {
        docs[i] = read_file(params->RegistrationDocsPath[i], "rb", &docs_size[i]);
        supnp_verify(docs[i] != NULL, cleanup, "Error reading Registration Document ID %d\n", i);
        docs_hex[i] = binary_to_hex_string((unsigned char *)docs[i], docs_size[i]);
        supnp_verify(docs_hex[i] != NULL, cleanup, "Error converting to hex string Registration Document ID %d\n", i);
        rc = UpnpAddToAction(&actionNode,
            RaRegistrationAction[RA_ACTIONS_REGISTER],
            RaServiceType[RA_SERVICE_REGISTER],
            RaRegisterVarName[i],
            docs_hex[i]);
        supnp_verify(rc == UPNP_E_SUCCESS, cleanup, "Error trying to add registration action param\n");
    }

    rc = UpnpSendAction(params->handle,
        controlUrl,
        RaServiceType[RA_SERVICE_REGISTER],
        NULL, /* UDN ignored & Must be NULL */
        actionNode,
        &respNode);
    supnp_verify(rc == UPNP_E_SUCCESS, cleanup, "Error in UpnpSendAction -- %d\n", rc);

    rc = SUPNP_E_INTERNAL_ERROR;

    /* Extract Challenge from respNode */
    response = GetFirstElementItem((IXML_Element*)respNode,
        RaRegistrationAction[RA_ACTIONS_CHALLENGE]);
    challenge = hex_string_to_binary(response, &challenge_size);
    supnp_verify(challenge, cleanup, "Error extracting challenge.\n");

    /* Decrypt the challenge using the participant's private key */
    nonce = decrypt_asym(sk, &nonce_len, challenge, challenge_size);
    supnp_verify(nonce, cleanup, "Error decrypting nonce.\n");
    supnp_verify(nonce_len == SHA256_DIGEST_LENGTH, cleanup, "Unexpected nonce length.\n");

    /* Signature = E(sk, H(nonce)) */
    signature = sign(sk, nonce, nonce_len, &sig_len);
    supnp_verify(signature, cleanup, "Error signing nonce E(sk, H(nonce)).\n");

    /* To Hex String */
    hex_sig = binary_to_hex_string(signature, sig_len);

    /* Send E(sk,H(n)) to RA */
    freeif2(actionNode, ixmlDocument_free);
    freeif2(respNode, ixmlDocument_free);
    rc = UpnpAddToAction(&actionNode,
        RaRegistrationAction[RA_ACTIONS_CHALLENGE],
        RaServiceType[RA_SERVICE_REGISTER],
        RaActionChallengeVarName[CHALLENGE_ACTION_RESPONSE],
        hex_sig);
    supnp_verify(rc == UPNP_E_SUCCESS, cleanup, "Error trying to add challenge action challenge param.\n");

    rc = UpnpAddToAction(&actionNode,
        RaRegistrationAction[RA_ACTIONS_CHALLENGE],
        RaServiceType[RA_SERVICE_REGISTER],
        RaActionChallengeVarName[CHALLENGE_ACTION_PUBLICKEY],
        pk_hex);
    supnp_verify(rc == UPNP_E_SUCCESS, cleanup, "Error trying to add challenge action public key param.\n");

    rc = UpnpSendAction(params->handle,
            controlUrl,
            RaServiceType[RA_SERVICE_REGISTER],
            NULL, /* UDN ignored & Must be NULL */
            actionNode,
            &respNode);
    supnp_verify(rc == UPNP_E_SUCCESS, cleanup, "Error in UpnpSendAction -- %d\n", rc);

    /* Check Challenge Response Status */
    rc = UPNP_E_INVALID_DEVICE;
    freeif(response);
    response = GetFirstElementItem((IXML_Element*)respNode, RaResponseVarName);
    supnp_verify(response, cleanup, "Error extracting response.\n");
    if (strcmp(response, RaResponseSuccess) == 0) {
        rc = SUPNP_DEVICE_REGISTERED;
    } else {
        rc = (int)strtol(response, NULL, 10);
    }

cleanup:
    free_key(sk);
    free_key(pk);
    freeif(pk_hex);
    freeif2(actionNode, ixmlDocument_free);
    freeif2(respNode, ixmlDocument_free);
    for (int i = 0; i < RA_REGISTER_VARCOUNT; ++i) {
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
    static ERegistrationStatus status = SUPNP_DEVICE_UNREGISTERED;
    int errCode = SUPNP_E_SUCCESS;
    IXML_Document *desc_doc = NULL;
    const UpnpDiscovery *d_event = (UpnpDiscovery *)event;
    const char *location = NULL;
    RegistrationParams *params = cookie;

    if (eventType != UPNP_DISCOVERY_SEARCH_RESULT)
        return SUPNP_E_SUCCESS;  /* Ignore */

    if (status == SUPNP_DEVICE_REGISTERED)
        return SUPNP_E_SUCCESS;  /* Ignore */

    supnp_verify(d_event, cleanup, "NULL Discovery event.\n");
    supnp_verify(params, cleanup, "NULL params.\n");

    /* Retrieve RA Description Document */
    errCode = UpnpDiscovery_get_ErrCode(d_event);
    supnp_verify(errCode == UPNP_E_SUCCESS, cleanup, "Error in Discovery Callback -- %d\n", errCode);
    location = UpnpString_get_String(UpnpDiscovery_get_Location(d_event));
    errCode = UpnpDownloadXmlDoc(location, &desc_doc);
    supnp_verify(errCode == UPNP_E_SUCCESS, cleanup, "Error in UpnpDownloadXmlDoc -- %d\n", errCode);

    /* Register the device if it is not already registered */
    errCode = strcmp(GetFirstElementItem((IXML_Element*)desc_doc, "deviceType"), RaDeviceType);
    supnp_verify(errCode == 0, cleanup, "Unexpected device type.\n");

    if (status != SUPNP_DEVICE_REGISTERED) {
        /* Extract Services List */
        errCode = getServiceTable((IXML_Node*)desc_doc, &services, location);
        supnp_verify(errCode, cleanup, "Couldn't fill service table.\n");

        /* Iterate Services and parse registration service */
        for (const service_info * service = services.serviceList; service != NULL; service = service->next) {
            char* controlURL = NULL;
            if (UpnpResolveURL2(location, service->controlURL, &controlURL) != UPNP_E_SUCCESS) {
                supnp_error("Error generating controlURL from %s + %s\n", location, service->controlURL);
            } else if (strcmp(service->serviceType, RaServiceType[RA_SERVICE_REGISTER]) == 0) {
                // Send the DSD to the RA
                errCode = SendRAActionRegister(params, controlURL);
                break;
            }
            freeif(controlURL);
            service = service->next;
        }

        if (errCode == SUPNP_DEVICE_REGISTERED) {
            supnp_log("SUPnP Control Point Registered\n");
            status = SUPNP_DEVICE_REGISTERED;
            UpnpUnRegisterClient(params->handle);
            params->callback(params->callback_cookie);
        } else {
            supnp_error("Error registering SUPnP device. Code: (%d).\n", errCode);
        }
    }
cleanup:
    freeServiceTable(&services);
    freeif2(desc_doc, ixmlDocument_free);
    freeif(params);
    return errCode;
}


int SupnpRegisterDevice(const char *pk_path,
    const char *sk_path,
    const char *RegistrationDocsPath[],
    const char *desc_doc_uri,
    int timeout,
    SUpnp_FunPtr callback,
    void *callback_cookie)
{
    int ret = SUPNP_E_SUCCESS;

    /* Verify Params */
    supnp_verify(pk_path, cleanup, "NULL public key path.\n");
    supnp_verify(sk_path, cleanup, "NULL private key path.\n");
    supnp_verify(RegistrationDocsPath, cleanup, "NULL Registration Docs Paths.\n");

    /* Set Registration Params */
    RegistrationParams *params = malloc(sizeof(RegistrationParams));
    supnp_verify(params, cleanup, "Error allocating memory for registration params.\n");
    params->handle = -1;
    params->callback = callback;
    params->callback_cookie = callback_cookie;
    params->publicKeyPath = pk_path;
    params->privateKeyPath = sk_path;
    for (int i = 0; i < RA_REGISTER_VARCOUNT; ++i) {
        supnp_verify(RegistrationDocsPath[i], cleanup, "NULL %s.\n", RaRegisterVarName[i]);
        params->RegistrationDocsPath[i] = RegistrationDocsPath[i];
    }
    params->desc_doc_uri = desc_doc_uri;

    /* Register registration handle with UPnP SDK */
    ret = UpnpRegisterClient(RegistrationCallbackEventHandler, params, &(params->handle));
    supnp_verify(ret == UPNP_E_SUCCESS, cleanup, "Error registering registration handle with sdk: %d\n", ret);

    /* Send RA Discovery Message */
    ret = UpnpSearchAsync(params->handle, timeout, RaDeviceType, params);
    supnp_verify(ret == UPNP_E_SUCCESS, cleanup, "Error sending RA discovery message (%d)\n", ret);

    return SUPNP_E_SUCCESS; /* Success */

cleanup:
    freeif(params);
    return ret;
}




#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */
