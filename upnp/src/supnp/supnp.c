/*!
 * \addtogroup SUPnP
 *
 * \file supnp.c
 *
 * \author Roman Koifman
 *
 * \brief source file for SUPnP secure layer method. Implementing logics from
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
char gCapTokenLocation[LOCATION_SIZE] = {0};
ithread_rwlock_t gDeviceTypeLock;
ithread_rwlock_t gDeviceKeyLock;
ithread_rwlock_t gRAKeyLock;
ithread_rwlock_t gCapTokenLocationLock;
/**/

#define supnp_extract_json_string(doc, key, value, label) \
{ \
    value = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(doc, key)); \
    supnp_verify(value, label, "Unexpected '%s'\n", key); \
}

void SUpnpSetDeviceType(const EDeviceType devType)
{
    ithread_rwlock_wrlock(&gDeviceTypeLock);
    gCurrentDeviceType = devType;
    ithread_rwlock_unlock(&gDeviceTypeLock);
}

EDeviceType SUpnpGetDeviceType()
{
    ithread_rwlock_rdlock(&gDeviceTypeLock);
    const EDeviceType type = gCurrentDeviceType;
    ithread_rwlock_unlock(&gDeviceTypeLock);
    return type;
}

void SUpnpSetDevicePKey(EVP_PKEY *pkey)
{
    ithread_rwlock_wrlock(&gDeviceKeyLock);
    if (gDevicePKey && (gDevicePKey != pkey)) {
        EVP_PKEY_free(gDevicePKey);
    }
    gDevicePKey = pkey;
    ithread_mutex_unlock(&gDeviceKeyLock);
}

EVP_PKEY *SUpnpGetDevicePKey()
{
    EVP_PKEY *pkey = NULL;
    ithread_rwlock_rdlock(&gDeviceKeyLock);
    if (gDevicePKey) {
        pkey = EVP_PKEY_dup(gDevicePKey);
    }
    ithread_rwlock_unlock(&gDeviceKeyLock);
    return pkey;
}

void SUpnpSetRAPublicKey(EVP_PKEY *pkey)
{
    ithread_rwlock_wrlock(&gRAKeyLock);
    if (gRAPublicKey && (gRAPublicKey != pkey)) {
        EVP_PKEY_free(gRAPublicKey);
    }
    gRAPublicKey = pkey;
    ithread_mutex_unlock(&gRAKeyLock);
}

EVP_PKEY *SUpnpGetRAPKey()
{
    EVP_PKEY *pkey = NULL;
    ithread_rwlock_rdlock(&gRAKeyLock);
    if (gRAPublicKey) {
        pkey = EVP_PKEY_dup(gRAPublicKey);
    }
    ithread_rwlock_unlock(&gRAKeyLock);
    return pkey;
}

void SUpnpSetCapTokenLocation(const int AF, const char *CapTokenLocation)
{
    ithread_rwlock_wrlock(&gCapTokenLocationLock);
    memset(gCapTokenLocation, 0, sizeof(gCapTokenLocation));
    if (CapTokenLocation && strlen(CapTokenLocation) < LOCATION_SIZE) {
        strncpy(gCapTokenLocation, CapTokenLocation, sizeof(gCapTokenLocation));
    } else {
        supnp_error("Invalid CapToken Location '%s'.\n", CapTokenLocation);
    }
    ithread_mutex_unlock(&gCapTokenLocationLock);
}

void SUpnpGetCapTokenLocation(char CapTokenLocation[LOCATION_SIZE])
{
    memset(CapTokenLocation, 0, LOCATION_SIZE);
    ithread_rwlock_rdlock(&gCapTokenLocationLock);
    strncpy(CapTokenLocation, gCapTokenLocation, LOCATION_SIZE);
    ithread_rwlock_unlock(&gCapTokenLocationLock);
}


int SUpnpBuildLocation(char url[LOCATION_SIZE],
    const int AF,
    const char *filename)
{
    int ret = SUPNP_E_INVALID_ARGUMENT;

    memset(url, 0, LOCATION_SIZE);
    supnp_verify(filename, cleanup, "NULL filename.\n");

    ret = SUPNP_E_INTERNAL_ERROR;
    char *ip = UpnpGetServerIpAddress();
    const unsigned short port = UpnpGetServerPort();
    supnp_verify((ip != NULL) && (port > 0), cleanup, "UPnP SDK is not initialized.\n");

    switch (AF) {
        case AF_INET:
            snprintf(url,
                LOCATION_SIZE,
                "http://%s:%d/%s",
                ip,
                port,
                filename);
            ret = SUPNP_E_SUCCESS;
            break;
        case AF_INET6:
            snprintf(url,
                LOCATION_SIZE,
                "http://[%s]:%d/%s",
                ip,
                port,
                filename);
            ret = SUPNP_E_SUCCESS;
            break;
        default:
            supnp_error("Invalid address family %d\n", AF);
            break;
        }
cleanup:
    return ret;
}


int SUpnpInit(const char *IfName, const unsigned short DestPort,
    const char *privateKeyPath, const int devType)
{
    supnp_log("Initializing SUPnP secure layer..\n");

    switch(devType) {
        case eDeviceType_SD:
        case eDeviceType_CP:
        case eDeviceType_RA:
            SUpnpSetDeviceType(devType);
            break;
        default:
            supnp_error("Invalid device type %d.\n", devType);
            goto cleanup;;
    }

    /* Initialize OpenSSL Wrapper */
    // todo supnp: maybe UpnpInitSslContext ?
    supnp_verify(OpenSslInitializeWrapper() == OPENSSL_SUCCESS, cleanup,
        "Error initializing OpenSSL.\n");

    /* Load key pair (public key is generated from private key) */
    EVP_PKEY *pkey = OpenSslLoadPrivateKeyFromPEM(privateKeyPath);
    supnp_verify(pkey, cleanup, "Error loading private key from '%s'.\n",
        privateKeyPath);
    SUpnpSetDevicePKey(pkey); /* Set global, no free */

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
    if (SUpnpGetDeviceType() == eDeviceType_SD) {
        return UpnpFinish(1);  /* Only SD can send secure adv. */
    }
    else {
        return UpnpFinish(0);
    }
}

char *SUpnpGetFirstElementItem(IXML_Element *element, const char *item)
{
	IXML_NodeList *nodeList = NULL;
	IXML_Node *textNode = NULL;
	IXML_Node *tmpNode = NULL;
	char *ret = NULL;

    supnp_verify(element, cleanup, "NULL XML Node.\n");
    supnp_verify(item, cleanup, "NULL item.\n");

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


char *SUpnpGetFirstElementItem2(const char *location, const char *item)
{
    IXML_Document *DescDoc = NULL;
    char *ret = NULL;

    supnp_verify(location, cleanup, "NULL description document URL.\n");

    const int errCode = UpnpDownloadXmlDoc(location, &DescDoc);
    supnp_verify(errCode == UPNP_E_SUCCESS, cleanup,
        "Error obtaining device description from %s -- error = %d\n",
        location, errCode);

    ret = SUpnpGetFirstElementItem((IXML_Element*)DescDoc, item);

cleanup:
    freeif2(DescDoc, ixmlDocument_free);
    return ret;
}

/**
 * DSD/SAD Verification process. Figure 15, SUPnP paper.
 * Steps 2-3.
 * @param PublicKeyCA CA public key
 * @param p_dev Device info
 * @return SUPNP_E_SUCCESS on success. Error code otherwise.
 */
int SUpnpVerifyDocument(EVP_PKEY* PublicKeyCA, supnp_device_t* p_dev)
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
    supnp_verify(PublicKeyCA, cleanup,  "NULL CA public key provided.\n");
    supnp_verify(p_dev, cleanup, "NULL device provided.\n");

    /* Read SUPnP document name & type */
    ret = SUPNP_E_INVALID_DOCUMENT;
    supnp_verify(p_dev->specDocument, cleanup, "NULL SAD/DSD provided.\n");
    supnp_extract_json_string(p_dev->specDocument, SUPNP_DOC_NAME, dev_name, cleanup);
    supnp_extract_json_string(p_dev->specDocument, SUPNP_DOC_TYPE, dev_type, cleanup);
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
    supnp_verify(p_dev->certUCA, cleanup, "NULL UCA Certificate provided.\n");
    supnp_verify(OpenSslVerifyCertificate("UCA", p_dev->certUCA, PublicKeyCA) == OPENSSL_SUCCESS, cleanup, "Invalid UCA cert.\n");

    /* Fig.15 step 2 - Verify Device Certificate using UCA's public key */
    supnp_verify(OpenSslVerifyCertificate(dev_name, p_dev->certDevice, p_dev->pkeyUCA) == OPENSSL_SUCCESS, cleanup, "Invalid Device cert.\n");

    /* Verify Device Public Key */
    ret = SUPNP_E_INVALID_DOCUMENT;
    supnp_extract_json_string(p_dev->specDocument, SUPNP_DOC_PUBLIC_KEY, in_doc_pkey, cleanup);
    doc_pk = OpenSslLoadPublicKeyFromHex(in_doc_pkey);
    supnp_verify(doc_pk, cleanup, "Error loading public key from '%s'.\n", SUPNP_DOC_PUBLIC_KEY);
    supnp_verify(EVP_PKEY_eq(doc_pk, p_dev->pkeyDevice) == OPENSSL_SUCCESS, cleanup,
                 "Document's device public key doesn't match Device certificate's public key.\n");

    /* Retrieve signature verification conditions */
    supnp_extract_json_string(p_dev->specDocument, SUPNP_DOC_SIG_CON, sig_ver_con, cleanup);
    supnp_verify(sscanf(sig_ver_con, "%d-of-%d", &x, &y) == 2, cleanup,
                 "Error parsing Signature Verification Conditions '%s'.\n", SUPNP_DOC_SIG_CON);
    supnp_verify(x >= 0 && y >= 0 && x <= y, cleanup, "Invalid Signature Verification Conditions '%s'.\n",
                 SUPNP_DOC_SIG_CON);
    supnp_log("Signature Verification Conditions: %d-of-%d\n", x, y);

    /* Retrieve Signatures */
    const cJSON* sigs = cJSON_GetObjectItemCaseSensitive(p_dev->specDocument, SUPNP_DOC_SIGNATURES);
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
    cJSON* doc_content = cJSON_Duplicate(p_dev->specDocument, 1);
    cJSON_DeleteItemFromObjectCaseSensitive(doc_content, SUPNP_DOC_SIG_OWNER);
    cJSON_DeleteItemFromObjectCaseSensitive(doc_content, SUPNP_DOC_SIG_UCA);
    data = cJSON_PrintUnformatted(doc_content);

    /* Verify Signatures */
    for (int sig_index = 0; sig_index < cJSON_GetArraySize(sigs); ++sig_index)
    {
        char* sig_name = cJSON_GetStringValue(cJSON_GetArrayItem(sigs, sig_index));
        if (strcmp(sig_name, SUPNP_DOC_SIG_OWNER) == 0)
        {
            pkey = p_dev->pkeyDevice;
        }
        else if (strcmp(sig_name, SUPNP_DOC_SIG_UCA) == 0)
        {
            pkey = p_dev->pkeyUCA;
        }
        else
        {
            supnp_error("Unexpected signature name '%s'\n", sig_name);
            ret = SUPNP_E_INVALID_DOCUMENT;
            break;
        }
        /* Extract the hex string signature and convert it to bytes */
        const char* signature = cJSON_GetStringValue(
            cJSON_GetObjectItemCaseSensitive(p_dev->specDocument, sig_name));
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
     * todo supnp: verify that the capability of an SD matches its DDD. Maintain Ledger.
     */
    supnp_verify(strlen(p_dev->descDocLocation) > 0, cleanup,
        "NULL description URL.\n");
    supnp_verify(p_dev->descDocument, cleanup, "NULL description document.\n");
    const cJSON* json_services = cJSON_GetObjectItemCaseSensitive(
        p_dev->specDocument, SUPNP_DOC_SERVICES);
    supnp_verify(json_services, cleanup,
        "Couldn't find services tagname '%s' in SUPnP Document.\n",
        SUPNP_DOC_SERVICES);

    ret = getServiceTable((IXML_Node*)p_dev->descDocument, &services,
        p_dev->descDocLocation);
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
    if (p_dev && (p_dev->type == eDeviceType_SD) && p_dev->descDocument) {
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
int sendRAActionRegister(RegistrationParams *Params, const char *ControlUrl)
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

    supnp_verify(Params, cleanup, "NULL Registration Params.\n");
    supnp_verify(ControlUrl, cleanup, "NULL Control URL.\n");

    size_t pkb_size;     /* Public key bytes size */
    device_pkey = SUpnpGetDevicePKey();
    unsigned char * pkb = OpenSslPublicKeyToBytes(device_pkey, &pkb_size);
    pk_hex = OpenSslBinaryToHexString(pkb, pkb_size);
    freeif(pkb);
    supnp_verify(pk_hex, cleanup, "Error converting public key to hex string.\n");

    for (int i = 0; i < SUPNP_DOCS_ON_DEVICE; ++i) {
        docs[i] = read_file(Params->RegistrationDocsPath[i], "rb", &docs_size[i]);
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

    /* Add Description Document Location, if applicable. */
    if (Params->descDocLocation) {
        rc = UpnpAddToAction(&actionNode,
            RaRegistrationAction[eRegisterServiceAction_Register],
            RaServiceType[eRegistrationAuthorityService_Register],
            RaRegisterActionVarName[eRegisterActionVar_DescDocFileLocation],
            Params->descDocLocation);
        supnp_verify(rc == UPNP_E_SUCCESS, cleanup,
            "Error trying to add Description Document Location\n");
    }

    /* Add CapToken Location */
    supnp_verify(Params->capTokenLocation, cleanup, "NULL CapToken Filename.\n");
    rc = UpnpAddToAction(&actionNode,
        RaRegistrationAction[eRegisterServiceAction_Register],
        RaServiceType[eRegistrationAuthorityService_Register],
        RaRegisterActionVarName[eRegisterActionVar_CapTokenLocation],
        Params->capTokenLocation);
    supnp_verify(rc == UPNP_E_SUCCESS, cleanup,
        "Error trying to add CapToken Location\n");

    rc = UpnpSendAction(Params->handle,
        ControlUrl,
        RaServiceType[eRegistrationAuthorityService_Register],
        NULL, /* UDN ignored & Must be NULL */
        NULL, /* SecureParams ignored */
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

    rc = UpnpSendAction(Params->handle,
            ControlUrl,
            RaServiceType[eRegistrationAuthorityService_Register],
            NULL, /* UDN ignored & Must be NULL */
            NULL, /* SecureParams ignored */
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
    supnp_verify(rc == eRegistrationStatus_DeviceRegistered, cleanup,
        "Registration Failed: %s\n", response);

    /* Extract Cap Token */
    rc = SUPNP_E_CAPTOKEN_ERROR;
    freeif(response);
    response = SUpnpGetFirstElementItem((IXML_Element*)respNode,
        CapTokenResponseVarName);
    supnp_verify(response, cleanup, "Error extracting CapToken.\n");
    capToken = SUpnpCapTokenFromHexString(response);
    supnp_verify(capToken, cleanup, "Error converting CapToken from hex string.\n");

    // Find the last occurrence of '/'
    const char *filename = strrchr( Params->capTokenLocation, '/');
    if (filename != NULL) {
        filename++;
    } else {
        supnp_error("Invalid url '%s'\n", Params->capTokenLocation);
        goto cleanup;
    }
    char filepath[256];
    sprintf(filepath, "web/%s", filename); // todo supnp: configure filepath in SUPnP init
    supnp_verify(SUpnpStoreCapToken(capToken, filepath) == SUPNP_E_SUCCESS,
        cleanup, "Error storing CapToken.\n");

    /* Load RA Public Key */
    supnp_verify(ra_pk == NULL, cleanup, "RA Public Key already loaded! "
        "Registering should be performed only once.\n");
    ra_pk = SUpnpExtractCapTokenFieldValue(capToken, eCapTokenPublicKeyRA);
    supnp_verify(ra_pk, cleanup, "Error extracting RA Public Key.\n");

    EVP_PKEY *ra_pkey = OpenSslLoadPublicKeyFromHex(ra_pk);
    supnp_verify(ra_pkey, cleanup, "Error loading RA Public Key.\n");
    SUpnpSetRAPublicKey(ra_pkey);  /* RA is set in global, hence no free */

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
    char *deviceType = NULL;

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
    deviceType = SUpnpGetFirstElementItem((IXML_Element*)ra_desc_doc,
        "deviceType");
    supnp_verify((strcmp(deviceType, RaDeviceType) == 0), cleanup,
        "Unexpected device type %s.\n", deviceType);

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
    freeif(deviceType);
    freeServiceTable(&services);
    freeif2(ra_desc_doc, ixmlDocument_free);
    SUpnpFreeRegistrationParamsContent(params);
    return errCode;
}

int SUpnpRegisterDevice(
    const char *RegistrationDocsPath[],
    const char *CapTokenFilename,
    const int AF,
    const char *DescDocName,
    const int Timeout,
    const SUpnp_FunPtr Callback,
    void *callback_cookie)
{
    int ret = SUPNP_E_SUCCESS;

    /* Verify Params */
    supnp_verify(RegistrationDocsPath, cleanup, "NULL Registration Docs Paths.\n");
    supnp_verify(CapTokenFilename, cleanup, "NULL CapToken Filename.\n");

    /* Set Registration Params */
    RegistrationParams *params = malloc(sizeof(RegistrationParams));
    supnp_verify(params, cleanup, "Error allocating memory for registration params.\n");
    params->handle = -1;
    params->callback = Callback;
    params->callback_cookie = callback_cookie;
    for (int i = 0; i < SUPNP_DOCS_ON_DEVICE; ++i) {
        supnp_verify(RegistrationDocsPath[i], cleanup, "NULL %s.\n", RaRegisterActionVarName[i]);
        params->RegistrationDocsPath[i] = RegistrationDocsPath[i];
    }
    ret = SUpnpBuildLocation(params->capTokenLocation, AF, CapTokenFilename);
    supnp_verify(ret == SUPNP_E_SUCCESS, cleanup,
        "Error building CapTokenLocation.\n");
    SUpnpSetCapTokenLocation(AF, params->capTokenLocation); /* Set global */

    /* Applicable only for SD, for CP set NULL */
    if (DescDocName != NULL) {
        ret = SUpnpBuildLocation(params->descDocLocation, AF, DescDocName);
        supnp_verify(ret == SUPNP_E_SUCCESS, cleanup,
            "Error building DescDocLocation.\n");
    }

    /* Register registration handle with UPnP SDK */
    ret = UpnpRegisterClient(RegistrationCallbackEventHandler, params, &(params->handle));
    supnp_verify(ret == UPNP_E_SUCCESS, cleanup, "Error registering registration handle with sdk: %d\n", ret);

    /* Send RA Non-Secure Discovery Message */
    ret = UpnpSearchAsync(params->handle,
        Timeout,
        RaDeviceType,
        NULL,  /* Secure Discovery Not Applicable */
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
 * @param Params Registration Params
 */
void SUpnpFreeRegistrationParamsContent(RegistrationParams *Params)
{
    if (!Params)
        return;
    // todo supnp: consider strdup instead of const paths
#if 0
    freeif(params->publicKeyPath);
    freeif(params->privateKeyPath);
    for (int i = 0; i < SUPNP_DOCS_ON_DEVICE; ++i) {
        freeif(params->RegistrationDocsPath[i]);
    }
#endif
    memset(Params->capTokenLocation, 0, sizeof(Params->capTokenLocation));
    memset(Params->descDocLocation, 0, sizeof(Params->descDocLocation));
}

/**
 * Free Registration Params
 * @param Params Registration Params
 */
void SUpnpFreeRegistrationParams(RegistrationParams **Params)
{
    SUpnpFreeRegistrationParamsContent(*Params);
    freeif(*Params);
}

int SUpnpGetSecureAdvertisementParams(char CapTokenLocation[LOCATION_SIZE],
    char AdvertisementSig[HEXSIG_SIZE])
{
    int ret = SUPNP_E_SECURE_PARAMS_ERROR;
    char *sig = NULL;
    memset(CapTokenLocation, 0, LOCATION_SIZE);
    memset(AdvertisementSig, 0, HEXSIG_SIZE);

    /* Extract CapTokenLocation */
    SUpnpGetCapTokenLocation(CapTokenLocation);

    /* Extract Advertisement Signature */
    sig = SUpnpExtractCapTokenFieldValue2(CapTokenLocation,
            eCapTokenSignatureAdvertisement);
    supnp_verify(sig, cleanup, "Error extracting Advertisement Signature\n");
    strncpy(AdvertisementSig, sig, HEXSIG_SIZE);
    ret = SUPNP_E_SUCCESS;

cleanup:
    freeif(sig);
    return ret;
}

int SUpnpPrepareSecureParams(SecureParams *Params)
{
    int ret = SUPNP_E_SECURE_PARAMS_ERROR;
    EVP_PKEY *device_pkey = NULL;
    unsigned char *nonce = NULL;
    unsigned char *nonce_sig = NULL;
    char *hexCapTokenLocationSig = NULL;
    char *hexNonce = NULL;
    char *nonce_sig_hex = NULL;
    size_t sig_len = 0;

    /* Extract CapTokenLocation */
    SUpnpGetCapTokenLocation(Params->CapTokenLocation);

    /* Extract CapTokenLocation Signature */
    hexCapTokenLocationSig = SUpnpExtractCapTokenFieldValue2(Params->CapTokenLocation,
        eCapTokenSignatureLocation);
    supnp_verify(hexCapTokenLocationSig, cleanup,
        "Error extracting CapTokenLocation Signature\n");
    SUPNP_PARAM_STRNCPY(Params->CapTokenLocationSig, hexCapTokenLocationSig);

    /* Generate nonce */
    nonce = OpenSslGenerateNonce(OPENSSL_CSPRNG_SIZE);
    supnp_verify(nonce, cleanup, "Error generating nonce of size %d.\n",
        OPENSSL_CSPRNG_SIZE);
    hexNonce = OpenSslBinaryToHexString(nonce, OPENSSL_CSPRNG_SIZE);
    supnp_verify(hexNonce, cleanup, "Error converting nonce to hex string.\n");
    SUPNP_PARAM_STRNCPY(Params->Nonce, hexNonce);

    /* Nonce Signature */
    device_pkey = SUpnpGetDevicePKey();
    nonce_sig = OpenSslSign(device_pkey, nonce, OPENSSL_CSPRNG_SIZE, &sig_len);
    supnp_verify(nonce_sig, cleanup, "Error signing nonce.\n");
    nonce_sig_hex = OpenSslBinaryToHexString(nonce_sig, sig_len);
    supnp_verify(nonce_sig_hex, cleanup, "Error converting nonce signature to hex string.\n");
    SUPNP_PARAM_STRNCPY(Params->NonceSig, nonce_sig_hex);

    ret = SUPNP_E_SUCCESS;

cleanup:
    freeif(nonce_sig_hex);
    freeif(nonce_sig);
    OpenSslFreePKey(&device_pkey);
    freeif(hexNonce);
    freeif(nonce);
    freeif(hexCapTokenLocationSig);
    return ret;
}

int SUpnpVerifySecureParams(const char *name, const SecureParams *SParams)
{
    int ret = SUPNP_E_SECURE_PARAMS_ERROR;;
    unsigned char *nonce = NULL;
    size_t nonce_len;
    char *cp_pk = NULL;
    EVP_PKEY *cp_pkey = NULL;
    EVP_PKEY *ra_pkey = NULL;

    supnp_verify(SParams, cleanup, "NULL SecureParams\n");
    supnp_verify(strlen(SParams->CapTokenLocation) > 0, cleanup,
        "Empty CapTokenLocation\n");
    supnp_verify(strlen(SParams->CapTokenLocationSig) > 0, cleanup,
        "Empty CapTokenLocationSignature\n");
    supnp_verify(strlen(SParams->Nonce) > 0, cleanup, "Empty Nonce\n");
    supnp_verify(strlen(SParams->NonceSig) > 0, cleanup,
        "Empty %s\n", name);

    /* nonce validation */
    nonce = OpenSslHexStringToBinary(SParams->Nonce, &nonce_len);
    supnp_verify(nonce, cleanup, "Error converting nonce to binary\n");

    supnp_verify(OpenSslInsertNonce(nonce, nonce_len) == OPENSSL_SUCCESS,
        cleanup, "nonce already exists. Dropping message..\n");

    ra_pkey = SUpnpGetRAPKey();
    supnp_verify(ra_pkey, cleanup, "NULL RA PKEY\n");

    /* CapToken location validation */
    ret = SUPNP_E_INVALID_SIGNATURE;
    supnp_verify(OPENSSL_SUCCESS == OpenSslVerifySignature(
        "CapTokenLocationSignature",
        ra_pkey,
        SParams->CapTokenLocationSig,
        SParams->CapTokenLocation,
        strlen(SParams->CapTokenLocation)),
        cleanup,
        "Error verifying CapToken Location Signature\n");

    /* Retrieve CP Public Key from CapToken */
    ret = SUPNP_E_CAPTOKEN_ERROR;
    cp_pk = SUpnpExtractCapTokenFieldValue2(SParams->CapTokenLocation, eCapTokenPublicKeyCP);
    supnp_verify(cp_pk, cleanup, "Error extracting CP Public Key\n");
    cp_pkey = OpenSslLoadPublicKeyFromHex(cp_pk);
    supnp_verify(cp_pkey, cleanup, "Error loading CP Public Key\n");

    /* Verify Discovery Signature */
    ret = SUPNP_E_INVALID_SIGNATURE;
    supnp_verify(OPENSSL_SUCCESS == OpenSslVerifySignature(name,
        cp_pkey,
        SParams->NonceSig,
        nonce,
        nonce_len),
        cleanup,
        "Error verifying %s\n", name);

    ret = SUPNP_E_SUCCESS;

cleanup:
    OpenSslFreePKey(&ra_pkey);
    OpenSslFreePKey(&cp_pkey);
    freeif(cp_pk);
    freeif(nonce);
    return ret;
}

/******************************************************************************
 ******************************************************************************
 *                                                                            *
 *                     SECURE SERVICE ADVERTISEMENT                           *
 *                                                                            *
 ******************************************************************************
 ******************************************************************************/

int SUpnpSendAdvertisement(const int Hnd, const int Exp)
{
    int ret = SUPNP_E_SECURE_PARAMS_ERROR;
    char capTokenLocation[LOCATION_SIZE];
    char advertisementSig[HEXSIG_SIZE];

    /* Secure Advertisement not applicable for RA */
    if (SUpnpGetDeviceType() == eDeviceType_RA) {
        ret = UpnpSendAdvertisement(Hnd, NULL, NULL, Exp);
        supnp_verify(ret == SUPNP_E_SUCCESS, cleanup,
            "Error in UpnpSendAdvertisement -- %d\n", ret);
        goto cleanup;
    }

    supnp_log("Secure Service Advertisement: sending..\n");

    ret = SUpnpGetSecureAdvertisementParams(capTokenLocation, advertisementSig);
    supnp_verify(ret == SUPNP_E_SUCCESS, cleanup,
        "Error Retrieving Secure Advertisement Params -- %d\n", ret);

    ret = UpnpSendAdvertisement(Hnd, capTokenLocation, advertisementSig, Exp);
    supnp_verify(ret == SUPNP_E_SUCCESS, cleanup,
        "Error in UpnpSendAdvertisement -- %d\n", ret);

    cleanup:
        return ret;
}


int SUpnpSecureServiceAdvertisementVerify(const char *descDocLocation,
    const char *capTokenLocation,
    const char *AdvertisementSig)
{
    int ret = SUPNP_E_SECURE_PARAMS_ERROR;
    char concatenate_url[2*LOCATION_SIZE] = {0};
    EVP_PKEY *ra_pk = NULL;
    IXML_Document *pDescDoc = NULL;
    captoken_t *pTargetCapToken = NULL;
    char *desc_doc_content = NULL;

    supnp_log("Verifying Secure Service Advertisement ..\n");

    supnp_verify(descDocLocation != NULL, cleanup, "NULL hexSignature\n");
    supnp_verify(capTokenLocation != NULL, cleanup, "NULL descDocUrl\n");
    supnp_verify(AdvertisementSig != NULL, cleanup, "NULL capTokenUrl\n");

    /* Load RA Public Key */
    ra_pk = SUpnpGetRAPKey();
    supnp_verify(ra_pk, cleanup, "NULL RA PKEY\n");

    /* Concatenate (description url || cap token url) */
    strncpy(concatenate_url, descDocLocation, LOCATION_SIZE);
    strncat(concatenate_url, capTokenLocation, LOCATION_SIZE);

    /* Verify the Advertisement Signature (Fig 17 - Secure Advertisement) */
    supnp_log("Verifying Secure Service Advertisement..\n");
    supnp_verify(OPENSSL_SUCCESS == OpenSslVerifySignature(
        "Advertisement Signature",
        ra_pk,
        AdvertisementSig,
        concatenate_url,
        strlen(concatenate_url)),
        cleanup,
        "Advertisement signature is forged !!!\n");

    /* Download Description Document */
    ret = UpnpDownloadXmlDoc(descDocLocation, &pDescDoc);
    supnp_verify(ret == UPNP_E_SUCCESS, cleanup, "Error in UpnpDownloadXmlDoc -- %d\n", ret);

    /* Download CapToken */
    ret = SUpnpDownloadCapToken(capTokenLocation, &pTargetCapToken);
    supnp_verify(ret == UPNP_E_SUCCESS, cleanup, "Error in downloadCapToken -- %d\n", ret);

    /* Secure Device Description - Fig17, SUPnP paper. */
    desc_doc_content = ixmlDocumenttoString(pDescDoc);
    ret = SUpnpVerifyCapToken(pTargetCapToken, ra_pk, desc_doc_content);
    supnp_verify(ret == SUPNP_E_SUCCESS, cleanup,
        "Secure Device Description failed !!! Error in verifyCapToken -- %d\n",
        ret);

    supnp_log("Secure Service Advertisement verified successfully.\n");

    ret = SUPNP_E_SUCCESS;

cleanup:
    freeif(desc_doc_content);
    freeif2(ra_pk, EVP_PKEY_free);
    freeif2(pDescDoc, ixmlDocument_free);
    SUpnpFreeCapToken(&pTargetCapToken);
    return ret;
}

UPNP_EXPORT_SPEC int SUpnpUnRegisterRootDevice(const int Hnd)
{
    int ret = SUPNP_E_SECURE_PARAMS_ERROR;
    char capTokenLocation[LOCATION_SIZE];
    char advertisementSig[HEXSIG_SIZE];

    supnp_log("Secure Service Advertisement: sending..\n");

    ret = SUpnpGetSecureAdvertisementParams(capTokenLocation, advertisementSig);
    supnp_verify(ret == SUPNP_E_SUCCESS, cleanup,
        "Error Retrieving Secure Advertisement Params -- %d\n", ret);

    ret = UpnpUnRegisterRootDevice(Hnd, capTokenLocation, advertisementSig);

    supnp_verify(ret == SUPNP_E_SUCCESS, cleanup,
        "Error in UpnpUnRegisterRootDevice -- %d\n", ret);

cleanup:
    return ret;
}


/******************************************************************************
 ******************************************************************************
 *                                                                            *
 *                       SECURE SERVICE DISCOVERY                             *
 *                                                                            *
 ******************************************************************************
 ******************************************************************************/

int SUpnpSearchAsync(const int Hnd,
    const int Mx,
    const char *Target,
    const char *Cookie)
{
    SecureParams params = {0};

    supnp_log("Secure Service Discovery: sending..\n");

    int ret = SUpnpPrepareSecureParams(&params);
    supnp_verify(ret == SUPNP_E_SUCCESS, cleanup,
        "Error preparing Secure Params\n");

    /* Invoke Secure Discovery */
    ret = UpnpSearchAsync(Hnd, Mx, Target, &params, Cookie);
    supnp_verify(ret == SUPNP_E_SUCCESS, cleanup,
        "Error in UpnpSearchAsync -- %d\n", ret);

cleanup:
    return ret;
}


int SUpnpSecureServiceDiscoveryVerify(const SecureParams *SParams)
{
    supnp_log("Secure Service Discovery verification..\n");
    const int ret = SUpnpVerifySecureParams("DiscoverySignature", SParams);
    if (ret == SUPNP_E_SUCCESS) {
        supnp_log("Secure Service Discovery successful.\n");
    } else if (ret == SUPNP_E_NONCE_EXISTS) {
        supnp_error("Secure Service Discovery failed!!! -- %d\n", ret);
    }
    return ret;
}


/******************************************************************************
 ******************************************************************************
 *                                                                            *
 *                           SECURE CONTROL                                   *
 *                                                                            *
 ******************************************************************************
 ******************************************************************************/

int SUpnpSendAction(const int Hnd,
    const char *ActionURL,
	const char *ServiceType,
	const char *DevUDN,
	IXML_Document *Action,
	IXML_Document **RespNode)
{
    SecureParams params = {0};

    supnp_log("Secure Control: Sending Secure Action..\n");

    int ret = SUpnpPrepareSecureParams(&params);
    supnp_verify(ret == SUPNP_E_SUCCESS, cleanup,
        "Error preparing Secure Params\n");

    ret = UpnpSendAction(Hnd,
        ActionURL,
        ServiceType,
        DevUDN,
        &params,
        Action,
        RespNode);
    supnp_verify(ret == SUPNP_E_SUCCESS, cleanup,
        "Error in UpnpSendAction -- %d\n", ret);

cleanup:
    return ret;
}

int SUpnpSendActionEx(const int Hnd,
	const char *ActionURL,
	const char *ServiceType,
	const char *DevUDN,
	IXML_Document *Header,
	IXML_Document *Action,
	IXML_Document **RespNode)
{
    SecureParams params = {0};

    supnp_log("Secure Control: Sending Secure Action..\n");

    int ret = SUpnpPrepareSecureParams(&params);
    supnp_verify(ret == SUPNP_E_SUCCESS, cleanup,
        "Error preparing Secure Params\n");

    ret = UpnpSendActionEx(Hnd,
        ActionURL,
        ServiceType,
        DevUDN,
        &params,
        Header,
        Action,
        RespNode);
    supnp_verify(ret == SUPNP_E_SUCCESS, cleanup,
        "Error in UpnpSendActionEx -- %d\n", ret);

    cleanup:
        return ret;
}

int SUpnpSendActionAsync(const int Hnd,
	const char *ActionURL,
	const char *ServiceType,
	const char *DevUDN,
	IXML_Document *Action,
    void *Fun,
	const void *Cookie)
{
    SecureParams params = {0};

    supnp_log("Secure Control: Sending Secure Action..\n");

    int ret = SUpnpPrepareSecureParams(&params);
    supnp_verify(ret == SUPNP_E_SUCCESS, cleanup,
        "Error preparing Secure Params\n");

    ret = UpnpSendActionAsync(Hnd,
        ActionURL,
        ServiceType,
        DevUDN,
        &params,
        Action,
        Fun,
        Cookie);
    supnp_verify(ret == SUPNP_E_SUCCESS, cleanup,
        "Error in UpnpSendActionAsync -- %d\n", ret);

    cleanup:
        return ret;
}

int SUpnpSendActionExAsync(const int Hnd,
	const char *ActionURL,
	const char *ServiceType,
	const char *DevUDN,
	IXML_Document *Header,
	IXML_Document *Action,
    void *Fun,
	const void *Cookie)
{
    SecureParams params = {0};

    supnp_log("Secure Control: Sending Secure Action..\n");

    int ret = SUpnpPrepareSecureParams(&params);
    supnp_verify(ret == SUPNP_E_SUCCESS, cleanup,
        "Error preparing Secure Params\n");

    ret = UpnpSendActionExAsync(Hnd,
        ActionURL,
        ServiceType,
        DevUDN,
        &params,
        Header,
        Action,
        Fun,
        Cookie);
    supnp_verify(ret == SUPNP_E_SUCCESS, cleanup,
        "Error in UpnpSendActionExAsync -- %d\n", ret);

    cleanup:
        return ret;
}

int SUpnpSecureControlVerify(const SecureParams *SParams)
{
    supnp_log("Secure Control verification..\n");
    const int ret = SUpnpVerifySecureParams("ActionSignature", SParams);
    if (ret == SUPNP_E_SUCCESS) {
        supnp_log("Secure Control successful.\n");
    } else {
        supnp_error("Secure Control failed!!!\n");
    }
    return ret;
}


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */
