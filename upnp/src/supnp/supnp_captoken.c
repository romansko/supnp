/*!
 * \addtogroup SUPnP
 *
 * \file supnp_captoken.c
 *
 * \brief source file for SUPnP CapToken algorithms. Implementing logics from
 * the paper "Kayas, G., Hossain, M., Payton, J., & Islam, S. R. (2021). SUPnP:
 * Secure Access and Service Registration for UPnP-Enabled Internet of Things.
 * IEEE Internet of Things Journal, 8(14), 11561-11580."
 *
 * \author Roman Koifman
 */
#include "supnp_captoken.h"
#include "openssl_error.h"
#include "supnp_device.h"
#include <cJSON/cJSON.h>
#include "file_utils.h"     /* write_file */
#include <openssl/evp.h>    /* EVP_PKEY_eq */
#include "httpreadwrite.h"  /* http_Download */

#if ENABLE_SUPNP

#ifdef __cplusplus
extern "C" {
#endif


/* Cap Token related */
#define ID_SIZE       11  /* As presented by the paper */
#define SD_TYPE_STR   "SERVICE-DEVICE"
#define CP_TYPE_STR   "CONTROL-POINT"
#define CT_ID         "ID"
#define CT_TYPE       "TYPE"
#define CT_TIMESTAMP  "ISSUER-INSTANT"
#define CT_RA_PK      "RA-PK"
#define CT_SD_PK      "SD-PK"
#define CT_CP_PK      "CP-PK"
#define CT_RA_SIG     "RA-SIG"
#define CT_ADV_SIG    "ADVERTISEMENT-SIG"
#define CT_DESC_SIG   "DESCRIPTION-SIG"
#define CT_URI_SIG    "LOCATION-SIG"
#define CT_SERVICES   "SERVICES"


const char *CapTokenFields[eCatTokenFieldTypesCount] = {
    CT_ID,
    CT_TYPE,
    CT_TIMESTAMP,
    CT_RA_PK,
    CT_SD_PK,
    CT_CP_PK,
    CT_RA_SIG,
    CT_ADV_SIG,
    CT_DESC_SIG,
    CT_URI_SIG,
    CT_SERVICES
};


/**
 * \brief Internal helper macro. Copy src to dst and increment dst by size.
 */
#define copy_inc(dst, src, size) \
{ \
    memcpy(dst, src, size); \
    dst += size; \
}


/*!
 * \brief Internal function to convert bytes to cJSON.
 *
 * \return cJSON object.
 */
UPNP_EXPORT_SPEC cJSON* bytesToJsonString(
    /*! [in] Bytes to convert. */
    unsigned char *bytes,
    /*! [in] Size of the bytes. */
    const size_t size)
{
    char *hex_string = NULL;
    cJSON *node = NULL;
    supnp_verify((bytes != NULL) && (size > 0), cleanup, "Invalids arguments.\n");
    hex_string = OpenSslBinaryToHexString(bytes, size);
    node = cJSON_CreateString(hex_string);
cleanup:
    freeif(hex_string);
    freeif(bytes);
    return node;
}


/**
 * Internal function to retrieve current timestamp as cJSON string
 * @return cJSON object
 */
cJSON* getTimestamp()
{
    time_t rawtime;
    time(&rawtime);
    const struct tm* timeinfo = localtime(&rawtime);
    return cJSON_CreateString(asctime(timeinfo));
}


captoken_t* SUpnpGenerateCapToken(const supnp_device_t* dev, EVP_PKEY* pkeyRA)
{
    char concatenate_url[2*LOCATION_SIZE] = {0}; // description url || token url
    captoken_t *cap_token = NULL;
    char *desc_doc = NULL;
    char *cap_token_content = NULL;

    unsigned char* bytes = NULL;
    size_t size = 0;

    /* Verifications */
    supnp_verify(dev, cleanup, "NULL Device.\n");
    supnp_verify(pkeyRA, cleanup, "NULL RA Private Key.\n");
    supnp_verify(dev->name, cleanup, "NULL Device Name.\n");
    supnp_verify((dev->type == eDeviceType_CP) ||
        (dev->type == eDeviceType_SD), cleanup, "Invalid device type\n");
    supnp_verify(dev->capTokenLocation != NULL, cleanup,
        "NULL capTokenLocation\n");
    supnp_verify(strlen(dev->capTokenLocation) < LOCATION_SIZE, cleanup,
        "capTokenLocation too long\n");

    supnp_log("Generating CapToken for device '%s' - %s..\n",
        SupnpDeviceTypeStr(dev), dev->name);

    /* Init Cap Token */
    cap_token = cJSON_CreateObject();
    supnp_verify(cap_token, error, "cap_token initial generation failed\n");

    /* ID */
    cJSON* id = bytesToJsonString(OpenSslGenerateNonce(ID_SIZE),
        ID_SIZE);
    supnp_verify(id, error, "ID Generation failed\n");
    cJSON_AddItemToObject(cap_token, "ID", id);

    /* Timestamp */
    cJSON* _timestamp = getTimestamp();
    supnp_verify(_timestamp, error, "Timestamp Generation failed\n");
    cJSON_AddItemToObject(cap_token, CT_TIMESTAMP, _timestamp);

    /* Export RA Public Key */
    bytes = OpenSslPublicKeyToBytes(pkeyRA, &size);
    cJSON* _pk_ra = bytesToJsonString(bytes, size);
    bytes = NULL; /* Freed in bytes_to_json_string */
    supnp_verify(_pk_ra, error, "RA Public Key exporting failed\n");
    cJSON_AddItemToObject(cap_token, CT_RA_PK, _pk_ra);

    /* Export Device Public Key & Type */
    bytes = OpenSslPublicKeyToBytes(dev->pkeyDevice, &size);
    cJSON* _pk_dev = bytesToJsonString(bytes, size);
    bytes = NULL; /* Freed in bytes_to_json_string */
    supnp_verify(_pk_dev, error, "Device Public Key exporting failed\n");
    switch (dev->type)
    {
        case eDeviceType_SD:
            cJSON_AddItemToObject(cap_token, CT_SD_PK, _pk_dev);
            cJSON_AddItemToObject(cap_token, CT_TYPE,
                cJSON_CreateString(SD_TYPE_STR));
            break;
        case eDeviceType_CP:
            cJSON_AddItemToObject(cap_token, CT_CP_PK, _pk_dev);
            cJSON_AddItemToObject(cap_token, CT_TYPE,
                cJSON_CreateString(CP_TYPE_STR));
            break;
        default:
            supnp_log("Device type not supported.\n");
            goto error;
    }

    /* Sign advertisement URI (description uri || token uri) */
    if (dev->type == eDeviceType_SD)
    {
        supnp_verify(dev->descDocLocation != NULL, cleanup,
            "NULL descDocLocation\n");
        supnp_verify(strlen(dev->descDocLocation) < LOCATION_SIZE, cleanup,
            "descDocLocation too long\n");

        /* Concatenate Description URL and Cap Token URL */
        strncpy(concatenate_url, dev->descDocLocation, LOCATION_SIZE);
        strncat(concatenate_url, dev->capTokenLocation, LOCATION_SIZE);

        /* Sign */
        bytes = OpenSslSign(pkeyRA, (const unsigned char*)concatenate_url,
            strlen(concatenate_url), &size);
        cJSON* _adv_sig = bytesToJsonString(bytes, size);
        bytes = NULL; /* Freed in bytes_to_json_string */
        supnp_verify(_adv_sig, error,
            "Advertisement Signature exporting failed (SD)\n");
        cJSON_AddItemToObject(cap_token, CT_ADV_SIG, _adv_sig);
    }

    /* Sign Cap Token URL */
    if (dev->type == eDeviceType_CP)
    {
        bytes = OpenSslSign(pkeyRA,
            dev->capTokenLocation,
            strlen(dev->capTokenLocation), &size);
        cJSON* _uri_sig = bytesToJsonString(bytes, size);
        bytes = NULL; /* Freed in bytes_to_json_string */
        supnp_verify(_uri_sig, error,
            "Advertisement Signature exporting failed (CP)\n");
        cJSON_AddItemToObject(cap_token, CT_URI_SIG, _uri_sig);
    }

    /* Sign Device Description Document */
    if (dev->type == eDeviceType_SD)
    {
        supnp_verify(dev->descDocument != NULL, cleanup,
            "NULL device description document\n");
        desc_doc = ixmlDocumenttoString(dev->descDocument);
        const size_t doc_size = strlen(desc_doc);
        supnp_verify(desc_doc, error, "ixmlPrintDocument failed\n");
        bytes = OpenSslSign(pkeyRA, (unsigned char*)desc_doc, doc_size, &size);
        cJSON* _doc_sig = bytesToJsonString(bytes, size);
        bytes = NULL; /* Freed in bytes_to_json_string */
        supnp_verify(_doc_sig, error,
            "Description Signature exporting failed\n");
        cJSON_AddItemToObject(cap_token, CT_DESC_SIG, _doc_sig);
    }

    /**
     * For each service in service_list do:
     *   if SD:
     *     service_sig = sign(sk_pk, hash(service_id));
     *     cap_token.add_Service(service_sig, service_type);
     *   if CP:
     *     cap_token.add_Service(service_type);
     */
    supnp_verify(dev->specDocument != NULL, cleanup,
        "NULL supnp specification document\n");
    const cJSON* service_list = cJSON_GetObjectItemCaseSensitive(
        dev->specDocument,
        "SERVICES");
    supnp_verify(service_list, cleanup,
        "Couldn't find services tagname in SUPnP Document.\n");
    cJSON* _services = dev->type == eDeviceType_SD ? cJSON_CreateObject() :
    cJSON_CreateArray();
    supnp_verify(_services, error, "Couldn't create services array\n");
    cJSON_AddItemToObject(cap_token, CT_SERVICES, _services);
    const cJSON* p_service = service_list->child;
    while (p_service != NULL)
    {
        const char* _id = p_service->string;
        const char* _type = p_service->valuestring;
        if (_id && _type)
        {
            if (dev->type == eDeviceType_SD)
            {
                bytes = OpenSslSign(pkeyRA, (unsigned char*)_id,
                    strlen(_id), &size);
                cJSON* _service_sig = bytesToJsonString(bytes, size);
                bytes = NULL; /* Freed in bytes_to_json_string */
                cJSON_AddItemToObject(_services, _type, _service_sig);
            }
            else
            {
                cJSON_AddItemToArray(_services, cJSON_CreateString(_type));
            }
        }
        p_service = p_service->next;
    }

    /* Sign the cap token's content */
    cap_token_content = cJSON_PrintUnformatted(cap_token);
    bytes = OpenSslSign(pkeyRA, (unsigned char*)cap_token_content,
        strlen(cap_token_content), &size);
    cJSON* _content_sig = bytesToJsonString(bytes, size);
    bytes = NULL; /* Freed in bytes_to_json_string */
    supnp_verify(_content_sig, error, "Signing Cap Token content failed\n");
    cJSON_AddItemToObject(cap_token, CT_RA_SIG, _content_sig);

    supnp_log("CapToken for device %s generated successfully.\n", dev->name);
    goto cleanup;

error:
    freeif2(cap_token, cJSON_Delete);

cleanup:
    freeif(bytes);
    freeif(cap_token_content);
    freeif(desc_doc);
    return cap_token;
}


void SUpnpFreeCapToken(captoken_t **p_capToken)
{
    if (p_capToken && *p_capToken)
    {
        cJSON_Delete(*p_capToken);
        *p_capToken = NULL;
    }
}


char *SUpnpCapTokenToString(const captoken_t *capToken)
{
    char *cap_token_str = NULL;
    if (capToken)
    {
        cap_token_str = cJSON_PrintUnformatted(capToken);
    }
    return cap_token_str;
}


char *SUpnpCapTokenToHexString(const captoken_t *capToken)
{
    char *str = NULL;
    char *hex = NULL;
    if (capToken)
    {
        str = SUpnpCapTokenToString(capToken);
        hex = OpenSslBinaryToHexString((unsigned char*)str, strlen(str));
        freeif(str);
    }
    return hex;
}


captoken_t *SUpnpCapTokenFromHexString(const char *hex)
{
    size_t size;
    char *str = NULL;
    captoken_t *capToken = NULL;
    if (hex == NULL)
        return NULL;
    str = (char *)OpenSslHexStringToBinary(hex, &size);
    if (str) {
        capToken = cJSON_Parse(str);
        free(str);
    }
    return capToken;
}


int SUpnpStoreCapToken(const captoken_t *capToken, const char *filepath)
{
    int ret = SUPNP_E_INTERNAL_ERROR;
    char *capTokenStr = cJSON_Print(capToken);
    if (capTokenStr && (FILE_OP_OK == write_file(
        filepath,
        (const unsigned char *)capTokenStr,
        strlen(capTokenStr)))) {
        ret = SUPNP_E_SUCCESS;
    }
    return ret;
}


int SUpnpDownloadCapToken(const char *capTokenUrl, captoken_t **p_capToken)
{
    int ret = SUPNP_E_INVALID_ARGUMENT;
    char content_type[LOCATION_SIZE] = {0};
    char *capTokenBuf = NULL;
    size_t dummy;

    supnp_verify(capTokenUrl, cleanup, "NULL capTokenUrl\n");
    supnp_verify(p_capToken, cleanup, "NULL p_capToken\n");

    *p_capToken = NULL;
    ret = http_Download(capTokenUrl,
        HTTP_DEFAULT_TIMEOUT,
        &capTokenBuf,
        &dummy,
        content_type);
    supnp_verify(ret == SUPNP_E_SUCCESS, cleanup,
        "Error downloading CapToken\n");

    *p_capToken = cJSON_Parse(capTokenBuf);
    supnp_verify(*p_capToken, cleanup, "Error parsing CapToken\n");

    ret = SUPNP_E_SUCCESS;
cleanup:
    freeif(capTokenBuf);
    return ret;
}


char *SUpnpExtractCapTokenFieldValue(const captoken_t *capToken,
    const ECapTokenFieldType type)
{
    supnp_verify(capToken != NULL, error_handle, "NULL CapToken\n");
    supnp_verify((uint)type < eCatTokenFieldTypesCount, error_handle,
        "Invalid field type\n");
    const char *fieldName = CapTokenFields[type];
    const cJSON *field = cJSON_GetObjectItemCaseSensitive(capToken, fieldName);
    supnp_verify(field != NULL, error_handle, "Field '%s' not found\n",
        fieldName);
    const char *fieldValue = cJSON_GetStringValue(field);
    supnp_verify(fieldValue != NULL, error_handle, "Field '%s' has no value\n",
        fieldName);
    return strdup(fieldValue);
error_handle:
    return NULL;
}


char *SUpnpExtractCapTokenFieldValue2(const char *capTokenUrl,
    const ECapTokenFieldType type)
{
    int ret = SUPNP_E_INVALID_ARGUMENT;
    char *fieldValue = NULL;
    captoken_t *capToken = NULL;
    supnp_verify(capTokenUrl != NULL, cleanup, "NULL capTokenUrl\n");
    supnp_verify((uint)type < eCatTokenFieldTypesCount, cleanup,
        "Invalid field type\n");
    ret = SUpnpDownloadCapToken(capTokenUrl, &capToken);
    supnp_verify(ret == SUPNP_E_SUCCESS, cleanup,
        "Error Retrieving CapToken\n");
    fieldValue = SUpnpExtractCapTokenFieldValue(capToken, type);
cleanup:
    freeif2(capToken, cJSON_Delete);
    return fieldValue;
}


int SUpnpVerifyCapToken(const captoken_t *capToken,
    EVP_PKEY *pkeyRA,
    const char *descDocContent)
{
    int ret = SUPNP_E_INVALID_ARGUMENT;
    char *ra_pk_hex = NULL;
    EVP_PKEY *ra_pk_cpy = NULL;
    char *ra_sig = NULL;
    captoken_t *cap_token_cpy = NULL;
    char *cap_token_content = NULL;
    char *desc_sig = NULL;

    supnp_log("Verifying Cap Token..\n");

    supnp_verify(capToken != NULL, cleanup, "NULL CapToken\n");
    supnp_verify(pkeyRA != NULL, cleanup, "NULL RA Public Key\n");
    supnp_verify(descDocContent != NULL, cleanup,
        "NULL Description Document\n");


    /* Verify RA Public Key is the same */
    ra_pk_hex = SUpnpExtractCapTokenFieldValue(capToken,
        eCapTokenPublicKeyRA);
    supnp_verify(ra_pk_hex, cleanup,
        "Error extracting RA Public Key from CapToken.\n");
    ra_pk_cpy = OpenSslLoadPublicKeyFromHex(ra_pk_hex);
    supnp_verify(ra_pk_cpy, cleanup,
        "Error loading RA Public Key from hex string.\n");
    ret = EVP_PKEY_eq(pkeyRA, ra_pk_cpy);
    supnp_verify(ret == OPENSSL_SUCCESS, cleanup, "RA Public Key mismatch.\n");

    /* Verify RA-SIG */
    supnp_log("Verifying RA Signature..\n");
    ra_sig = SUpnpExtractCapTokenFieldValue(capToken,
        eCapTokenSignatureRA);
    supnp_verify(ra_sig, cleanup,
        "Error extracting RA Signature from CapToken.\n");
    cap_token_cpy = cJSON_Duplicate(capToken, 1);
    supnp_verify(cap_token_cpy, cleanup, "Error duplicating CapToken.\n");
    cJSON_DeleteItemFromObject(cap_token_cpy, CT_RA_SIG);
    cap_token_content = cJSON_PrintUnformatted(cap_token_cpy);
    ret = OpenSslVerifySignature(CT_RA_SIG,
        pkeyRA,
        ra_sig,
        (unsigned char*)cap_token_content,
        strlen(cap_token_content));
    supnp_verify(ret == OPENSSL_SUCCESS, cleanup,
        "RA Signature verification failed.\n");
    supnp_log("RA Signature verified successfully.\n");


    /* Verify DESCRIPTION-SIG */
    supnp_log("Verifying Description Signature..\n");
    desc_sig = SUpnpExtractCapTokenFieldValue(capToken,
        eCapTokenSignatureDescription);
    OpenSslVerifySignature(CT_DESC_SIG,
        pkeyRA,
        desc_sig,
        (unsigned char*)descDocContent,
        strlen(descDocContent));
    supnp_verify(ret == OPENSSL_SUCCESS, cleanup,
        "Description Signature verification failed.\n");
    supnp_log("Description Signature verified successfully.\n");

    ret = SUPNP_E_SUCCESS;

cleanup:
    freeif(desc_sig);
    freeif(cap_token_content);
    SUpnpFreeCapToken(&cap_token_cpy);
    freeif(ra_sig);
    OpenSslFreePKey(&ra_pk_cpy);
    freeif(ra_pk_hex);

    return ret;
}


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */
