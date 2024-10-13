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
#include "openssl_wrapper.h"
#include "supnp_device.h"
#include "supnp_err.h"

#include <cJSON/cJSON.h>
#include <file_utils.h>
#include <ixml.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <upnp.h>
#include <upnptools.h>

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
 * Copy src to dst and increment dst by size
 * @param dst destination buffer
 * @param src source buffer
 * @param size size of source buffer
 */
#define copy_inc(dst, src, size) \
{ \
    memcpy(dst, src, size); \
    dst += size; \
}

captoken_t *loadCapTokenString(const char *capTokenStr)
{
    return cJSON_Parse(capTokenStr);
}

/**
 * Helper function to convert string to cJSON.
 * @note the function free the input string.
 * @param string input string
 * @return cJSON object on success, NULL on failure
 */
cJSON* stringToJsonString(char* string)
{
    cJSON* node = NULL;
    supnp_verify(string != NULL, cleanup, "NULL string\n");
    node = cJSON_CreateString(string);
cleanup:
    freeif(string);
    return node;
}

/**
 * Helper function to convert bytes to cJSON.
 * @note the function free the input bytes.
 * @param bytes input bytes
 * @param size size of input bytes
 * @return cJSON object on success, NULL on failure
 */
cJSON* bytesToJsonString(unsigned char* bytes, size_t size)
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

cJSON* getTimestamp()
{
    time_t rawtime;
    time(&rawtime);
    const struct tm* timeinfo = localtime(&rawtime);
    return cJSON_CreateString(asctime(timeinfo));
}

/**
 * Generate a CapToken for a Service Device which consists of:
 *   ID - Random Token ID
 *   ISSUER_INSTANT - Current time
 *   RA_PK - RA Public Key
 *   SD_PK - SD Public Key
 *   RA_SIG - RA Signature on Cap Token's content
 *   TYPE - "SERVICE-DEVICE"
 *   ADV_SIG - RA Signature on (description uri || cap token uri).
 *   SERVICES - List of service types and corresponding signature by RA on their
 * ID. Note: This differs from the paper, where the signature is on the
 * description.
 *
 * @param p_dev device information
 * @param sk_ra RA private key
 * @return CapToken on success, NULL on failure
 */
captoken_t* generateCapToken(const supnp_device_t* p_dev, EVP_PKEY* sk_ra)
{
    int ret = SUPNP_E_INVALID_ARGUMENT;
    captoken_t *cap_token = NULL;
    char *desc_doc = NULL;
    char *desc_doc_url = NULL;
    char *cap_token_url = NULL;
    char *concatenate_url = NULL; // description url || token url
    char *cap_token_content = NULL;

    unsigned char* bytes = NULL;
    size_t size = 0;

    /* Verifications */
    supnp_verify(p_dev, cleanup, "NULL Device.\n");
    supnp_verify(sk_ra, cleanup, "NULL RA Private Key.\n");
    supnp_verify(p_dev->name, cleanup, "NULL Device Name.\n");
    supnp_verify((p_dev->type == eDeviceType_CP) || (p_dev->type == eDeviceType_SD), cleanup, "Invalid device type\n");
    supnp_verify(p_dev->device_url != NULL, cleanup, "NULL device_url\n");

    supnp_log("Generating CapToken for device '%s' - %s..\n",
        device_type_str[p_dev->type], p_dev->name);

    /* Init Cap Token */
    cap_token = cJSON_CreateObject();
    supnp_verify(cap_token, error, "cap_token initial generation failed\n");

    /* ID */
    cJSON* id = bytesToJsonString(OpenSslGenerateNonce(ID_SIZE), ID_SIZE);
    supnp_verify(id, error, "ID Generation failed\n");
    cJSON_AddItemToObject(cap_token, "ID", id);

    /* Timestamp */
    cJSON* _timestamp = getTimestamp();
    supnp_verify(_timestamp, error, "Timestamp Generation failed\n");
    cJSON_AddItemToObject(cap_token, CT_TIMESTAMP, _timestamp);

    /* Export RA Public Key */
    bytes = OpenSslPublicKeyToBytes(sk_ra, &size);
    cJSON* _pk_ra = bytesToJsonString(bytes, size);
    bytes = NULL; /* Freed in bytes_to_json_string */
    supnp_verify(_pk_ra, error, "RA Public Key exporting failed\n");
    cJSON_AddItemToObject(cap_token, CT_RA_PK, _pk_ra);

    /* Export Device Public Key & Type */
    bytes = OpenSslPublicKeyToBytes(p_dev->dev_pkey, &size);
    cJSON* _pk_dev = bytesToJsonString(bytes, size);
    bytes = NULL; /* Freed in bytes_to_json_string */
    supnp_verify(_pk_dev, error, "Device Public Key exporting failed\n");
    switch (p_dev->type)
    {
    case eDeviceType_SD:
        cJSON_AddItemToObject(cap_token, CT_SD_PK, _pk_dev);
        cJSON_AddItemToObject(cap_token, CT_TYPE, cJSON_CreateString(SD_TYPE_STR));
        break;
    case eDeviceType_CP:
        cJSON_AddItemToObject(cap_token, CT_CP_PK, _pk_dev);
        cJSON_AddItemToObject(cap_token, CT_TYPE, cJSON_CreateString(CP_TYPE_STR));
        break;
    }

    /* Generate CapToken URL */
    supnp_verify(p_dev->cap_token_name != NULL, cleanup, "NULL cap_token_name\n");
    ret = UpnpResolveURL2(p_dev->device_url, p_dev->cap_token_name , &cap_token_url);
    supnp_verify(ret == SUPNP_E_SUCCESS, cleanup, "Error resolving Cap Token URL.\n");

    /* Sign advertisement URI (description uri || token uri) */
    if (p_dev->type == eDeviceType_SD)
    {

        /* Generate Description Document URL */
        supnp_verify(p_dev->desc_doc_name != NULL, cleanup, "NULL desc_doc_name\n");
        ret = UpnpResolveURL2(p_dev->device_url, p_dev->desc_doc_name , &desc_doc_url);
        supnp_verify(ret == SUPNP_E_SUCCESS, cleanup, "Error resolving description Document URL.\n");

        /* Concatenate Description URL and Cap Token URL */
        concatenate_url = malloc(strlen(desc_doc_url) + strlen(cap_token_url) + 1);
        supnp_verify(concatenate_url, error, "concatenate_uri memory allocation failed\n");
        strcpy(concatenate_url, desc_doc_url);
        strcat(concatenate_url, cap_token_url);

        /* Sign */
        bytes = OpenSslSign(sk_ra, (const unsigned char*)concatenate_url, strlen(concatenate_url), &size);
        cJSON* _adv_sig = bytesToJsonString(bytes, size);
        bytes = NULL; /* Freed in bytes_to_json_string */
        supnp_verify(_adv_sig, error, "Advertisement Signature exporting failed (SD)\n");
        cJSON_AddItemToObject(cap_token, CT_ADV_SIG, _adv_sig);
    }

    /* Sign Cap Token URI */
    if (p_dev->type == eDeviceType_CP)
    {
        bytes = OpenSslSign(sk_ra, (const unsigned char*)cap_token_url, strlen(cap_token_url), &size);
        cJSON* _uri_sig = bytesToJsonString(bytes, size);
        bytes = NULL; /* Freed in bytes_to_json_string */
        supnp_verify(_uri_sig, error, "Advertisement Signature exporting failed (CP)\n");
        cJSON_AddItemToObject(cap_token, CT_URI_SIG, _uri_sig);
    }

    /* Sign Device Description Document */
    if (p_dev->type == eDeviceType_SD)
    {
        supnp_verify(p_dev->desc_doc != NULL, cleanup, "NULL device description document\n");
        desc_doc = ixmlDocumenttoString(p_dev->desc_doc);
        const size_t doc_size = strlen(desc_doc);
        supnp_verify(desc_doc, error, "ixmlPrintDocument failed\n");
        bytes = OpenSslSign(sk_ra, (unsigned char*)desc_doc, doc_size, &size);
        cJSON* _doc_sig = bytesToJsonString(bytes, size);
        bytes = NULL; /* Freed in bytes_to_json_string */
        supnp_verify(_doc_sig, error, "Description Signature exporting failed\n");
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
    supnp_verify(p_dev->supnp_doc != NULL, cleanup, "NULL supnp specification document\n");
    const cJSON* service_list = cJSON_GetObjectItemCaseSensitive(p_dev->supnp_doc, "SERVICES");
    supnp_verify(service_list, cleanup, "Couldn't find services tagname in SUPnP Document.\n");
    cJSON* _services = p_dev->type == eDeviceType_SD ? cJSON_CreateObject() : cJSON_CreateArray();
    supnp_verify(_services, error, "Couldn't create services array\n");
    cJSON_AddItemToObject(cap_token, CT_SERVICES, _services);
    const cJSON* p_service = service_list->child;
    while (p_service != NULL)
    {
        const char* _id = p_service->string;
        const char* _type = p_service->valuestring;
        if (_id && _type)
        {
            if (p_dev->type == eDeviceType_SD)
            {
                bytes = OpenSslSign(sk_ra, (unsigned char*)_id, strlen(_id), &size);
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
    bytes = OpenSslSign(sk_ra, (unsigned char*)cap_token_content, strlen(cap_token_content), &size);
    cJSON* _content_sig = bytesToJsonString(bytes, size);
    bytes = NULL; /* Freed in bytes_to_json_string */
    supnp_verify(_content_sig, error, "Signing Cap Token content failed\n");
    cJSON_AddItemToObject(cap_token, CT_RA_SIG, _content_sig);

    supnp_log("CapToken for device %s generated successfully.\n", p_dev->name);
    goto cleanup;

error:
    freeif2(cap_token, cJSON_Delete);

cleanup:
    freeif(bytes);
    freeif(cap_token_content);
    freeif(desc_doc);
    freeif(concatenate_url);
    freeif(cap_token_url);
    return cap_token;
}

/**
 * Free a CapToken
 * @param cap_token CapToken to free
 */
void freeCapToken(captoken_t **cap_token)
{
    if (cap_token && *cap_token)
    {
        cJSON_Delete(*cap_token);
        *cap_token = NULL;
    }
}

/**
 * Convert CapToken to string
 * @param cap_token CapToken to convert
 * @note the caller is responsible to free the returned string
 * @return CapToken as string on success, NULL on failure
 */
char *capTokenToString(const captoken_t *cap_token)
{
    char *cap_token_str = NULL;
    if (cap_token)
    {
        cap_token_str = cJSON_PrintUnformatted(cap_token);
    }
    return cap_token_str;
}

/**
 * Convert CapToken to hex string
 * @param cap_token CapToken to convert
 * @note the caller is responsible to free the returned string
 * @return CapToken as hex string on success, NULL on failure
 */
char *capTokenToHexString(const captoken_t *cap_token)
{
    char *str = NULL;
    char *hex = NULL;
    if (cap_token)
    {
        str = capTokenToString(cap_token);
        hex = OpenSslBinaryToHexString((unsigned char*)str, strlen(str));
        freeif(str);
    }
    return hex;
}

/**
 * Convert string to CapToken
 * @param cap_token_str CapToken as string
 * @return CapToken on success, NULL on failure
 */
captoken_t *capTokenFromString(const char *cap_token_str)
{
    if (cap_token_str == NULL)
        return NULL;
    return cJSON_Parse(cap_token_str);
}

/**
 * Convert hex string to CapToken
 * @param hex CapToken as hex string
 * @return CapToken on success, NULL on failure
 */
captoken_t *capTokenFromHexString(const char *hex)
{
    size_t size;
    char *str = NULL;
    captoken_t *capToken = NULL;
    if (hex == NULL)
        return NULL;
    str = (char *)OpenSslHexStringToBinary(hex, &size);
    capToken = capTokenFromString(str);
    freeif(str);
    return capToken;
}

/**
 * Store CapToken to file
 * @param capToken CapToken to store
 * @param filepath path to CapToken file
 * @return FILE_OP_OK on success, FILE_OP_ERR on failure
 */
int storeCapToken(const captoken_t *capToken, const char *filepath)
{
    char *capTokenStr = cJSON_Print(capToken);
    int ret = write_file(filepath, (const unsigned char *)capTokenStr, strlen(capTokenStr));
    freeif(capTokenStr);
    return ret;
}

/**
 * Download CapToken from url
 * @param capTokenUrl CapToken URL
 * @param ppCapToken CapToken to store
 * @return SUPNP_E_SUCCESS on success, SUPNP_E_ERROR on failure
 */
int downloadCapToken(const char *capTokenUrl, captoken_t **ppCapToken)
{
    int ret = UPNP_E_INVALID_PARAM;
    char content_type[LINE_SIZE] = {0};
    char *capTokenBuf = NULL;
    *ppCapToken = NULL;
    ret = UpnpDownloadUrlItem(capTokenUrl, &capTokenBuf, content_type);
    supnp_verify(ret == SUPNP_E_SUCCESS, cleanup, "Error downloading CapToken\n");
    *ppCapToken = cJSON_Parse(capTokenBuf);
    supnp_verify(*ppCapToken, cleanup, "Error parsing CapToken\n");
    ret = SUPNP_E_SUCCESS;
cleanup:
    freeif(capTokenBuf);
    return ret;
}

/**
 * Extract Field Value from CapToken. User is responsible to free the returned value.
 * @cap_token CapToken to extract from
 * @type Field type to extract
 * @return Field Value on success, NULL on failure
 */
char *extractCapTokenFieldValue(const captoken_t *cap_token, const ECapTokenFieldType type)
{
    supnp_verify(cap_token != NULL, error_handle, "NULL CapToken\n");
    supnp_verify((uint)type < eCatTokenFieldTypesCount, error_handle, "Invalid field type\n");
    const char *fieldName = CapTokenFields[type];
    const cJSON *field = cJSON_GetObjectItemCaseSensitive(cap_token, fieldName);
    supnp_verify(field != NULL, error_handle, "Field '%s' not found\n", fieldName);
    const char *fieldValue = cJSON_GetStringValue(field);
    supnp_verify(fieldValue != NULL, error_handle, "Field '%s' has no value\n", fieldName);
    return strdup(fieldValue);
error_handle:
    return NULL;
}

/**
 * Extract Field Value from CapToken URL. User is responsible to free the returned value.
 * @capTokenUrl CapToken URL to extract from
 * @type Field type to extract
 * @return Field Value on success, NULL on failure
 */
char *extractCapTokenFieldValue2(const char *capTokenUrl, const ECapTokenFieldType type)
{
    int ret = SUPNP_E_INVALID_ARGUMENT;
    char *fieldValue = NULL;
    captoken_t *capToken = NULL;
    supnp_verify(capTokenUrl != NULL, cleanup, "NULL capTokenUrl\n");
    supnp_verify((uint)type < eCatTokenFieldTypesCount, cleanup, "Invalid field type\n");
    ret = downloadCapToken(capTokenUrl, &capToken);
    supnp_verify(ret == SUPNP_E_SUCCESS, cleanup, "Error Retrieving CapToken\n");
    fieldValue = extractCapTokenFieldValue(capToken, type);
cleanup:
    freeif2(capToken, cJSON_Delete);
    return fieldValue;
}

/**
 * Verify CapToken as part of Secure Device Description.
 * @param cap_token CapToken to verify
 * @param ra_pk RA Public Key
 * @param desc_doc_content Device Description Document
 * @return SUPNP_E_SUCCESS on success, SUPNP_E_ERROR on failure
 */
int verifyCapToken(const captoken_t *cap_token, EVP_PKEY *ra_pk, const char *desc_doc_content)
{
    int ret = SUPNP_E_INVALID_ARGUMENT;
    char *ra_pk_hex = NULL;
    EVP_PKEY *ra_pk_cpy = NULL;
    char *ra_sig = NULL;
    captoken_t *cap_token_cpy = NULL;
    char *cap_token_content = NULL;
    char *desc_sig = NULL;

    supnp_log("Verifying Cap Token..\n");

    supnp_verify(cap_token != NULL, cleanup, "NULL CapToken\n");
    supnp_verify(ra_pk != NULL, cleanup, "NULL RA Public Key\n");
    supnp_verify(desc_doc_content != NULL, cleanup, "NULL Description Document\n");


    /* Verify RA Public Key is the same */
    ra_pk_hex = extractCapTokenFieldValue(cap_token, eCapTokenPublicKeyRA);
    supnp_verify(ra_pk_hex, cleanup, "Error extracting RA Public Key from CapToken.\n");
    ra_pk_cpy = OpenSslLoadPublicKeyFromHex(ra_pk_hex);
    supnp_verify(ra_pk_cpy, cleanup, "Error loading RA Public Key from hex string.\n");
    ret = EVP_PKEY_eq(ra_pk, ra_pk_cpy);
    supnp_verify(ret == OPENSSL_SUCCESS, cleanup, "RA Public Key mismatch.\n");

    /* Verify RA-SIG */
    supnp_log("Verifying RA Signature..\n");
    ra_sig = extractCapTokenFieldValue(cap_token, eCapTokenSignatureRA);
    supnp_verify(ra_sig, cleanup, "Error extracting RA Signature from CapToken.\n");
    cap_token_cpy = cJSON_Duplicate(cap_token, 1);
    supnp_verify(cap_token_cpy, cleanup, "Error duplicating CapToken.\n");
    cJSON_DeleteItemFromObject(cap_token_cpy, CT_RA_SIG);
    cap_token_content = cJSON_PrintUnformatted(cap_token_cpy);
    ret = OpenSslVerifySignature(CT_RA_SIG,
        ra_pk,
        ra_sig,
        (unsigned char*)cap_token_content,
        strlen(cap_token_content));
    supnp_verify(ret == OPENSSL_SUCCESS, cleanup,
        "RA Signature verification failed.\n");
    supnp_log("RA Signature verified successfully.\n");


    /* Verify DESCRIPTION-SIG */
    supnp_log("Verifying Description Signature..\n");
    desc_sig = extractCapTokenFieldValue(cap_token, eCapTokenSignatureDescription);
    OpenSslVerifySignature(CT_DESC_SIG,
        ra_pk,
        desc_sig,
        (unsigned char*)desc_doc_content,
        strlen(desc_doc_content));
    supnp_verify(ret == OPENSSL_SUCCESS, cleanup,
        "Description Signature verification failed.\n");
    supnp_log("Description Signature verified successfully.\n");

    ret = SUPNP_E_SUCCESS;

cleanup:
    freeif(desc_sig);
    freeif(cap_token_content);
    freeCapToken(&cap_token_cpy);
    freeif(ra_sig);
    freeif2(ra_pk_cpy, EVP_PKEY_free);
    freeif(ra_pk_hex);

    return ret;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */
