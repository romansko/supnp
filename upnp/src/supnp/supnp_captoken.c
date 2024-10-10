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
#include <upnptools.h>

#if ENABLE_SUPNP

#ifdef __cplusplus
extern "C" {
#endif

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
    hex_string = binary_to_hex_string(bytes, size);
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
    captoken_t *cap_token = NULL;
    char *desc_doc = NULL;
    char *concatenate_uri = NULL; // description uri || token uri
    char *cap_token_content = NULL;
    char *cap_token_uri = NULL;
    unsigned char* bytes = NULL;
    size_t size = 0;

    /* Verifications */
    supnp_verify(p_dev, cleanup, "NULL Device.\n");
    supnp_verify(sk_ra, cleanup, "NULL RA Private Key.\n");
    supnp_verify(p_dev->name, cleanup, "NULL Device Name.\n");
    supnp_verify((p_dev->type == eDeviceType_CP) || (p_dev->type == eDeviceType_SD), cleanup, "Invalid device type\n");


    supnp_log("Generating CapToken for device '%s' - %s..\n",
        device_type_str[p_dev->type], p_dev->name);

    /* Init Cap Token */
    cap_token = cJSON_CreateObject();
    supnp_verify(cap_token, error, "cap_token initial generation failed\n");

    /* ID */
    cJSON* id = bytesToJsonString(generate_nonce(ID_SIZE), ID_SIZE);
    supnp_verify(id, error, "ID Generation failed\n");
    cJSON_AddItemToObject(cap_token, "ID", id);

    /* Timestamp */
    cJSON* _timestamp = getTimestamp();
    supnp_verify(_timestamp, error, "Timestamp Generation failed\n");
    cJSON_AddItemToObject(cap_token, CT_TIMESTAMP, _timestamp);

    /* Export RA Public Key */
    bytes = public_key_to_bytes(sk_ra, &size);
    cJSON* _pk_ra = bytesToJsonString(bytes, size);
    bytes = NULL; /* Freed in bytes_to_json_string */
    supnp_verify(_pk_ra, error, "RA Public Key exporting failed\n");
    cJSON_AddItemToObject(cap_token, RA_PK, _pk_ra);

    /* Export Device Public Key & Type */
    bytes = public_key_to_bytes(p_dev->dev_pkey, &size);
    cJSON* _pk_dev = bytesToJsonString(bytes, size);
    bytes = NULL; /* Freed in bytes_to_json_string */
    supnp_verify(_pk_dev, error, "Device Public Key exporting failed\n");
    switch (p_dev->type)
    {
    case eDeviceType_SD:
        cJSON_AddItemToObject(cap_token, SD_PK, _pk_dev);
        cJSON_AddItemToObject(cap_token, CT_TYPE, cJSON_CreateString(SD_TYPE_STR));
        break;
    case eDeviceType_CP:
        cJSON_AddItemToObject(cap_token, CP_PK, _pk_dev);
        cJSON_AddItemToObject(cap_token, CT_TYPE, cJSON_CreateString(CP_TYPE_STR));
        break;
    }

    /* Generate CapToken URI */
    supnp_verify(p_dev->cap_token_name != NULL, cleanup, "NULL cap token name\n");
    int ret = UpnpResolveURL2(p_dev->device_url, p_dev->cap_token_name , &cap_token_uri);
    supnp_verify(ret == SUPNP_E_SUCCESS, cleanup, "Error resolving Cap Token URI.\n");

    /* Sign advertisement URI (description uri || token uri) */
    if (p_dev->type == eDeviceType_SD)
    {
        supnp_verify(p_dev->desc_doc_name != NULL, cleanup, "NULL description document URI\n");
        concatenate_uri = malloc(strlen(p_dev->desc_doc_name) + strlen(cap_token_uri) + 1);
        supnp_verify(concatenate_uri, error, "concatenate_uri memory allocation failed\n");
        strcpy(concatenate_uri, p_dev->desc_doc_name);
        strcat(concatenate_uri, cap_token_uri);
        bytes = sign(sk_ra, (const unsigned char*)concatenate_uri, strlen(concatenate_uri), &size);
        cJSON* _adv_sig = bytesToJsonString(bytes, size);
        bytes = NULL; /* Freed in bytes_to_json_string */
        supnp_verify(_adv_sig, error, "Advertisement Signature exporting failed (SD)\n");
        cJSON_AddItemToObject(cap_token, CT_ADV_SIG, _adv_sig);
    }

    /* Sign Cap Token URI */
    if (p_dev->type == eDeviceType_CP)
    {
        bytes = sign(sk_ra, (const unsigned char*)cap_token_uri, strlen(cap_token_uri), &size);
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
        bytes = sign(sk_ra, (unsigned char*)desc_doc, doc_size, &size);
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
                bytes = sign(sk_ra, (unsigned char*)_id, strlen(_id), &size);
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
    bytes = sign(sk_ra, (unsigned char*)cap_token_content, strlen(cap_token_content), &size);
    cJSON* _content_sig = bytesToJsonString(bytes, size);
    bytes = NULL; /* Freed in bytes_to_json_string */
    supnp_verify(_content_sig, error, "Signing Cap Token content failed\n");
    cJSON_AddItemToObject(cap_token, RA_SIG, _content_sig);

    supnp_log("CapToken for device %s generated successfully.\n", p_dev->name);
    goto cleanup;

error:
    freeif2(cap_token, cJSON_Delete);

cleanup:
    freeif(bytes);
    freeif(cap_token_content);
    freeif(desc_doc);
    freeif(concatenate_uri);
    freeif(cap_token_uri);
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
        hex = binary_to_hex_string((unsigned char*)str, strlen(str));
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
    str = (char *)hex_string_to_binary(hex, &size);
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

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */
