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
#include "supnp.h"
#include "supnp_captoken.h"
#include "supnp_device.h"
#include "supnp_err.h"
#include <cJSON/cJSON.h>
#include <ixml.h>


// todo: refactor to openssl_wrapper
#include <openssl/x509.h>
//

#ifdef __cplusplus
extern "C" {
#endif

#define supnp_extract_json_string(doc, key, value, label) \
{ \
    value = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(doc, key)); \
    supnp_verify(value, label, "Unexpected '%s'\n", key); \
}

/**
 * Initialize SUPnP secure layer.
 * @return SUPNP_E_SUCCESS on success, SUPNP_E_INTERNAL_ERROR on failure.
 */
int SUpnpInit()
{
    supnp_log("Initializing SUPnP secure layer..\n");
    supnp_verify(init_openssl_wrapper() == OPENSSL_SUCCESS, cleanup, "Error initializing OpenSSL.\n");

    // SUpnp_test_registration();

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
int verify_supnp_document(EVP_PKEY* ca_pkey, supnp_device_t* p_dev)
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
    const cJSON* json_services = cJSON_GetObjectItemCaseSensitive(p_dev->supnp_doc, SUPNP_DOC_SERVICES);
    supnp_verify(json_services, cleanup,
                 "Couldn't find services tagname '%s' in SUPnP Document.\n", SUPNP_DOC_SERVICES);

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


#if SUPNP_TEST

void test_nonce_encryption(EVP_PKEY* pk, EVP_PKEY* sk)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char* nonce = NULL;
    unsigned char* enc_nonce = NULL;
    unsigned char* dec_nonce = NULL;
    unsigned char* enc_hash = NULL;
    unsigned char* dec_hash = NULL;
    size_t enc_len = 0;
    size_t dec_len = 0;
    size_t ehash_len = 0;
    size_t dhash_len = 0;
    supnp_verify(pk && sk, cleanup, "NULL keys\n");

    /* Generates a nonce  */
    nonce = generate_nonce(OPENSSL_CSPRNG_SIZE);
    supnp_verify(nonce, cleanup, "Error generating nonce.\n");
    supnp_log("Generated nonce: ");    // todo upnp_log DEBUG
    print_as_hex(nonce, OPENSSL_CSPRNG_SIZE);

    /* Encrypt the challenge using the participant's public key */
    enc_nonce = encrypt_asym(pk, &enc_len, nonce, OPENSSL_CSPRNG_SIZE);
    supnp_verify(enc_nonce, cleanup, "Error encrypting nonce.\n");
    supnp_log("Encrypted nonce: ");    // todo upnp_log DEBUG
    print_as_hex(enc_nonce, enc_len);

    /* Decrypt the challenge using the participant's private key */
    dec_nonce = decrypt_asym(sk, &dec_len, enc_nonce, enc_len);
    supnp_verify(dec_nonce, cleanup, "Error decrypting nonce.\n");
    supnp_log("Decrypted nonce: ");    // todo upnp_log DEBUG
    print_as_hex(dec_nonce, dec_len);

    /* hash the nonce N (HN = Hash(N)). */
    supnp_verify(do_sha256(hash, nonce, OPENSSL_CSPRNG_SIZE) == OPENSSL_SUCCESS, cleanup, "Error hashing nonce.\n");
    supnp_log("Hash(nonce): ");    // todo upnp_log DEBUG
    print_as_hex(hash, SHA256_DIGEST_LENGTH);

    /* Encrypt the nonce hash with participant's private key (signed response) */
    enc_hash = encrypt_asym(sk, &ehash_len, hash, SHA256_DIGEST_LENGTH);
    supnp_verify(enc_hash, cleanup, "Error encrypting hash(nonce).\n");
    supnp_log("Encrypted Hash(nonce): ");    // todo upnp_log DEBUG
    print_as_hex(enc_hash, SHA256_DIGEST_LENGTH);

    /* Decrypt the response using the public key */
    dec_hash = decrypt_asym(sk, &dhash_len, enc_hash, ehash_len);
    supnp_verify(dec_hash, cleanup, "Error decrypting hash(nonce).\n");
    supnp_log("Decrypted Hash(nonce): ");    // todo upnp_log DEBUG
    print_as_hex(dec_hash, SHA256_DIGEST_LENGTH);

    /* Verify hashes matches */
    supnp_verify(memcmp(nonce, dec_nonce, OPENSSL_CSPRNG_SIZE) == 0, cleanup,
                 "Decrypted nonce doesn't match the original nonce.\n");
    supnp_verify(memcmp(hash, dec_hash, SHA256_DIGEST_LENGTH) == 0, cleanup,
                 "Decrypted nonce hash doesn't match the original hash.\n");
    supnp_log("nonce encryption test ok.\n");

cleanup:
    freeif(dec_hash);
    freeif(enc_hash);
    freeif(dec_nonce);
    freeif(enc_nonce);
    freeif(nonce);
}

void test_captoken_generation(const supnp_device_t* dev, EVP_PKEY* ra_sk)
{
    cJSON* token = NULL;
    supnp_verify((dev->type == DEVICE_TYPE_CP) || (dev->type == DEVICE_TYPE_SD), cleanup, "Invalid device type\n");
    supnp_verify(ra_sk, cleanup, "NULL RA PK\n");
    token = generate_cap_token(dev, ra_sk);
    supnp_verify(token, cleanup, "Error generating %s's capability token\n", supnp_device_type_str(dev->type));
    supnp_log("%s's Capability Token: %s\n", supnp_device_type_str(dev->type), cJSON_Print(token)); // todo upnp_log DEBUG
cleanup:
    freeif2(token, cJSON_Delete);
}

#endif /* SUPNP_TEST */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */
