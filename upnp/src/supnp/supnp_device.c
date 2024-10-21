/*!
 * \addtogroup SUPnP
 *
 * \file supnp_device.c
 *
 * \brief source file for SUPnP device logics.
 *
 * \author Roman Koifman
 */
#include "supnp_device.h"
#include "openssl_wrapper.h"
#include "supnp_common.h"
#include <cJSON/cJSON.h>
#include <ixml.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "openssl_error.h"

#if ENABLE_SUPNP

#ifdef __cplusplus
extern "C" {
#endif


supnp_device_t *SupnpNewDevice(const char *specDocument,
    const char *certDevice,
    const char *certUCA)
{
    supnp_device_t *p_dev = NULL;
    char *type = NULL;
    char *name = NULL;

    supnp_verify(specDocument, cleanup, "NULL SAD/DSD provided\n");
    supnp_verify(certDevice, cleanup, "NULL Device Certificate provided\n");
    supnp_verify(certUCA, cleanup, "NULL UCA Certificate provided\n");

    p_dev = malloc(sizeof(supnp_device_t));
    supnp_verify(p_dev, cleanup, "Error allocating memory for device.\n");
    memset(p_dev, 0, sizeof(supnp_device_t));

    p_dev->specDocument = cJSON_Parse(specDocument);
    supnp_verify(p_dev->specDocument, cleanup,
        "cJSON Error parsing spec document.\n");

    p_dev->certDevice = OpenSslLoadCertificateFromString(certDevice);
    supnp_verify(p_dev->certDevice, cleanup,
        "Error loading device certificate.\n");

    p_dev->pkeyDevice = X509_get_pubkey(p_dev->certDevice);
    supnp_verify(p_dev->pkeyDevice, cleanup,
        "Error extracting device public key.\n");

    p_dev->certUCA = OpenSslLoadCertificateFromString(certUCA);
    supnp_verify(certUCA, cleanup, "Error loading UCA certificate.\n");

    p_dev->pkeyUCA = X509_get_pubkey(p_dev->certUCA);
    supnp_verify(p_dev->pkeyUCA, cleanup,
        "Error extracting uca public key.\n");

    /* Extract Device Type */
    type = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(
        p_dev->specDocument, "TYPE"));
    supnp_verify(type, cleanup, "Unexpected '%s'\n", "TYPE");
    if (!strcmp("CP", type)) {
        p_dev->type = eDeviceType_CP;
    } else if (!strcmp("SD", type)) {
        p_dev->type = eDeviceType_SD;
    } else {
        supnp_verify(NULL, cleanup, "Invalid device type '%s'.\n", type);
    }

    /* Extract ID*/
    name = cJSON_GetStringValue(
        cJSON_GetObjectItemCaseSensitive(p_dev->specDocument, "NAME"));
    supnp_verify(name, cleanup, "Unexpected '%s'\n", "NAME");
    p_dev->name = strdup(name);

    return p_dev;

cleanup:
    SupnpFreeDevice(&p_dev);
    return p_dev;
}


const char *SupnpDeviceTypeStr(const supnp_device_t *dev)
{
    if (dev == NULL) {
        return "";
    }
    switch(dev->type) {
        case eDeviceType_SD:
            return "SD";
        case eDeviceType_CP:
            return "CP";
        case eDeviceType_RA:
            return "RA";
        default:
            return "";
    }
}


void SupnpFreeDevice(supnp_device_t **p_dev)
{
    if (p_dev == NULL || *p_dev == NULL)
        return; /* Do Nothing */

    /* Remove from list */
    supnp_device_t *prev = (*p_dev)->prev;
    supnp_device_t *next = (*p_dev)->next;
    if (prev) {
        prev->next = next;
    }
    if (next) {
        next->prev = prev;
    }

    /* Free content */
    freeif((*p_dev)->name);
    freeif2((*p_dev)->certDevice, X509_free);
    freeif2((*p_dev)->certUCA, X509_free);
    freeif2((*p_dev)->pkeyDevice, EVP_PKEY_free);
    freeif2((*p_dev)->pkeyUCA, EVP_PKEY_free);
    freeif2((*p_dev)->descDocument, ixmlDocument_free);
    freeif2((*p_dev)->specDocument, cJSON_Delete);
    freeif2((*p_dev)->capToken, cJSON_Delete);
    memset((*p_dev)->descDocLocation, 0,
        sizeof((*p_dev)->descDocLocation));
    memset((*p_dev)->capTokenLocation, 0,
        sizeof((*p_dev)->capTokenLocation));
    memset((*p_dev)->nonce, 0, sizeof((*p_dev)->nonce));

    /* Free pointer */
    freeif(*p_dev);
}


void SupnpAddListDevice(supnp_device_t **p_head, supnp_device_t *dev)
{
    if (p_head == NULL || dev == NULL) /* Nothing can be done */
        return;
    if (*p_head == NULL) {
        *p_head = dev; /* new head */
    } else if (OPENSSL_SUCCESS != EVP_PKEY_eq((*p_head)->pkeyDevice,
        dev->pkeyDevice)) {
        supnp_device_t *itr = *p_head;
        while (itr->next != NULL) {
            if (OPENSSL_SUCCESS == EVP_PKEY_eq((*p_head)->pkeyDevice,
                dev->pkeyDevice)) {
                return; /* Already in List */
            }
            itr = itr->next;
        }
        itr->next = dev;
        dev->prev = itr;
    }
}


void SupnpRemoveListDevice(supnp_device_t **p_head, supnp_device_t *dev)
{
    if (p_head == NULL || dev == NULL) /* Nothing can be done */
        return;

    /* If dev is head, replace it */
    if (dev == *p_head) {
        *p_head = dev->next; /* new head */
        (*p_head)->prev = NULL;
        SupnpFreeDevice(&dev);
        return;
    }

    /* Search for dev in list and remove it */
    const supnp_device_t *itr = *p_head;
    while (itr != NULL) {
        if (itr == dev) {
            if (itr->prev) {
                itr->prev->next = itr->next;
            }
            if (itr->next) {
                itr->next->prev = itr->prev;
            }
            SupnpFreeDevice(&dev);
            return;
        }
        itr = itr->next;
    }
}


supnp_device_t *SupnpFindDeviceByPublicKey(supnp_device_t *head,
    const EVP_PKEY *pkey)
{
    if (head == NULL || pkey == NULL) /* Nothing can be done */
        return NULL;
    supnp_device_t *itr = head;
    while (itr != NULL) {
        if (OPENSSL_SUCCESS == EVP_PKEY_eq(itr->pkeyDevice, pkey)) {
            return itr;
        }
        itr = itr->next;
    }
    return NULL;
}


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */
