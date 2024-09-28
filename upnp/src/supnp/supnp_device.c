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
#include "supnp_err.h"
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <ixml.h>
#include <cJSON/cJSON.h>
#include "openssl_wrapper.h"

#ifdef ENABLE_SUPNP

#ifdef __cplusplus
extern "C" {
#endif

supnp_device_t* new_supnp_device(const char* spec_doc, const char* cert, const char* uca_cert)
{
    supnp_device_t* p_dev = NULL;
    char * type = NULL;
    char * id = NULL;

    supnp_verify(spec_doc, cleanup, "NULL SAD/DSD provided\n");
    supnp_verify(cert, cleanup, "NULL Device Certificate provided\n");
    supnp_verify(uca_cert, cleanup, "NULL UCA Certificate provided\n");

    p_dev = malloc(sizeof(supnp_device_t));
    supnp_verify(p_dev, cleanup, "Error allocating memory for device.\n");
    memset(p_dev, 0, sizeof(supnp_device_t));

    p_dev->supnp_doc = cJSON_Parse(spec_doc);
    supnp_verify(p_dev->supnp_doc, cleanup, "cJSON Error parsing spec document.\n");

    p_dev->dev_cert = load_certificate_from_str(cert);
    supnp_verify(p_dev->dev_cert , cleanup, "Error loading device certificate.\n");

    p_dev->uca_cert = load_certificate_from_str(uca_cert);
    supnp_verify(uca_cert, cleanup, "Error loading UCA certificate.\n");

    /* Extract Device Type */
    type = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(p_dev->supnp_doc, "TYPE"));
    supnp_verify(type, cleanup, "Unexpected '%s'\n", "TYPE");
    if (!strcmp("CP", type)) {
        p_dev->type = DEVICE_TYPE_CP;
    } else if (!strcmp("SD", type)) {
        p_dev->type = DEVICE_TYPE_SD;
    } else {
        supnp_verify(NULL, cleanup, "Invalid device type '%s'.\n", type);
    }

    /* Extract ID*/
    id = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(p_dev->supnp_doc, "NAME"));
    supnp_verify(id, cleanup, "Unexpected '%s'\n", "NAME");
    p_dev->id = strdup(id);

    return p_dev;

cleanup:
    supnp_free_device_content(p_dev);
    return p_dev;
}

const char* supnp_device_type_str(const EDeviceType type)
{
    switch (type)
    {
    case DEVICE_TYPE_SD:
        return "SD";
    case DEVICE_TYPE_CP:
        return "CP";
    default:
        return "";
    }
}

void supnp_free_device_content(supnp_device_t* p_dev)
{
    if (p_dev == NULL)
        return; /* Do Nothing */
    freeif(p_dev->id);
    freeif2(p_dev->pk, EVP_PKEY_free);
    freeif2(p_dev->sk, EVP_PKEY_free);
    freeif2(p_dev->dev_cert, X509_free);
    freeif2(p_dev->uca_cert, X509_free);
    freeif(p_dev->desc_uri);
    freeif2(p_dev->desc_doc, ixmlDocument_free);
    freeif2(p_dev->supnp_doc, cJSON_Delete);
    freeif(p_dev->cap_token_uri);
}

void supnp_free_device(supnp_device_t** pp_dev)
{
    if (pp_dev == NULL)
        return; /* Do Nothing */
    supnp_device_t *prev = (*pp_dev)->prev;
    supnp_device_t *next = (*pp_dev)->next;
    if (prev) {
        prev->next = next;
    }
    if (next) {
        next->prev = prev;
    }
    supnp_free_device_content(*pp_dev);
    freeif(*pp_dev);
}

/*
 * todo: consider refreshing device addition to list instead of blocking.
 */
void add_list_device(supnp_device_t** head, supnp_device_t *p_dev)
{
    if (head == NULL || p_dev == NULL) /* Nothing can be done */
        return;
    if (*head == NULL) {
        *head = p_dev; /* new head */
    }
    else if (strcmp((*head)->id, p_dev->id) != 0) {
        supnp_device_t *itr = *head;
        while (itr->next != NULL) {
            if (!strcmp(itr->id,p_dev->id)) {
                return; /* Already in List */
            }
            itr = itr->next;
        }
        itr->next = p_dev;
        p_dev->prev = itr;
    }
}

void remove_list_device(supnp_device_t** head, supnp_device_t *p_dev)
{
    if (head == NULL || p_dev == NULL) /* Nothing can be done */
        return;
    if (p_dev == *head) {
        *head = p_dev->next; /* new head */
    }
    supnp_free_device(&p_dev);
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */
