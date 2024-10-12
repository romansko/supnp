#ifndef UPNPDISCOVERY_H
#define UPNPDISCOVERY_H

/*!
 * \file
 *
 * \brief Header file for UpnpDiscovery methods.
 *
 * Do not edit this file, it is automatically generated. Please look at
 * generator.c.
 *
 * \author Marcelo Roberto Jimenez
 */
#include <stdlib.h> /* for size_t */

#include "UpnpGlobal.h" /* for UPNP_EXPORT_SPEC */

#include "UpnpInet.h"
#include "UpnpString.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*!
 * UpnpDiscovery
 */
typedef struct s_UpnpDiscovery UpnpDiscovery;

/*! Constructor */
UPNP_EXPORT_SPEC UpnpDiscovery *UpnpDiscovery_new();
/*! Destructor */
UPNP_EXPORT_SPEC void UpnpDiscovery_delete(UpnpDiscovery *p);
/*! Copy Constructor */
UPNP_EXPORT_SPEC UpnpDiscovery *UpnpDiscovery_dup(const UpnpDiscovery *p);
/*! Assignment operator */
UPNP_EXPORT_SPEC int UpnpDiscovery_assign(
    UpnpDiscovery *p, const UpnpDiscovery *q);

/*! UpnpDiscovery_get_ErrCode */
UPNP_EXPORT_SPEC int UpnpDiscovery_get_ErrCode(const UpnpDiscovery *p);
/*! UpnpDiscovery_set_ErrCode */
UPNP_EXPORT_SPEC int UpnpDiscovery_set_ErrCode(UpnpDiscovery *p, int n);

/*! UpnpDiscovery_get_Expires */
UPNP_EXPORT_SPEC int UpnpDiscovery_get_Expires(const UpnpDiscovery *p);
/*! UpnpDiscovery_set_Expires */
UPNP_EXPORT_SPEC int UpnpDiscovery_set_Expires(UpnpDiscovery *p, int n);

/*! UpnpDiscovery_get_DeviceID */
UPNP_EXPORT_SPEC const UpnpString *UpnpDiscovery_get_DeviceID(
    const UpnpDiscovery *p);
/*! UpnpDiscovery_set_DeviceID */
UPNP_EXPORT_SPEC int UpnpDiscovery_set_DeviceID(
    UpnpDiscovery *p, const UpnpString *s);
/*! UpnpDiscovery_get_DeviceID_Length */
UPNP_EXPORT_SPEC size_t UpnpDiscovery_get_DeviceID_Length(
    const UpnpDiscovery *p);
/*! UpnpDiscovery_get_DeviceID_cstr */
UPNP_EXPORT_SPEC const char *UpnpDiscovery_get_DeviceID_cstr(
    const UpnpDiscovery *p);
/*! UpnpDiscovery_strcpy_DeviceID */
UPNP_EXPORT_SPEC int UpnpDiscovery_strcpy_DeviceID(
    UpnpDiscovery *p, const char *s);
/*! UpnpDiscovery_strncpy_DeviceID */
UPNP_EXPORT_SPEC int UpnpDiscovery_strncpy_DeviceID(
    UpnpDiscovery *p, const char *s, size_t n);
/*! UpnpDiscovery_clear_DeviceID */
UPNP_EXPORT_SPEC void UpnpDiscovery_clear_DeviceID(UpnpDiscovery *p);

/*! UpnpDiscovery_get_DeviceType */
UPNP_EXPORT_SPEC const UpnpString *UpnpDiscovery_get_DeviceType(
    const UpnpDiscovery *p);
/*! UpnpDiscovery_set_DeviceType */
UPNP_EXPORT_SPEC int UpnpDiscovery_set_DeviceType(
    UpnpDiscovery *p, const UpnpString *s);
/*! UpnpDiscovery_get_DeviceType_Length */
UPNP_EXPORT_SPEC size_t UpnpDiscovery_get_DeviceType_Length(
    const UpnpDiscovery *p);
/*! UpnpDiscovery_get_DeviceType_cstr */
UPNP_EXPORT_SPEC const char *UpnpDiscovery_get_DeviceType_cstr(
    const UpnpDiscovery *p);
/*! UpnpDiscovery_strcpy_DeviceType */
UPNP_EXPORT_SPEC int UpnpDiscovery_strcpy_DeviceType(
    UpnpDiscovery *p, const char *s);
/*! UpnpDiscovery_strncpy_DeviceType */
UPNP_EXPORT_SPEC int UpnpDiscovery_strncpy_DeviceType(
    UpnpDiscovery *p, const char *s, size_t n);
/*! UpnpDiscovery_clear_DeviceType */
UPNP_EXPORT_SPEC void UpnpDiscovery_clear_DeviceType(UpnpDiscovery *p);

/*! UpnpDiscovery_get_ServiceType */
UPNP_EXPORT_SPEC const UpnpString *UpnpDiscovery_get_ServiceType(
    const UpnpDiscovery *p);
/*! UpnpDiscovery_set_ServiceType */
UPNP_EXPORT_SPEC int UpnpDiscovery_set_ServiceType(
    UpnpDiscovery *p, const UpnpString *s);
/*! UpnpDiscovery_get_ServiceType_Length */
UPNP_EXPORT_SPEC size_t UpnpDiscovery_get_ServiceType_Length(
    const UpnpDiscovery *p);
/*! UpnpDiscovery_get_ServiceType_cstr */
UPNP_EXPORT_SPEC const char *UpnpDiscovery_get_ServiceType_cstr(
    const UpnpDiscovery *p);
/*! UpnpDiscovery_strcpy_ServiceType */
UPNP_EXPORT_SPEC int UpnpDiscovery_strcpy_ServiceType(
    UpnpDiscovery *p, const char *s);
/*! UpnpDiscovery_strncpy_ServiceType */
UPNP_EXPORT_SPEC int UpnpDiscovery_strncpy_ServiceType(
    UpnpDiscovery *p, const char *s, size_t n);
/*! UpnpDiscovery_clear_ServiceType */
UPNP_EXPORT_SPEC void UpnpDiscovery_clear_ServiceType(UpnpDiscovery *p);

/*! UpnpDiscovery_get_ServiceVer */
UPNP_EXPORT_SPEC const UpnpString *UpnpDiscovery_get_ServiceVer(
    const UpnpDiscovery *p);
/*! UpnpDiscovery_set_ServiceVer */
UPNP_EXPORT_SPEC int UpnpDiscovery_set_ServiceVer(
    UpnpDiscovery *p, const UpnpString *s);
/*! UpnpDiscovery_get_ServiceVer_Length */
UPNP_EXPORT_SPEC size_t UpnpDiscovery_get_ServiceVer_Length(
    const UpnpDiscovery *p);
/*! UpnpDiscovery_get_ServiceVer_cstr */
UPNP_EXPORT_SPEC const char *UpnpDiscovery_get_ServiceVer_cstr(
    const UpnpDiscovery *p);
/*! UpnpDiscovery_strcpy_ServiceVer */
UPNP_EXPORT_SPEC int UpnpDiscovery_strcpy_ServiceVer(
    UpnpDiscovery *p, const char *s);
/*! UpnpDiscovery_strncpy_ServiceVer */
UPNP_EXPORT_SPEC int UpnpDiscovery_strncpy_ServiceVer(
    UpnpDiscovery *p, const char *s, size_t n);
/*! UpnpDiscovery_clear_ServiceVer */
UPNP_EXPORT_SPEC void UpnpDiscovery_clear_ServiceVer(UpnpDiscovery *p);

/*! UpnpDiscovery_get_Location */
UPNP_EXPORT_SPEC const UpnpString *UpnpDiscovery_get_Location(
    const UpnpDiscovery *p);
/*! UpnpDiscovery_set_Location */
UPNP_EXPORT_SPEC int UpnpDiscovery_set_Location(
    UpnpDiscovery *p, const UpnpString *s);
/*! UpnpDiscovery_get_Location_Length */
UPNP_EXPORT_SPEC size_t UpnpDiscovery_get_Location_Length(
    const UpnpDiscovery *p);
/*! UpnpDiscovery_get_Location_cstr */
UPNP_EXPORT_SPEC const char *UpnpDiscovery_get_Location_cstr(
    const UpnpDiscovery *p);
/*! UpnpDiscovery_strcpy_Location */
UPNP_EXPORT_SPEC int UpnpDiscovery_strcpy_Location(
    UpnpDiscovery *p, const char *s);
/*! UpnpDiscovery_strncpy_Location */
UPNP_EXPORT_SPEC int UpnpDiscovery_strncpy_Location(
    UpnpDiscovery *p, const char *s, size_t n);
/*! UpnpDiscovery_clear_Location */
UPNP_EXPORT_SPEC void UpnpDiscovery_clear_Location(UpnpDiscovery *p);

/*! UpnpDiscovery_get_CapTokenUrl */
UPNP_EXPORT_SPEC const UpnpString *UpnpDiscovery_get_CapTokenUrl(
    const UpnpDiscovery *p);
/*! UpnpDiscovery_set_CapTokenUrl */
UPNP_EXPORT_SPEC int UpnpDiscovery_set_CapTokenUrl(
    UpnpDiscovery *p, const UpnpString *s);
/*! UpnpDiscovery_get_CapTokenUrl_Length */
UPNP_EXPORT_SPEC size_t UpnpDiscovery_get_CapTokenUrl_Length(
    const UpnpDiscovery *p);
/*! UpnpDiscovery_get_CapTokenUrl_cstr */
UPNP_EXPORT_SPEC const char *UpnpDiscovery_get_CapTokenUrl_cstr(
    const UpnpDiscovery *p);
/*! UpnpDiscovery_strcpy_CapTokenUrl */
UPNP_EXPORT_SPEC int UpnpDiscovery_strcpy_CapTokenUrl(
    UpnpDiscovery *p, const char *s);
/*! UpnpDiscovery_strncpy_CapTokenUrl */
UPNP_EXPORT_SPEC int UpnpDiscovery_strncpy_CapTokenUrl(
    UpnpDiscovery *p, const char *s, size_t n);
/*! UpnpDiscovery_clear_CapTokenUrl */
UPNP_EXPORT_SPEC void UpnpDiscovery_clear_CapTokenUrl(UpnpDiscovery *p);

/*! UpnpDiscovery_get_AdvSignature */
UPNP_EXPORT_SPEC const UpnpString *UpnpDiscovery_get_AdvSignature(
    const UpnpDiscovery *p);
/*! UpnpDiscovery_set_AdvSignature */
UPNP_EXPORT_SPEC int UpnpDiscovery_set_AdvSignature(
    UpnpDiscovery *p, const UpnpString *s);
/*! UpnpDiscovery_get_AdvSignature_Length */
UPNP_EXPORT_SPEC size_t UpnpDiscovery_get_AdvSignature_Length(
    const UpnpDiscovery *p);
/*! UpnpDiscovery_get_AdvSignature_cstr */
UPNP_EXPORT_SPEC const char *UpnpDiscovery_get_AdvSignature_cstr(
    const UpnpDiscovery *p);
/*! UpnpDiscovery_strcpy_AdvSignature */
UPNP_EXPORT_SPEC int UpnpDiscovery_strcpy_AdvSignature(
    UpnpDiscovery *p, const char *s);
/*! UpnpDiscovery_strncpy_AdvSignature */
UPNP_EXPORT_SPEC int UpnpDiscovery_strncpy_AdvSignature(
    UpnpDiscovery *p, const char *s, size_t n);
/*! UpnpDiscovery_clear_AdvSignature */
UPNP_EXPORT_SPEC void UpnpDiscovery_clear_AdvSignature(UpnpDiscovery *p);

/*! UpnpDiscovery_get_Os */
UPNP_EXPORT_SPEC const UpnpString *UpnpDiscovery_get_Os(const UpnpDiscovery *p);
/*! UpnpDiscovery_set_Os */
UPNP_EXPORT_SPEC int UpnpDiscovery_set_Os(
    UpnpDiscovery *p, const UpnpString *s);
/*! UpnpDiscovery_get_Os_Length */
UPNP_EXPORT_SPEC size_t UpnpDiscovery_get_Os_Length(const UpnpDiscovery *p);
/*! UpnpDiscovery_get_Os_cstr */
UPNP_EXPORT_SPEC const char *UpnpDiscovery_get_Os_cstr(const UpnpDiscovery *p);
/*! UpnpDiscovery_strcpy_Os */
UPNP_EXPORT_SPEC int UpnpDiscovery_strcpy_Os(UpnpDiscovery *p, const char *s);
/*! UpnpDiscovery_strncpy_Os */
UPNP_EXPORT_SPEC int UpnpDiscovery_strncpy_Os(
    UpnpDiscovery *p, const char *s, size_t n);
/*! UpnpDiscovery_clear_Os */
UPNP_EXPORT_SPEC void UpnpDiscovery_clear_Os(UpnpDiscovery *p);

/*! UpnpDiscovery_get_Date */
UPNP_EXPORT_SPEC const UpnpString *UpnpDiscovery_get_Date(
    const UpnpDiscovery *p);
/*! UpnpDiscovery_set_Date */
UPNP_EXPORT_SPEC int UpnpDiscovery_set_Date(
    UpnpDiscovery *p, const UpnpString *s);
/*! UpnpDiscovery_get_Date_Length */
UPNP_EXPORT_SPEC size_t UpnpDiscovery_get_Date_Length(const UpnpDiscovery *p);
/*! UpnpDiscovery_get_Date_cstr */
UPNP_EXPORT_SPEC const char *UpnpDiscovery_get_Date_cstr(
    const UpnpDiscovery *p);
/*! UpnpDiscovery_strcpy_Date */
UPNP_EXPORT_SPEC int UpnpDiscovery_strcpy_Date(UpnpDiscovery *p, const char *s);
/*! UpnpDiscovery_strncpy_Date */
UPNP_EXPORT_SPEC int UpnpDiscovery_strncpy_Date(
    UpnpDiscovery *p, const char *s, size_t n);
/*! UpnpDiscovery_clear_Date */
UPNP_EXPORT_SPEC void UpnpDiscovery_clear_Date(UpnpDiscovery *p);

/*! UpnpDiscovery_get_Ext */
UPNP_EXPORT_SPEC const UpnpString *UpnpDiscovery_get_Ext(
    const UpnpDiscovery *p);
/*! UpnpDiscovery_set_Ext */
UPNP_EXPORT_SPEC int UpnpDiscovery_set_Ext(
    UpnpDiscovery *p, const UpnpString *s);
/*! UpnpDiscovery_get_Ext_Length */
UPNP_EXPORT_SPEC size_t UpnpDiscovery_get_Ext_Length(const UpnpDiscovery *p);
/*! UpnpDiscovery_get_Ext_cstr */
UPNP_EXPORT_SPEC const char *UpnpDiscovery_get_Ext_cstr(const UpnpDiscovery *p);
/*! UpnpDiscovery_strcpy_Ext */
UPNP_EXPORT_SPEC int UpnpDiscovery_strcpy_Ext(UpnpDiscovery *p, const char *s);
/*! UpnpDiscovery_strncpy_Ext */
UPNP_EXPORT_SPEC int UpnpDiscovery_strncpy_Ext(
    UpnpDiscovery *p, const char *s, size_t n);
/*! UpnpDiscovery_clear_Ext */
UPNP_EXPORT_SPEC void UpnpDiscovery_clear_Ext(UpnpDiscovery *p);

/*! UpnpDiscovery_get_DestAddr */
UPNP_EXPORT_SPEC const struct sockaddr_storage *UpnpDiscovery_get_DestAddr(
    const UpnpDiscovery *p);
/*! UpnpDiscovery_get_DestAddr */
UPNP_EXPORT_SPEC int UpnpDiscovery_set_DestAddr(
    UpnpDiscovery *p, const struct sockaddr_storage *buf);
/*! UpnpDiscovery_get_DestAddr */
UPNP_EXPORT_SPEC void UpnpDiscovery_clear_DestAddr(UpnpDiscovery *p);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* UPNPDISCOVERY_H */
