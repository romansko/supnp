#ifndef UPNPEVENT_H
#define UPNPEVENT_H

/*!
 * \file
 *
 * \brief Header file for UpnpEvent methods.
 *
 * Do not edit this file, it is automatically generated. Please look at
 * generator.c.
 *
 * \author Marcelo Roberto Jimenez
 */
#include <stdlib.h> /* for size_t */

#include "UpnpGlobal.h" /* for UPNP_EXPORT_SPEC */

#include "UpnpString.h"
#include "ixml.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*!
 * UpnpEvent
 */
typedef struct s_UpnpEvent UpnpEvent;

/*! Constructor */
UPNP_EXPORT_SPEC UpnpEvent *UpnpEvent_new();
/*! Destructor */
UPNP_EXPORT_SPEC void UpnpEvent_delete(UpnpEvent *p);
/*! Copy Constructor */
UPNP_EXPORT_SPEC UpnpEvent *UpnpEvent_dup(const UpnpEvent *p);
/*! Assignment operator */
UPNP_EXPORT_SPEC int UpnpEvent_assign(UpnpEvent *p, const UpnpEvent *q);

/*! UpnpEvent_get_EventKey */
UPNP_EXPORT_SPEC int UpnpEvent_get_EventKey(const UpnpEvent *p);
/*! UpnpEvent_set_EventKey */
UPNP_EXPORT_SPEC int UpnpEvent_set_EventKey(UpnpEvent *p, int n);

/*! UpnpEvent_get_ChangedVariables */
UPNP_EXPORT_SPEC IXML_Document *UpnpEvent_get_ChangedVariables(
    const UpnpEvent *p);
/*! UpnpEvent_set_ChangedVariables */
UPNP_EXPORT_SPEC int UpnpEvent_set_ChangedVariables(
    UpnpEvent *p, IXML_Document *n);

/*! UpnpEvent_get_SID */
UPNP_EXPORT_SPEC const UpnpString *UpnpEvent_get_SID(const UpnpEvent *p);
/*! UpnpEvent_set_SID */
UPNP_EXPORT_SPEC int UpnpEvent_set_SID(UpnpEvent *p, const UpnpString *s);
/*! UpnpEvent_get_SID_Length */
UPNP_EXPORT_SPEC size_t UpnpEvent_get_SID_Length(const UpnpEvent *p);
/*! UpnpEvent_get_SID_cstr */
UPNP_EXPORT_SPEC const char *UpnpEvent_get_SID_cstr(const UpnpEvent *p);
/*! UpnpEvent_strcpy_SID */
UPNP_EXPORT_SPEC int UpnpEvent_strcpy_SID(UpnpEvent *p, const char *s);
/*! UpnpEvent_strncpy_SID */
UPNP_EXPORT_SPEC int UpnpEvent_strncpy_SID(
    UpnpEvent *p, const char *s, size_t n);
/*! UpnpEvent_clear_SID */
UPNP_EXPORT_SPEC void UpnpEvent_clear_SID(UpnpEvent *p);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* UPNPEVENT_H */
