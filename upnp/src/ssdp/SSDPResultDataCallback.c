
/*!
 * \file
 *
 * \brief SSDPResultDataCallback.
 *
 * \author Marcelo Roberto Jimenez
 */

#include "config.h"

#include "SSDPResultData.h"
#include "SSDPResultDataCallback.h"

#if ENABLE_SUPNP
#include "supnp_common.h"
#include "supnp.h"
#include <string.h>
#endif

void SSDPResultData_Callback(const SSDPResultData *p)
{
	Upnp_FunPtr callback = SSDPResultData_get_CtrlptCallback(p);

    #if ENABLE_SUPNP
    /* Secure Advertisement verified only by CP device */
    if (SUpnpGetDeviceType() == eDeviceType_CP) {
        const UpnpDiscovery *event = SSDPResultData_get_Param(p);
        if (event == NULL) {
            supnp_error("SSDPResultData_get_Param resulted in NULL.\n")
            return;
        }
        const char *location = UpnpString_get_String(
            UpnpDiscovery_get_Location(event));
        if (location == NULL) {
            supnp_error("UpnpDiscovery_get_Location resulted in NULL.\n")
            return;
        }
        char *deviceType = SUpnpGetFirstElementItem2(location, "deviceType");
        if (deviceType == NULL) {
            supnp_error("NULL deviceType.\n")
            return;
        }

        /* Allow Advertisements from RA */
        if (strcmp(deviceType, SUpnpRaDeviceTypeString) != 0) {
            free(deviceType);
            const char *capTokenUrl = UpnpString_get_String(
                UpnpDiscovery_get_CapTokenLocation(event));
            const char *advSignature = UpnpString_get_String(
                UpnpDiscovery_get_AdvSignature(event));
            if (SUPNP_E_SUCCESS != SUpnpSecureAdvertisementVerify(
                location, capTokenUrl, advSignature))
            {
                /* Secure Advertisement failed, ignore this Advertisement */
                return;
            }
            if (SUPNP_E_SUCCESS != SUpnpSecureDeviceDescriptionVerify(
                location, capTokenUrl))
            {
                /* Secure Device Description failed, ignore this Advertisement */
                return;
            }
        }
    }
    #endif
    callback(UPNP_DISCOVERY_SEARCH_RESULT,
        SSDPResultData_get_Param(p),
        SSDPResultData_get_Cookie(p));
}
