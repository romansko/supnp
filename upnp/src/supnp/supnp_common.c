/*!
* \addtogroup SUPnP
 *
 * \file supnp_common.c
 *
 * \brief source file for SUPnP common logics.
 *
 * \author Roman Koifman
 */
#include "supnp_common.h"

#if ENABLE_SUPNP

#ifdef __cplusplus
extern "C" {
#endif


const char *SUpnpRaDeviceTypeString = "urn:schemas-upnp-org:device:ra:1";

const char *SUpnpRaServiceTypeStrings[eRegistrationAuthorityServiceCount] = {
	"urn:schemas-upnp-org:service:registration:1"
};

const char *SUpnpRaRegistrationActionString[eRegisterServiceActionCount] = {
	"Register",
	"Challenge"
};

const char *SUpnpRaRegisterActionVarName[eRegisterActionVarCount] = {
	"SpecificationDocument",
	"CertificateDevice",
	"CertificateUCA",
	"DescriptionDocumentLocation", /* Applicable only for SD */
	"CapTokenLocation"
};

const char *SUpnpRaChallengeActionVarName[eChallengeActionVarCount] = {
	"Challenge",
	"PublicKey"
};

const char *SUpnpActionResponseVarName = "ActionResponse";

const char *SUpnpCapTokenResponseVarName = "CapToken";

const char *SUpnpActionSuccessString = "1";

const char *SUpnpActionResponseRACert = "RACertificate";

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* ENABLE_SUPNP */
