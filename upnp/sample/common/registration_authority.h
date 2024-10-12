#ifndef SUPNP_REGISTRATION_AUTHORIRTY_H
#define SUPNP_REGISTRATION_AUTHORIRTY_H

/**************************************************************************
 *
 * Copyright (c) 2000-2003 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * - Neither name of Intel Corporation nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL INTEL OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 **************************************************************************/

/*!
 * \addtogroup UpnpSamples
 *
 * @{
 *
 * \name Device Sample API
 *
 * @{
 *
 * \file
 */

#include <signal.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "sample_util.h"

#include "ithread.h"
#include <upnp.h>
#include <supnp.h>


#include <stdlib.h>
#include <string.h>

/*! Max actions */
#define RA_MAXACTIONS 12

/*! This should be the maximum VARCOUNT from supnp.h varcounts */
#define RA_MAXVARS eRegisterActionVarCount

#define IP_MODE_IPV4 1
#define IP_MODE_IPV6_LLA 2
#define IP_MODE_IPV6_ULA_GUA 3


/*!
 * \brief Prototype for all actions. For each action that a service
 * implements, there is a corresponding function with this prototype.
 *
 * Pointers to these functions, along with action names, are stored
 * in the service table. When an action request comes in the action
 * name is matched, and the appropriate function is called.
 * Each function returns UPNP_E_SUCCESS, on success, and a nonzero
 * error code on failure.
 */
typedef int (*ra_action)(
	/*! [in] Document of action request. */
	IXML_Document *request,
	/*! [out] Action result. */
	IXML_Document **out,
	/*! [out] Error string in case action was unsuccessful. */
	const char **errorString);

/*! Structure for storing Tv Service identifiers and state table. */
struct RAService
{
	/*! Universally Unique Device Name. */
	char UDN[NAME_SIZE];
	/*! . */
	char ServiceId[NAME_SIZE];
	/*! . */
	char ServiceType[NAME_SIZE];
	/*! . */
	const char *VariableName[RA_MAXVARS];
	/*! . */
	char *VariableStrVal[RA_MAXVARS];
	/*! . */
	const char *ActionNames[RA_MAXACTIONS];
	/*! . */
	ra_action actions[RA_MAXACTIONS];
	/*! . */
	int VariableCount;
};

/*! Array of service structures */
extern struct RAService ra_service_table[];

/*! Device handle returned from sdk */
extern UpnpDevice_Handle device_handle;

/*! Mutex for protecting the global state table data
 * in a multi-threaded, asynchronous environment.
 * All functions should lock this mutex before reading
 * or writing the state table data. */
extern ithread_mutex_t RAMutex;

/*!
 * \brief Initializes the action table for the specified service.
 *
 * Note that knowledge of the service description is assumed.
 * Action names are hardcoded.
 */
int SetActionTable(
	/*! [in] RA Service Type. */
	ERAServiceType serviceType,
	/*! [in,out] service containing action table to set. */
	struct RAService *out);

/*!
 * \brief Initialize the device state table for this RA, pulling
 * identifier info from the description Document.
 *
 * Note that knowledge of the service description is assumed.
 * State table variables and default values are currently hardcoded in
 * this file rather than being read from service description documents.
 */
int RAStateTableInit(
	/*! [in] The description document URL. */
	char *DescDocURL);

/*!
 * \brief Called during a get variable request callback.
 *
 * If the request is for this device and its services,
 * then respond with the variable value.
 */
int RAHandleGetVarRequest(
	/*! [in,out] The control get variable request event structure. */
	UpnpStateVarRequest *cgv_event);

/*!
 * \brief Called during an action request callback.
 *
 * If the request is for this device and its services,
 * then perform the action and respond.
 */
int RAHandleActionRequest(
	/*! [in,out] The control action request event structure. */
	UpnpActionRequest *ca_event);

/*!
 * \brief The callback handler registered with the SDK while registering
 * root device.
 *
 * Dispatches the request to the appropriate procedure
 * based on the value of EventType. The four requests handled by the
 * device are:
 *	\li 1) Event Subscription requests.
 *	\li 2) Get Variable requests.
 *	\li 3) Action requests.
 */
int RACallbackEventHandler(
	/*! [in] The type of callback event. */
	Upnp_EventType,
	/*! [in] Data structure containing event data. */
	const void *Event,
	/*! [in] Optional data specified during callback registration. */
	void *Cookie);

/*!
 * \brief First phase of DSD/SAD verification process.
 */
int RegisterDevice(
	/*! [in] Document of action request. */
	IXML_Document *in,
	/*! [in] Action result. */
	IXML_Document **out,
	/*! [out] ErrorString in case action was unsuccessful. */
	const char **errorString);

/*!
 * \brief Second phase of DSD/SAD verification process.
 *        Verifies the challenge.
 */
int VerifyChallenge(
	/*! [in] Document of action request. */
	IXML_Document *in,
	/*! [out] Action result. */
	IXML_Document **out,
	/*! [out] ErrorString in case action was unsuccessful. */
	const char **errorString);

/*!
 * \brief Initializes the UPnP Sdk, registers the device, and sends out
 * advertisements.
 */
int RAStart(
	/*! [in] interface to initialize the sdk (may be NULL)
	 * if null, then the first non null interface is used. */
	char *iface,
	/*! [in] port number to initialize the sdk (may be 0)
	 * if zero, then a random number is used. */
	unsigned short port,
	/*! [in] name of description document.
	 * may be NULL. Default is tvdevicedesc.xml. */
	const char *desc_doc_name,
	/*! [in] path of web directory.
	 * may be NULL. Default is ./web (for Linux) or ../tvdevice/web. */
	const char *web_dir_path,
	/*! [in] IP mode: IP_MODE_IPV4, IP_MODE_IPV6_LLA or
	 * IP_MODE_IPV6_ULA_GUA. Default is IP_MODE_IPV4. */
	int ip_mode,
	/*! [in] print function to use. */
	print_string pfun);

/*!
 * \brief Stops the device. Uninitializes the sdk.
 */
int RAStop(void);

/*!
 * \brief Function that receives commands from the user at the command prompt
 * during the lifetime of the device, and calls the appropriate
 * functions for those commands. Only one command, exit, is currently
 * defined.
 */
void *RACommandLoop(void *args);

/*!
 * \brief Main entry point for tv device application.
 *
 * Initializes and registers with the sdk.
 * Initializes the state stables of the service.
 * Starts the command loop.
 *
 * Accepts the following optional arguments:
 *	\li \c -ip ipaddress
 *	\li \c -port port
 *	\li \c -desc desc_doc_name
 *	\li \c -webdir web_dir_path
 *	\li \c -help
 */
int ra_main(int argc, char *argv[]);

#ifdef __cplusplus
}
#endif

/*! @} Control Point Sample API */

/*! @} UpnpSamples */

#endif /* UPNP_TV_DEVICE_H */
