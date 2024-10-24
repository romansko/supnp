/*******************************************************************************
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
 ******************************************************************************/

#include "sample_util.h"
#include "tv_ctrlpt.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;
	char *iface = NULL;
	int rc;
	ithread_t cmdloop_thread;
	int i = 0;
#ifdef _WIN32
#else
	int sig;
	sigset_t sigs_to_catch;
#endif
	int code;
    #if ENABLE_SUPNP
    char *cap_token_name = NULL;
    char *public_key_ca = NULL;
    char *private_key_cp = NULL;
    char *sad = NULL;
    char *cert_cp = NULL;
    char *cert_uca = NULL;
    char *web_dir_path = NULL; /* For CP Cap Token */
    #endif

	SampleUtil_Initialize(linux_print);
	/* Parse options */
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-i") == 0) {
			iface = argv[++i];
		#if ENABLE_SUPNP
		} else if (strcmp(argv[i], "-cap") == 0) {
		    cap_token_name = argv[++i];
		} else if (strcmp(argv[i], "-ca_pkey") == 0) {
		    public_key_ca = argv[++i];
		} else if (strcmp(argv[i], "-cp_pkey") == 0) {
		    private_key_cp = argv[++i];
		} else if (strcmp(argv[i], "-sad") == 0) {
		    sad = argv[++i];
		} else if (strcmp(argv[i], "-cert_cp") == 0) {
		    cert_cp = argv[++i];
		} else if (strcmp(argv[i], "-cert_uca") == 0) {
		    cert_uca = argv[++i];
		} else if (strcmp(argv[i], "-webdir") == 0) {
		    web_dir_path = argv[++i];
		#endif
		} else if (strcmp(argv[i], "-help") == 0) {
			SampleUtil_Print(
				"Usage: %s -i interface"
				#if ENABLE_SUPNP
                " -cap cap_token_name"
                " -ca_pkey public_key_ca"
                " -cp_pkey private_key_cp"
                " -sad device_spec"
                " -cert_cp cert_cp"
                " -cert_uca cert_uca"
                " -webdir web_dir_path"
                #endif
				" -help (this message)\n",
				argv[0]);
			SampleUtil_Print("\tinterface:      interface address "
					 "of the control point\n"
					 "\t\t\te.g.: eth0\n"
                    #if ENABLE_SUPNP
                    "\tcap_token_name: filename of the capability token\n"
                    "\t\t\te.g.: captoken_cp\n"
                    "\tpublic_key_ca:  PEM filepath of CA public key\n"
                    "\t\t\te.g.: publickey_ca.pem\n"
                    "\tprivate_key_cp: PEM filepath of CP private key\n"
                    "\t\t\te.g.: privatekey_cp.pem\n"
                    "\tdevice_spec:    filepath of device specification document\n"
                    "\t\t\te.g.: sad.json\n"
                    "\tcert_cp:        PEM filepath of CP certificate\n"
                    "\t\t\te.g.: cert_cp.pem\n"
                    "\tcert_uca:       PEM filepath of UCA certificate\n"
                    "\t\t\te.g.: cert_uca.pem\n"
                    "\tweb_dir_path:   Filesystem path where web files"
				    " related to the device are stored\n"
				    "\t\t\te.g.: /upnp/sample/tvdevice/web\n"
                    #endif
                    );
			return 1;
		}
	}

	rc = TvCtrlPointStart(iface,
        #if ENABLE_SUPNP
	    cap_token_name,
	    public_key_ca,
	    private_key_cp,
	    sad,
	    cert_cp,
	    cert_uca,
	    web_dir_path,
	    #endif
	    NULL, 0);
	if (rc != TV_SUCCESS) {
		SampleUtil_Print("Error starting UPnP TV Control Point\n");
		return rc;
	}
	/* start a command loop thread */
	code = ithread_create(
		&cmdloop_thread, NULL, TvCtrlPointCommandLoop, NULL);
	if (code != 0) {
		return UPNP_E_INTERNAL_ERROR;
	}
#ifdef _WIN32
	ithread_join(cmdloop_thread, NULL);
#else
	/* Catch Ctrl-C and properly shutdown */
	sigemptyset(&sigs_to_catch);
	sigaddset(&sigs_to_catch, SIGINT);
	sigwait(&sigs_to_catch, &sig);
	SampleUtil_Print("Shutting down on signal %d...\n", sig);
#endif
	rc = TvCtrlPointStop();

	return rc;
}
