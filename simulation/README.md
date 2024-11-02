# Simulation

The folder contains simulation scripts to demonstrate SUPnP scheme capabilities. The SUPnP Protocol Scheme 
is presented in the paper [Kayas, G., Hossain, M., Payton, J., & Islam, S. R. (2021). SUPnP: Secure Access and Service Registration for UPnP-Enabled Internet of Things. IEEE Internet of Things Journal, 8(14), 11561-11580](https://ieeexplore.ieee.org/document/9352973). 

The implementation provided here is only for educational purposes, and made as a part of my MSc computer 
science studies. **For Licensing**, please consult the authors of the [supnp paper](https://ieeexplore.ieee.org/document/9352973).

**Simulation Scripts**

1. [Device Enrollment](#device-enrollment)
2. [Attack Scenarios](#attack-scenarios)

<br/>

## Requirements

* Python 3
* see [requirements.txt](requirements.txt), to install, run `pip install -r requirements.txt`

<br/>

## Device Enrollment

The `device_enrollment.py` script is responsible for generating the artifacts which are required by the 
different phases of the SUPnP proposed scheme. The script generates keys, certificates, and simulates the 
**Device Enrollment** part by generating `SAD` and `DSD` documents for the SUPnP proposed scheme 

Given a device description xml document file, the script will generate the following artifacts:

* $SK{ca}$ - A common CA's private key. PEM format.
* $PK{ca}$ - A common CA's public key. PEM format.
* $Cert_{uca}$ - UCA (UPnP Certification Authority) certificate signed by CA's public key. PEM format.
* $SK_{uca}$ - UCA's private key. PEM format.
* $PK_{uca}$ - UCA's public key. PEM format.
* $Cert_{cp}$ - CP (Control Point) certificate, which contains CP's public key, and signed by UCA's private key. PEM format.
* $SK_{cp}$ - CP's private key. PEM format.
* $PK_{cp}$ - CP's public key. PEM format.
* $Cert_{sd}$ - SD (Service Device) certificate, which contains SD's public key, and signed by UCA's private key. PEM format.
* $SK_{sd}$ - SD's private key. PEM format.
* $PK_{sd}$ - SD's public key. PEM format.
* $DSD$ (Device Specification Document). JSON format. Signed by SD & UCA.
* $SAD$ (Service Action Document). JSON format. Signed by CP & UCA.

<br/>

The following artifacts should be stored on the SD: $PK_{ca}$, $Cert_{uca}$, $Cert_{sd}$, $SK_{sd}$, $PK_{sd}$ and $DSD$.

The following artifacts should be stored on the CP: $PK_{ca}$, $Cert_{uca}$, $Cert_{cp}$, $SK_{cp}$, $PK_{cp}$ and $SAD$.

Note that in the simulation scenario the UCA is reused, but it can be different among devices. 
The root of trust is a CA which signs the different UCA entities.

<br/> 

### DSD (Device Specification Document) Components

The following DSD structure is presented by the [supnp paper](https://ieeexplore.ieee.org/document/9352973):

* `TYPE` - Type of of the participant - "SD" (Service Device).
* `PK` - Public Key of the SD.
* `HW` - Hardware description of the device (e.g., CPU, RAM, ROM, and network interfaces).
* `SW` - Software specification of the device (e.g., operating system and runtime environment).
* `SERVICES` - The list of services, represented as (name, type) pairs, that are provided by the SD.
* `SIG-OWNER` - The signature of owner, generated from the DSD contents using the secret key of the SD.
* `SIG-UCA` - The signature of the UCA, generated from the DSD contents using the secret key of the UCA.
* `SIG-VER-CON` - The verification condition of the DSD. The “CON” field value “2-of-2” means both signatures 
mentioned in the “SIGS” field need to be verified to prove the authenticity of this document.
* `SIGS` - The signatures need to be verified to check the authenticity of this document.

<br/> 

### SAD (Service Action Document) Components

The following SAD structure is presented by the [supnp paper](https://ieeexplore.ieee.org/document/9352973):

* `TYPE` - Type of of the participant - "CP" (Control Point).
* `PK` - Public Key of the CP.
* `SERVICES` - The list of services, represented as (name, type) pairs, that the CP will be authorized to use.
* `SIG-OWNER` - The signature of owner, generated from the SAD contents using the secret key of the SD.
* `SIG-UCA` - The signature of the UCA, generated from the SAD contents using the secret key of the UCA.
* `SIG-VER-CON` - The verification condition of the SAD. The “CON” field value “2-of-2” means both signatures 
mentioned in the “SIGS” field need to be verified to prove the authenticity of this document.
* `SIGS` - The signatures need to be verified to check the authenticity of this document.

<br/>

### Usage

It's possible to invoke [Makefile](Makefile) script, by simply executing the command 

```bash
make
```

This will create a virtual environment `venv`, the requirements within in, and will invoke 
`./venv/bin/python3 ./device_enrollment.py ../upnp/sample/web/tvdevicedesc.xml`

For direct activation, if `venv` is not desired, execute:

```bash
./device_enrollment.py <device_description_xml>
```

**Usage example:**

```bash
supnp/simulation$ make
[*] Initializing python venv for UCA Simulation..
python3 -m venv venv
venv/bin/pip install -r requirements.txt
...
[*] Generating Artifacts from libupnp sample..
rm -rf CA CP RA SD UCA 
./venv/bin/python3 ./device_enrollment.py ../upnp/sample/web/tvdevicedesc.xml
~~~ Device Enrollment simulation ~~~
[*] Initialized Device('supnp/upnp/sample/web/tvdevicedesc.xml')
[*] Initializing CA..
	Generated 'supnp/simulation/CA/private_key.pem'
	Generated 'supnp/simulation/CA/public_key.pem'
[*] Initializing UCA..
	Generated 'supnp/simulation/UCA/private_key.pem'
	Generated 'supnp/simulation/UCA/public_key.pem'
[*] CA signs UCA's certificate..
	Generated 'supnp/simulation/UCA/certificate.pem'
[*] Initializing CP..
	Generated 'supnp/simulation/CP/private_key.pem'
	Generated 'supnp/simulation/CP/public_key.pem'
[*] UCA signs CP's certificate..
	Generated 'supnp/simulation/CP/certificate.pem'
[*] Initializing SD..
	Generated 'supnp/simulation/SD/private_key.pem'
	Generated 'supnp/simulation/SD/public_key.pem'
[*] UCA signs SD's certificate..
	Generated 'supnp/simulation/SD/certificate.pem'
[*] Initializing RA..
	Generated 'supnp/simulation/RA/private_key.pem'
	Generated 'supnp/simulation/RA/public_key.pem'
[*] UCA signs RA's certificate..
	Generated 'supnp/simulation/RA/certificate.pem'
[*] Service Action Document (SAD)
	Generated 'supnp/simulation/CP/sad.json'
[*] Device Specification Document (DSD)
	Generated 'supnp/simulation/SD/dsd.json'
[*] Verifying signatures for 'SAD':
	Verifying public key..		public key ok.
	Verifying 'SIG-OWNER'..		signature ok.
	Verifying 'SIG-UCA'..		signature ok.
[*] Verifying signatures for 'DSD':
	Verifying public key..		public key ok.
	Verifying 'SIG-OWNER'..		signature ok.
	Verifying 'SIG-UCA'..		signature ok.
[*] Verifying certificates..
	Verifying UCA's certificate..	certificate ok.
	Verifying CP's certificate..	certificate ok.
	Verifying SD's certificate..	certificate ok.
	Verifying RA's certificate..	certificate ok.
[*] Done.
```

<br/>

## Attack Scenarios

The script [smiranda.py](smiranda.py) is demonstrating the attack scenarios which are described by 
[Table III](#table-iii-properties-evaluated-in-the-security-analysis-of-supnp) 
in the [supnp paper](https://ieeexplore.ieee.org/document/9352973). 
The script itself is based on the `miranda-upnp` script by Craig Heffner, an Python-based interactive UPnP client.

* [miranda-upnp (python3)](https://github.com/romansko/miranda-upnp)
* [miranda-upnp (original)](https://code.google.com/archive/p/miranda-upnp)

**For Licensing**, as written before, please consult the authors of the [supnp paper](https://ieeexplore.ieee.org/document/9352973).
The miranda-upnp script itself is MIT licensed. (See [Project Information](https://code.google.com/archive/p/miranda-upnp/)).

<br/>

### Table III: Properties evaluated in the security analysis of SUPnP

<table border="1">
    <tr>
        <th>Security Property</th>
        <th>Attack Scenario</th>
        <th>Requirements</th>
    </tr>
    <tr>
        <td>Trustworthy Capability Verification</td>
        <td>An adversary sends a forge capability document (DSD, or SAD) during the registration process.</td>
        <td>Registration Authority(RA) should be able to identify the forged capability document and reject registration 
        request.</td>
    </tr>
    <tr>
        <td>SD Impersonation mitigation</td>
        <td>A malicious SD sends a forged advertisement with an altered service description document.</td>
        <td>The control-point should detect the forgery of the advertisement and service description document.</td>
    </tr>
    <tr>
        <td>CP Impersonation mitigation</td>
        <td>A malicious CP sends a fake discovery request to find a service without having the capability to process 
        the service data.</td>
        <td>An SD should identify the fake discovery request and drop the request without processing it.</td>
    </tr>
    <tr>
        <td>Action Authentication</td>
        <td>An adversary gains unauthorized access to an SD's service description document, learns the control URL from 
        the document, and sends a forged service action request.</td>
        <td>The SD should be able to detect that the CP does not have the capability to perform the action.</td>
    </tr>
    <tr>
        <td>Event Subscription Authentication</td>
        <td>An adversary gains unauthorized access to an SD's device description document, learns the event URL from 
        the document, and sends an event subscription request.</td>
        <td>The SD should detect the unauthorized subscription request and ignore it.</td>
    </tr>
</table>

<br/>


### Usage

To start `smiranda`:

```bash
make
source venv/bin/activate
./smiranda.py
```

The Attack Scenarios are located under the command `supnp` inside the miranda script. The other commands are left unchanged.

```
Miranda-SUPnP (smiranda)
Interactive UPnP client + SUPnP Attack Scenarios extension

smiranda> help

help            Show program help
quit            Exit this shell
exit            Exit this shell
save            Save current host data to file
set             Show/define application settings
head            Show/define SSDP headers
host            View and send host list and host information
pcap            Passively listen for UPNP hosts
msearch         Actively locate UPNP hosts
load            Restore previous host data from file
log             Logs user-supplied commands to a log file
supnp           Invoke SUPnP Attack Scenarios
```

**Usage Examples:**

```
smiranda> supnp help

Description:
        Invoke SUPnP Attack Scenarios:
        [1] An adversary sends a forged capability document (DSD, or SAD)
            during the registration process.
        [2] A malicious SD sends a forged advertisement with an altered
            service description document.
        [3] A malicious CP sends a fake discovery request to find a service
            without having the capability to process the service data.
        [4] An adversary gains unauthorized access to an SD's service
            description document, learns the control URL from the document,
            and sends a forged service action request.
        [5] An adversary gains unauthorized access to an SD's device
            description document, learns the event URL from the
            document, and sends an event subscription request.
        If only supnp make is specified, the script invoke device enrollment simulation.

Usage:
        supnp make or <scenario_id>

Example:
        supnp make
        supnp 1
```

<br/>

### Scenario 1 Run log

```
smiranda> supnp 1

[*] Setting default interface 'eth0'.. To change run 'set iface <interface>'
Interface set to eth0, re-binding sockets...
Binding to eth0 interface IP: 192.168.1.100
WARNING: Failed to join multicast group: [Errno 98] Address already in use
Interface change successful!
[*] Timeout set to 3 seconds.
[*] Attack Scenario #1: An adversary sends a forged capability document (DSD, or SAD) during the registration process.
[*] Invoking RA: 'supnp/upnp/sample/registration_authority -i eth0 -ca_pkey CA/public_key.pem -ra_pkey RA/private_key.pem -cert_ra RA/certificate.pem -webdir ../upnp/sample/web'

########################################################################################################################
#                                                      RA Output                                                       #
########################################################################################################################
# Initializing [S]UPnP Sdk with                                                                                        #
# interface = eth0 port = 0                                                                                            #
# [SUPnP] [tid 132838372640064] SUpnpInit(262): Initializing SUPnP secure layer..                                      #
# [SSL_W] [tid 132838372640064] OpenSslInitializeWrapper(50): Initializing OpenSSL Wrapper..                           #
# UPnP Initialized                                                                                                     #
# ipaddress = 192.168.1.100 port = 49152                                                                               #
# Specifying the webserver root directory -- ../upnp/sample/web                                                        #
# Registering the RootDevice                                                                                           #
# with desc_doc_url: http://192.168.1.100:49152/radesc.xml                                                             #
# RootDevice Registered                                                                                                #
# Initializing State Table                                                                                             #
# Found service: urn:schemas-upnp-org:service:registration:1                                                           #
# serviceId: urn:upnp-org:serviceId:registration1                                                                      #
# State Table Initialized                                                                                              #
# State Table Initialized                                                                                              #
# Advertisements Sent                                                                                                  #
########################################################################################################################

[*] Searching for RA..
Entering discovery mode for 'upnp:rootdevice', Ctl+C to stop...

****************************************************************
SSDP reply message from 192.168.1.100:49152
XML file is located at http://192.168.1.100:49152/radesc.xml
Device is running Linux/6.8.0-48-generic, UPnP/1.0, Portable SDK for UPnP devices/17.2.1
****************************************************************


Discover mode halted..
        [0] 192.168.1.100:49152

Requesting device and service info for 192.168.1.100:49152 (this could take a few seconds)...

Host data enumeration complete!

[*] Generating Fake SAD..
[*] Initializing FakeCA..
        Generated 'supnp/simulation/FakeCA/private_key.pem'
        Generated 'supnp/simulation/FakeCA/public_key.pem'
[*] Initializing FakeUCA..
        Generated 'supnp/simulation/FakeUCA/private_key.pem'
        Generated 'supnp/simulation/FakeUCA/public_key.pem'
[*] Initializing Adversary..
        Generated 'supnp/simulation/Adversary/private_key.pem'
        Generated 'supnp/simulation/Adversary/public_key.pem'
[*] FakeCA signs FakeUCA's certificate..
        Generated 'supnp/simulation/FakeUCA/certificate.pem'
[*] FakeUCA signs Adversary's certificate..
        Generated 'supnp/simulation/Adversary/certificate.pem'
[*] Initialized Device('supnp/upnp/sample/web/tvdevicedesc.xml')
[*] Service Action Document (SAD)
        Generated 'supnp/simulation/Adversary/sad.json'

########################################################################################################################
#                                                       Fake SAD                                                       #
########################################################################################################################
# {                                                                                                                    #
# "TYPE": "CP",                                                                                                        #
# "NAME": "CP user-friendly name",                                                                                     #
#     "PK": "<truncated>",                                                                                             #
# "SERVICES": {                                                                                                        #
# "urn:upnp-org:serviceId:tvcontrol1": "urn:schemas-upnp-org:service:tvcontrol:1",                                     #
# "urn:upnp-org:serviceId:tvpicture1": "urn:schemas-upnp-org:service:tvpicture:1"                                      #
# },                                                                                                                   #
# "SIG-VER-CON": "2-of-2",                                                                                             #
# "SIGS": [                                                                                                            #
# "SIG-OWNER",                                                                                                         #
# "SIG-UCA"                                                                                                            #
# ],                                                                                                                   #
#     "SIG-OWNER": "<truncated>",                                                                                      #
#     "SIG-UCA": "<truncated>"                                                                                         #
# }                                                                                                                    #
########################################################################################################################

[*] Trying to Register fake CP..
[*] Sending Service Action Request.. 'supnp send 0 ra registration Register <truncated>

########################################################################################################################
#                                                     RA Response                                                      #
########################################################################################################################
# <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/enc #
# oding/">                                                                                                             #
# <s:Body>                                                                                                             #
# <s:Fault>                                                                                                            #
# <faultcode>s:Client</faultcode>                                                                                      #
# <faultstring>UPnPError</faultstring>                                                                                 #
# <detail>                                                                                                             #
# <UPnPError xmlns="urn:schemas-upnp-org:control-1-0">                                                                 #
# <errorCode>501</errorCode>                                                                                           #
# <errorDescription>Unable to verify device                                                                            #
# </errorDescription>                                                                                                  #
# </UPnPError>                                                                                                         #
# </detail>                                                                                                            #
# </s:Fault>                                                                                                           #
# </s:Body>                                                                                                            #
# </s:Envelope>                                                                                                        #
########################################################################################################################


########################################################################################################################
#                                                      RA Output                                                       #
########################################################################################################################
# Initializing [S]UPnP Sdk with                                                                                        #
# interface = eth0 port = 0                                                                                            #
# [SUPnP] [tid 132838372640064] SUpnpInit(262): Initializing SUPnP secure layer..                                      #
# [SSL_W] [tid 132838372640064] OpenSslInitializeWrapper(50): Initializing OpenSSL Wrapper..                           #
# UPnP Initialized                                                                                                     #
# ipaddress = 192.168.1.100 port = 49152                                                                               #
# Specifying the webserver root directory -- ../upnp/sample/web                                                        #
# Registering the RootDevice                                                                                           #
# with desc_doc_url: http://192.168.1.100:49152/radesc.xml                                                             #
# RootDevice Registered                                                                                                #
# Initializing State Table                                                                                             #
# Found service: urn:schemas-upnp-org:service:registration:1                                                           #
# serviceId: urn:upnp-org:serviceId:registration1                                                                      #
# State Table Initialized                                                                                              #
# State Table Initialized                                                                                              #
# Advertisements Sent                                                                                                  #
# Sleeping for 10 seconds before main command loop..                                                                   #
# [SSL_W Error] [tid 132838309496512] .upnp/src/openssl/openssl_wrapper.c::OpenSslVerifyCertificate(312): 'UCA' certif #
# icate verification error                                                                                             #
# error:0200008A:rsa routines::invalid padding                                                                         #
# [SUPnP Error] [tid 132838309496512] .upnp/src/supnp/supnp.c::SUpnpVerifyDocument(416): Invalid UCA cert.             #
# [SUPnP] [tid 132838309496512] SUpnpVerifyDocument(411): Verifying CP user-friendly name document. Type: 'CP'.        #
# [SSL_W] [tid 132838309496512] OpenSslVerifyCertificate(307): Verifying 'UCA''s certificate..                         #
# Unable to verify device                                                                                              #
# ======================================================================                                               #
# ----------------------------------------------------------------------                                               #
# UPNP_CONTROL_ACTION_REQUEST                                                                                          #
# ErrCode     =  501                                                                                                   #
# ErrStr      =  Unable to verify device                                                                               #
# ActionName  =  Register                                                                                              #
# UDN         =  uuid:SUpnp-RA-1_0-1234567890001                                                                       #
# ServiceID   =  urn:upnp-org:serviceId:registration1                                                                  #
# ActRequest  =  <m:Register xmlns:m="urn:schemas-upnp-org:service:registration:1">                                    #
# <SpecificationDocument><truncated></SpecificationDocument>                                                           #
# <CertificateDevice><truncated></CertificateDevice>                                                                   #
# <CertificateUCA><truncated></CertificateUCA>                                                                         #
# <ErrorCode>-603</ErrorCode>                                                                                          #
# </u:RegisterResponse>                                                                                                #
# ----------------------------------------------------------------------                                               #
# ======================================================================                                               #
########################################################################################################################

[*] Scenario Succeeded. Received 'Unable to verify device' as expected.
[*] RA: 'RA_log.txt' closed. 'registration_authority' terminated.
Host list cleared!
```

<br/>

### Scenario 2 Run log

```
smiranda> supnp 2

[*] Timeout set to 3 seconds.
[*] Attack Scenario #2: A malicious SD sends a forged advertisement with an altered service description document.
[*] Invoking RA: 'supnp/upnp/sample/registration_authority -i eth0 -ca_pkey CA/public_key.pem -ra_pkey RA/private_key.pem -cert_ra RA/certificate.pem -webdir ../upnp/sample/web'
[*] Invoking CP: 'supnp/upnp/sample/tv_ctrlpt -i eth0 -ca_pkey CA/public_key.pem -cp_pkey CP/private_key.pem -sad CP/sad.json -cert_cp CP/certificate.pem -cert_uca UCA/certificate.pem -webdir ../upnp/sample/web'
[*] CP registered with RA. Terminating RA - Not required anymore..
[*] RA: 'RA_log.txt' closed. 'registration_authority' terminated.
[*] Initializing FakeRA..
[*] Serving at port 1901 for 5 seconds..
        Generated 'supnp/simulation/FakeRA/private_key.pem'
        Generated 'supnp/simulation/FakeRA/public_key.pem'
[*] Signed 'http://192.168.1.100:1901/tvdevicedesc.xmlhttp://192.168.1.100:1901/fake.json' with FakeRA's private key.
[*] Sending NOTIFY message (NT = upnp:rootdevice)..
192.168.1.100 - - [02/Nov/2024 15:11:45] "GET /tvdevicedesc.xml HTTP/1.1" 200 -
[*] Server shutting down..

########################################################################################################################
#                                                      CP Output                                                       #
########################################################################################################################
# Initializing UPnP Sdk with                                                                                           #
# interface = eth0 port = 0                                                                                            #
# [SUPnP] [tid 126232359011648] SUpnpInit(262): Initializing SUPnP secure layer..                                      #
# [SSL_W] [tid 126232359011648] OpenSslInitializeWrapper(50): Initializing OpenSSL Wrapper..                           #
# UPnP Initialized                                                                                                     #
# ipv4 address = 192.168.1.100 port = 49153                                                                            #
# ipv6 address =  port = 0                                                                                             #
# ipv6ulagua address =  port = 0                                                                                       #
# Registering Control Point..                                                                                          #
# [SUPnP] [tid 126232359011648] SUpnpSetCapTokenLocation(147): Setting captoken location to 'http://192.168.1.100:4915 #
# 3/captoken_cp.json'.                                                                                                 #
# Sleeping for 10 seconds before main command loop..                                                                   #
# [SSL_W] [tid 126232326833856] OpenSslVerifyCertificate(307): Verifying 'ra_cert''s certificate..                     #
# [SUPnP] [tid 126232326833856] RegistrationCallbackEventHandler(862): SUPnP Device Registered                         #
# Control Point Registered with RA                                                                                     #
# [SSL_W Error] [tid 126232316348096] .upnp/src/openssl/openssl_wrapper.c::OpenSslVerifySignature(364): 'Advertisement #
# Signature':     error:0200008A:rsa routines::invalid padding                                                         #
# [SUPnP Error] [tid 126232316348096] .upnp/src/supnp/supnp.c::SUpnpSecureAdvertisementVerify(1172): Advertisement sig #
# nature is forged !!!                                                                                                 #
########################################################################################################################

[*] Scenario Succeeded. Received 'Advertisement signature is forged' as expected.
[*] CP: 'CP_log.txt' closed. 'tv_ctrlpt' terminated.
Host list cleared!
```

<br/>

### Scenario 3 Run log

```
smiranda> supnp 3

[*] Timeout set to 3 seconds.
[*] Invoking RA: 'supnp/upnp/sample/registration_authority -i eth0 -ca_pkey CA/public_key.pem -ra_pkey RA/private_key.pem -cert_ra RA/certificate.pem -webdir ../upnp/sample/web'
[*] Attack Scenario #3: A malicious CP sends a fake discovery request to find a service without having the capability to process the service data.
[*] Invoking SD: 'supnp/upnp/sample/tv_device -i eth0 -ca_pkey CA/public_key.pem -sd_pkey SD/private_key.pem -dsd SD/dsd.json -cert_sd SD/certificate.pem -cert_uca UCA/certificate.pem -disable_ad -webdir ../upnp/sample/web'
[*] SD registered with RA. Terminating RA - Not required anymore..
[*] RA: 'RA_log.txt' closed. 'registration_authority' terminated.
[*] Timeout set to 20 seconds.
[*] Sending Fake Discovery Request..
Entering discovery mode for 'upnp:rootdevice', Ctl+C to stop...


Discover mode halted..
No known hosts - try running the 'msearch' or 'pcap' commands

[*] Timeout set to 3 seconds.

########################################################################################################################
#                                                      SD Output                                                       #
########################################################################################################################
# Initializing UPnP Sdk with                                                                                           #
# interface = eth0 port = 0                                                                                            #
# [SUPnP] [tid 130474404418880] SUpnpInit(262): Initializing SUPnP secure layer..                                      #
# [SSL_W] [tid 130474404418880] OpenSslInitializeWrapper(50): Initializing OpenSSL Wrapper..                           #
# UPnP Initialized                                                                                                     #
# ipaddress = 192.168.1.100 port = 49153                                                                               #
# Specifying the webserver root directory -- ../upnp/sample/web                                                        #
# Registering the RootDevice                                                                                           #
# with desc_doc_url: http://192.168.1.100:49153/tvdevicedesc.xml                                                       #
# with cap_token_url: http://192.168.1.100:49153/captoken_sd.json                                                      #
# RootDevice Registered                                                                                                #
# Initializing State Table                                                                                             #
# Found service: urn:schemas-upnp-org:service:tvcontrol:1                                                              #
# serviceId: urn:upnp-org:serviceId:tvcontrol1                                                                         #
# Found service: urn:schemas-upnp-org:service:tvpicture:1                                                              #
# serviceId: urn:upnp-org:serviceId:tvpicture1                                                                         #
# State Table Initialized                                                                                              #
# Registering SD with RA..                                                                                             #
# [SUPnP] [tid 130474404418880] SUpnpSetCapTokenLocation(147): Setting captoken location to 'http://192.168.1.100:4915 #
# 3/captoken_sd.json'.                                                                                                 #
# Sleeping for 10 seconds before main command loop..                                                                   #
# [SSL_W] [tid 130474372499136] OpenSslVerifyCertificate(307): Verifying 'ra_cert''s certificate..                     #
# [SUPnP] [tid 130474372499136] RegistrationCallbackEventHandler(862): SUPnP Device Registered                         #
# [SUPnP] [tid 130474372499136] RegistrationCallbackSD(1427): SD registered with RA successfully.                      #
#  [SUPnP Error] [tid 130474362013376] .upnp/src/ssdp/ssdp_device.c::ssdp_handle_device_request(168): Secure Service D #
# iscovery failed - missing CapTokenLocation                                                                           #
########################################################################################################################

[*] Scenario Succeeded. Received 'Secure Service Discovery failed' as expected.
[*] SD: 'SD_log.txt' closed. 'tv_device' terminated.
Host list cleared!
```

<br/>

### Scenario 4 Run log

```
smiranda> supnp 4

[*] Timeout set to 3 seconds.
[*] Invoking RA: 'supnp/upnp/sample/registration_authority -i eth0 -ca_pkey CA/public_key.pem -ra_pkey RA/private_key.pem -cert_ra RA/certificate.pem -webdir ../upnp/sample/web'
[*] Attack Scenario #4: An adversary gains unauthorized access to an SD's service description document, learns the control URL from the document, and sends a forged service action request.
[*] Invoking SD: 'supnp/upnp/sample/tv_device -i eth0 -ca_pkey CA/public_key.pem -sd_pkey SD/private_key.pem -dsd SD/dsd.json -cert_sd SD/certificate.pem -cert_uca UCA/certificate.pem -webdir ../upnp/sample/web'
[*] SD registered with RA. Terminating RA - Not required anymore..
[*] RA: 'RA_log.txt' closed. 'registration_authority' terminated.
[*] Timeout set to 20 seconds.
[*] Searching for SD..
Entering discovery mode for 'upnp:rootdevice', Ctl+C to stop...

****************************************************************
SSDP notification message from 192.168.1.100:49153
XML file is located at http://192.168.1.100:49153/tvdevicedesc.xml
Device is running Linux/6.8.0-48-generic, UPnP/1.0, Portable SDK for UPnP devices/17.2.1
****************************************************************


Discover mode halted..
        [0] 192.168.1.100:49153

Requesting device and service info for 192.168.1.100:49153 (this could take a few seconds)...

Failed to find tag relatedStateVariable for argument Power!
Host data enumeration complete!
[*] Timeout set to 3 seconds.
[*] Sending Service Action Request.. 'supnp send 0 tv tvcontrol IncreaseVolume'
Volume : None

########################################################################################################################
#                                                     SD Response                                                      #
########################################################################################################################
# <html><body><h1>401 Unauthorized</h1></body></html>                                                                  #
########################################################################################################################


########################################################################################################################
#                                                      SD Output                                                       #
########################################################################################################################
# Initializing UPnP Sdk with                                                                                           #
# interface = eth0 port = 0                                                                                            #
# [SUPnP] [tid 129196096861504] SUpnpInit(262): Initializing SUPnP secure layer..                                      #
# [SSL_W] [tid 129196096861504] OpenSslInitializeWrapper(50): Initializing OpenSSL Wrapper..                           #
# UPnP Initialized                                                                                                     #
# ipaddress = 192.168.1.100 port = 49153                                                                               #
# Specifying the webserver root directory -- ../upnp/sample/web                                                        #
# Registering the RootDevice                                                                                           #
# with desc_doc_url: http://192.168.1.100:49153/tvdevicedesc.xml                                                       #
# with cap_token_url: http://192.168.1.100:49153/captoken_sd.json                                                      #
# RootDevice Registered                                                                                                #
# Initializing State Table                                                                                             #
# Found service: urn:schemas-upnp-org:service:tvcontrol:1                                                              #
# serviceId: urn:upnp-org:serviceId:tvcontrol1                                                                         #
# Found service: urn:schemas-upnp-org:service:tvpicture:1                                                              #
# serviceId: urn:upnp-org:serviceId:tvpicture1                                                                         #
# State Table Initialized                                                                                              #
# Registering SD with RA..                                                                                             #
# [SUPnP] [tid 129196096861504] SUpnpSetCapTokenLocation(147): Setting captoken location to 'http://192.168.1.100:4915 #
# 3/captoken_sd.json'.                                                                                                 #
# Sleeping for 10 seconds before main command loop..                                                                   #
# [SSL_W] [tid 129196053497536] OpenSslVerifyCertificate(307): Verifying 'ra_cert''s certificate..                     #
# [SUPnP] [tid 129196053497536] RegistrationCallbackEventHandler(862): SUPnP Device Registered                         #
# [SUPnP] [tid 129196053497536] RegistrationCallbackSD(1427): SD registered with RA successfully.                      #
# [SUPnP] [tid 129196053497536] SUpnpSendAdvertisement(1133): Secure Service Advertisement: sending..                  #
#  [SUPnP Error] [tid 129195990582976] .upnp/src/ssdp/ssdp_device.c::ssdp_handle_device_request(168): Secure Service D #
# iscovery failed - missing CapTokenLocation                                                                           #
# [SUPnP Error] [tid 129196011554496] .upnp/src/soap/soap_device.c::soap_device_callback(818): Secure Control Failure: #
# Expected 'CAPTOKEN-LOCATION' not found                                                                               #
########################################################################################################################

[*] Scenario Succeeded. Received 'Secure Control Failure' as expected.
[*] SD: 'SD_log.txt' closed. 'tv_device' terminated.
Host list cleared!
```

<br/>

### Scenario 5 Run log

```
miranda> supnp 5

[*] Timeout set to 3 seconds.
[*] Invoking RA: 'supnp/upnp/sample/registration_authority -i eth0 -ca_pkey CA/public_key.pem -ra_pkey RA/private_key.pem -cert_ra RA/certificate.pem -webdir ../upnp/sample/web'
[*] Attack Scenario #5: An adversary gains unauthorized access to an SD's device description document, learns the event URL from the document, and sends an event subscription request.
[*] Invoking SD: 'supnp/upnp/sample/tv_device -i eth0 -ca_pkey CA/public_key.pem -sd_pkey SD/private_key.pem -dsd SD/dsd.json -cert_sd SD/certificate.pem -cert_uca UCA/certificate.pem -webdir ../upnp/sample/web'
[*] SD registered with RA. Terminating RA - Not required anymore..
[*] RA: 'RA_log.txt' closed. 'registration_authority' terminated.
[*] Timeout set to 20 seconds.
[*] Searching for SD..
Entering discovery mode for 'upnp:rootdevice', Ctl+C to stop...

****************************************************************
SSDP notification message from 192.168.1.100:49153
XML file is located at http://192.168.1.100:49153/tvdevicedesc.xml
Device is running Linux/6.8.0-48-generic, UPnP/1.0, Portable SDK for UPnP devices/17.2.1
****************************************************************


Discover mode halted..
        [0] 192.168.1.100:49153

Requesting device and service info for 192.168.1.100:49153 (this could take a few seconds)...

Failed to find tag relatedStateVariable for argument Power!
Host data enumeration complete!
[*] Timeout set to 3 seconds.
[*] Sending Service Action Request.. 'supnp subscribe 0 tv tvcontrol'

########################################################################################################################
#                                                     SD Response                                                      #
########################################################################################################################
# <html><body><h1>400 Bad Request</h1></body></html>                                                                   #
########################################################################################################################


########################################################################################################################
#                                                      SD Output                                                       #
########################################################################################################################
# Initializing UPnP Sdk with                                                                                           #
# interface = eth0 port = 0                                                                                            #
# [SUPnP] [tid 137224463484224] SUpnpInit(262): Initializing SUPnP secure layer..                                      #
# [SSL_W] [tid 137224463484224] OpenSslInitializeWrapper(50): Initializing OpenSSL Wrapper..                           #
# UPnP Initialized                                                                                                     #
# ipaddress = 192.168.1.100 port = 49153                                                                               #
# Specifying the webserver root directory -- ../upnp/sample/web                                                        #
# Registering the RootDevice                                                                                           #
# with desc_doc_url: http://192.168.1.100:49153/tvdevicedesc.xml                                                       #
# with cap_token_url: http://192.168.1.100:49153/captoken_sd.json                                                      #
# RootDevice Registered                                                                                                #
# Initializing State Table                                                                                             #
# Found service: urn:schemas-upnp-org:service:tvcontrol:1                                                              #
# serviceId: urn:upnp-org:serviceId:tvcontrol1                                                                         #
# Found service: urn:schemas-upnp-org:service:tvpicture:1                                                              #
# serviceId: urn:upnp-org:serviceId:tvpicture1                                                                         #
# State Table Initialized                                                                                              #
# Registering SD with RA..                                                                                             #
# [SUPnP] [tid 137224463484224] SUpnpSetCapTokenLocation(147): Setting captoken location to 'http://192.168.1.100:4915 #
# 3/captoken_sd.json'.                                                                                                 #
# [SSL_W] [tid 137224431601344] OpenSslVerifyCertificate(307): Verifying 'ra_cert''s certificate..                     #
# [SUPnP] [tid 137224431601344] RegistrationCallbackEventHandler(862): SUPnP Device Registered                         #
# [SUPnP] [tid 137224431601344] RegistrationCallbackSD(1427): SD registered with RA successfully.                      #
# [SUPnP] [tid 137224431601344] SUpnpSendAdvertisement(1133): Secure Service Advertisement: sending..                  #
# Sleeping for 10 seconds before main command loop..                                                                   #
# [SUPnP Error] [tid 137224431601344] .upnp/src/ssdp/ssdp_device.c::ssdp_handle_device_request(168): Secure Service Di #
# scovery failed - missing CapTokenLocation                                                                            #
#  [SUPnP Error] [tid 137224379172544] .upnp/src/gena/gena_device.c::gena_process_subscription_request(1411): Secure E #
# venting Failure: Expected 'CAPTOKEN-LOCATION' not found                                                              #
########################################################################################################################

[*] Scenario Succeeded. Received 'Secure Eventing Failure' as expected.
[*] SD: 'SD_log.txt' closed. 'tv_device' terminated.
Host list cleared!
```

<br/>