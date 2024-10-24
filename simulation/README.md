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

To start `smiranda`, simply run

```bash
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
        [1] An adversary sends a forge capability document (DSD, or SAD)
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

Usage:
        supnp [scenario #]

Example:
        supnp 1
```
