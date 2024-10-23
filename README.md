# SUPnP: Secure Access and Service Registration for UPnP-Enabled Internet of Things

This repository is a fork of the portable SDK for UPnP Devices ([libupnp](https://github.com/pupnp/pupnp)) with a secure layer extension as described in 
the paper [SUPnP: Secure Access and Service Registration for UPnP-Enabled Internet of Things](https://ieeexplore.ieee.org/document/9352973) 
by Kayas, G., Hossain, M., Payton, J., & Islam, S. R. (2021), IEEE Internet of Things Journal, 8(14), 11561-11580.

<br/> 

## Important Notice

It's strongly recommended to read the original `libupnp`'s [README](https://github.com/pupnp/pupnp/blob/branch-1.14.x/README.md) file before continuing with this one.
The current README file was edited to include specific `SUPnP` secure layer build instructions and usage, and some information was <ins>removed</ins> for simplicity.
To read more about `libupnp`, its usage, and licencing, please refer to the original [libupnp](https://github.com/pupnp/pupnp) repository.
For Licensing related to `SUPnP`, please consult the authors of the paper [SUPnP: Secure Access and Service Registration for UPnP-Enabled Internet of Things](https://ieeexplore.ieee.org/document/9352973).

The `SUPnP` secure layer implementation for `libupnp` was made as part of my MSc studies in computer science.
One should not use this implementation in a production environment as it is not fully tested and might have security flaws.
The implementation of `SUPnP` is intended for educational purposes only.

<br/>

## SUPnP Package Contents

For the original `libupnp` package contents, refer to [libupnp package contents](https://github.com/pupnp/pupnp/blob/branch-1.14.x/README.md#8-package-contents)

The SUPnP additons and modifications are:

| Path/File        | Description                                                                                                     |
|------------------|-----------------------------------------------------------------------------------------------------------------|
| README           | This file. Contains the installation and build instructions for SUPnP.                                          |
| cJSON            | Package for handling JSON files and content. For more information: [cJSON](https://github.com/DaveGamble/cJSON) |
| simulation       | Python scripts to simulate UPnP-CA (UCA) Device Enrollment, and demonstrate SUPnP Attack Scenarios.             |
| upnp/inc         | Additional supnp, openssl & file_utils include files.                                                           |
| upnp/src/supnp   | SUPnP source files.                                                                                             |
| upnp/src/opensll | OpenSSL wrapper source files.                                                                                   |
| upnp/src/file    | file utils source files.                                                                                        |
| upnp/sample      | Addiotonal Registration Authority source code and header files.                                                 |
| upnp/scripts     | SUPnP build automation scripts and interface setting scripts.                                                   |

That being said, a lot of files were modified with guards `#if ENABLE_SUPNP` to allow original compilation without the `SUPnP` layer.
However, some logics might be modified, so it's best to use the original `libupnp` if `SUPnP` is not required.

<br/>

## SUPnP Demonstration

This section demonstrates the SUPnP secure layer usage for Registration Authority (RA), 
Service Device (SD) and Control Point (CP).

For build and usage please proceed to the next sections.

For SUPnP Attack simulations, refer to [simulation/README.md](simulation/README.md#attack-scenarios).

<br/>

### Device Enrollment Simulation

For UPnP Certification Authority (UCA) device enrollment simulation, refer to [simulation/README.md](simulation/README.md#device-enrollment).

<br/>

### SUPnP protocol messages - captured by wireshark

This section shows the SUPnP protocol messages captured by Wireshark for the RA, SD, and CP.

The signatures, CapTokens, etc. are represented as hex strings. However, for simplicity of this file, they've been
truncated to `...`

#### RA Discovery

```html
M-SEARCH * HTTP/1.1
HOST: 239.255.255.250:1900
MAN: "ssdp:discover"
MX: 10
ST: urn:schemas-upnp-org:device:ra:1
```

#### RA discovery responses

```html
NOTIFY * HTTP/1.1
HOST: 239.255.255.250:1900
CACHE-CONTROL: max-age=100
LOCATION: http://192.168.1.100:49152/radesc.xml
OPT: "http://schemas.upnp.org/upnp/1/0/"; ns=01
01-NLS: ad697988-8fd9-11ef-a561-da1b695d95fc
NT: upnp:rootdevice
NTS: ssdp:alive
SERVER: Linux/6.8.0-47-generic, UPnP/1.0, Portable SDK for UPnP devices/17.2.1
X-User-Agent: redsonic
USN: uuid:SUpnp-RA-1_0-1234567890001::upnp:rootdevice
```

```html
NOTIFY * HTTP/1.1
HOST: 239.255.255.250:1900
CACHE-CONTROL: max-age=100
LOCATION: http://192.168.1.100:49152/radesc.xml
OPT: "http://schemas.upnp.org/upnp/1/0/"; ns=01
01-NLS: ad697988-8fd9-11ef-a561-da1b695d95fc
NT: uuid:SUpnp-RA-1_0-1234567890001
NTS: ssdp:alive
SERVER: Linux/6.8.0-47-generic, UPnP/1.0, Portable SDK for UPnP devices/17.2.1
X-User-Agent: redsonic
USN: uuid:SUpnp-RA-1_0-1234567890001
```

```html
NOTIFY * HTTP/1.1
HOST: 239.255.255.250:1900
CACHE-CONTROL: max-age=100
LOCATION: http://192.168.1.100:49152/radesc.xml
OPT: "http://schemas.upnp.org/upnp/1/0/"; ns=01
01-NLS: ad697988-8fd9-11ef-a561-da1b695d95fc
NT: urn:schemas-upnp-org:device:ra:1
NTS: ssdp:alive
SERVER: Linux/6.8.0-47-generic, UPnP/1.0, Portable SDK for UPnP devices/17.2.1
X-User-Agent: redsonic
USN: uuid:SUpnp-RA-1_0-1234567890001::urn:schemas-upnp-org:device:ra:1
```

```html
NOTIFY * HTTP/1.1
HOST: 239.255.255.250:1900
CACHE-CONTROL: max-age=100
LOCATION: http://192.168.1.100:49152/radesc.xml
OPT: "http://schemas.upnp.org/upnp/1/0/"; ns=01
01-NLS: ad697988-8fd9-11ef-a561-da1b695d95fc
NT: urn:schemas-upnp-org:service:registration:1
NTS: ssdp:alive
SERVER: Linux/6.8.0-47-generic, UPnP/1.0, Portable SDK for UPnP devices/17.2.1
X-User-Agent: redsonic
USN: uuid:SUpnp-RA-1_0-1234567890001::urn:schemas-upnp-org:service:registration:1
```

#### Registration message

Messages sent to RA by CP or SD.

1st message:

```html
POST /upnp/control/registration1 HTTP/1.1
HOST: 192.168.1.100:49152
CONTENT-LENGTH: 9168
Accept-Ranges: bytes
CONTENT-TYPE: text/xml; charset="utf-8"
SOAPACTION: "urn:schemas-upnp-org:service:registration:1#Register"
USER-AGENT: Linux/6.8.0-47-generic, UPnP/1.0, Portable SDK for UPnP devices/17.2.1

<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body><u:Register xmlns:u="urn:schemas-upnp-org:service:registration:1">
<SpecificationDocument>...</SpecificationDocument>
<CertificateDevice>...</CertificateDevice>
<CertificateUCA>...</CertificateUCA>
<DescriptionDocumentLocation>http://192.168.1.100:49153/tvdevicedesc.xml</DescriptionDocumentLocation>
<CapTokenLocation>http://192.168.1.100:49153/captoken_sd.json</CapTokenLocation>
</u:Register>
</s:Body>
</s:Envelope>
```

response: 

```html
HTTP/1.1 200 OK
CONTENT-LENGTH: 792
Accept-Ranges: bytes
CONTENT-TYPE: text/xml; charset="utf-8"
DATE: Mon, 21 Oct 2024 18:24:17 GMT
EXT:
SERVER: Linux/6.8.0-47-generic, UPnP/1.0, Portable SDK for UPnP devices/17.2.1
X-User-Agent: redsonic

<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>
<u:RegisterResponse xmlns:u="urn:schemas-upnp-org:service:registration:1">
<Challenge>...</Challenge>
</u:RegisterResponse>
</s:Body> </s:Envelope>
```

2nd message - challenge response:

```html
POST /upnp/control/registration1 HTTP/1.1
HOST: 192.168.1.100:49152
CONTENT-LENGTH: 1397
Accept-Ranges: bytes
CONTENT-TYPE: text/xml; charset="utf-8"
SOAPACTION: "urn:schemas-upnp-org:service:registration:1#Challenge"
USER-AGENT: Linux/6.8.0-47-generic, UPnP/1.0, Portable SDK for UPnP devices/17.2.1

<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body><u:Challenge xmlns:u="urn:schemas-upnp-org:service:registration:1">
<Challenge>...</Challenge>
<PublicKey>...</PublicKey>
</u:Challenge>
</s:Body>
</s:Envelope>
```

response: 

```html
HTTP/1.1 200 OK
CONTENT-LENGTH: 8356
Accept-Ranges: bytes
CONTENT-TYPE: text/xml; charset="utf-8"
DATE: Mon, 21 Oct 2024 18:24:17 GMT
EXT:
SERVER: Linux/6.8.0-47-generic, UPnP/1.0, Portable SDK for UPnP devices/17.2.1
X-User-Agent: redsonic

<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>
<u:ChallengeResponse xmlns:u="urn:schemas-upnp-org:service:registration:1">
<CapToken>...</CapToken>
<ActionResponse>1</ActionResponse>
</u:ChallengeResponse>
</s:Body> </s:Envelope>
```

#### Secure Service Advertisements

Messages sent by SD, after successful registration with RA.

```html
NOTIFY * HTTP/1.1
HOST: 239.255.255.250:1900
CACHE-CONTROL: max-age=100
LOCATION: http://192.168.1.100:49153/tvdevicedesc.xml
CAPTOKEN-LOCATION: http://192.168.1.100:49153/captoken_sd.json
ADVERTISEMENT-SIG: ...
OPT: "http://schemas.upnp.org/upnp/1/0/"; ns=01
01-NLS: ae892cc8-8fd9-11ef-8fba-85cd853f2837
NT: upnp:rootdevice
NTS: ssdp:alive
SERVER: Linux/6.8.0-47-generic, UPnP/1.0, Portable SDK for UPnP devices/17.2.1
X-User-Agent: redsonic
USN: uuid:Upnp-TVEmulator-1_0-1234567890001::upnp:rootdevice
```

```html
NOTIFY * HTTP/1.1
HOST: 239.255.255.250:1900
CACHE-CONTROL: max-age=100
LOCATION: http://192.168.1.100:49153/tvdevicedesc.xml
CAPTOKEN-LOCATION: http://192.168.1.100:49153/captoken_sd.json
ADVERTISEMENT-SIG: ...
OPT: "http://schemas.upnp.org/upnp/1/0/"; ns=01
01-NLS: ae892cc8-8fd9-11ef-8fba-85cd853f2837
NT: uuid:Upnp-TVEmulator-1_0-1234567890001
NTS: ssdp:alive
SERVER: Linux/6.8.0-47-generic, UPnP/1.0, Portable SDK for UPnP devices/17.2.1
X-User-Agent: redsonic
USN: uuid:Upnp-TVEmulator-1_0-1234567890001
```

```html
NOTIFY * HTTP/1.1
HOST: 239.255.255.250:1900
CACHE-CONTROL: max-age=100
LOCATION: http://192.168.1.100:49153/tvdevicedesc.xml
CAPTOKEN-LOCATION: http://192.168.1.100:49153/captoken_sd.json
ADVERTISEMENT-SIG: ...
OPT: "http://schemas.upnp.org/upnp/1/0/"; ns=01
01-NLS: ae892cc8-8fd9-11ef-8fba-85cd853f2837
NT: urn:schemas-upnp-org:device:tvdevice:1
NTS: ssdp:alive
SERVER: Linux/6.8.0-47-generic, UPnP/1.0, Portable SDK for UPnP devices/17.2.1
X-User-Agent: redsonic
USN: uuid:Upnp-TVEmulator-1_0-1234567890001::urn:schemas-upnp-org:device:tvdevice:1
```

```html
NOTIFY * HTTP/1.1
HOST: 239.255.255.250:1900
CACHE-CONTROL: max-age=100
LOCATION: http://192.168.1.100:49153/tvdevicedesc.xml
CAPTOKEN-LOCATION: http://192.168.1.100:49153/captoken_sd.json
ADVERTISEMENT-SIG: ...
OPT: "http://schemas.upnp.org/upnp/1/0/"; ns=01
01-NLS: ae892cc8-8fd9-11ef-8fba-85cd853f2837
NT: urn:schemas-upnp-org:service:tvcontrol:1
NTS: ssdp:alive
SERVER: Linux/6.8.0-47-generic, UPnP/1.0, Portable SDK for UPnP devices/17.2.1
X-User-Agent: redsonic
USN: uuid:Upnp-TVEmulator-1_0-1234567890001::urn:schemas-upnp-org:service:tvcontrol:1
```

When RA device shuts down, it signs only the description URL, since RA doen't have CapToken:
```html
NOTIFY * HTTP/1.1
HOST: 239.255.255.250:1900
CACHE-CONTROL: max-age=100
LOCATION: http://192.168.1.100:49152/radesc.xml
CAPTOKEN-LOCATION: ra
ADVERTISEMENT-SIG: ...
OPT: "http://schemas.upnp.org/upnp/1/0/"; ns=01
01-NLS: 02d61eba-9072-11ef-8724-d4a63343a7f8
NT: urn:schemas-upnp-org:service:registration:1
NTS: ssdp:byebye
SERVER: Linux/6.8.0-47-generic, UPnP/1.0, Portable SDK for UPnP devices/17.2.1
X-User-Agent: redsonic
USN: uuid:SUpnp-RA-1_0-1234567890001::urn:schemas-upnp-org:service:registration:1
```
##### Secure Service Discovery

Message sent by CP, after successful registration with RA.

```html
M-SEARCH * HTTP/1.1
HOST: 239.255.255.250:1900
MAN: "ssdp:discover"
MX: 10
ST: urn:schemas-upnp-org:device:tvdevice:1
CAPTOKEN-LOCATION: http://192.168.1.100:49154/captoken_cp.json
CAPTOKEN-LOCATION-SIG: ...
NONCE: ded2b674fcaf534606525ee4c90b6d77c35ed5f97e0f645598e27b994ec582c9
DISCOVERY-SIG: ...
```

#### Secure Control

Message sent by CP, by a requested command, after successful registration with RA.

```html
POST /upnp/control/tvcontrol1 HTTP/1.1
HOST: 192.168.1.100:49153
CONTENT-LENGTH: 238
Accept-Ranges: bytes
CONTENT-TYPE: text/xml; charset="utf-8"
CAPTOKEN-LOCATION: http://192.168.1.100:49154/captoken_cp.json
CAPTOKEN-LOCATION-SIG: 929cd5ebf3d16c08e10ee68f50d44a11e9cdf782843c01945c28695c007bb68562e794a8201e4e2206395af9dc08bdc2052b11ae56c8016e562908e8e386d853a8a9bd9c53144f05678ee4e94e9016bf034ce13ad777f3dc64262b21a4a4179ce379e9da1b13d85a311be5b154910261dd15080629effccfa4ca89b191168626c762dd8fa1e36f827a99a78b8ae88be67847db56219674bfc0212633ddeb3d358137758da6ea8e6fa9d42d4edf4a0c72537a840ff3bd0b1544b6b1f64b0a99d31ab9f1e15db7162c5208fe0c36bac9d1b796b2d9a0a5565f5cc521d6390335f0da13057b463936f74ec1433c167c799fead86c4173edcc4f22305747d5af4099
NONCE: cea37ac1b3b460726afed5e9ec9669099890ae5b550406ec0bfb5c4d66f494c2
ACTION-SIG: 8aab6ccd497cf97b1a527ee3490082ac9e408610043b8b414ca95fb510fce84eab2da08f53f74d75996a143ff273c0794a57dc16eed91ae89e0de2bd800e2219508720c51203da1d59d1890007f939df650956e21c907111e26f54dc1909dac466f5ed216fe05c1dff65c4c66276f6f1596f97d71f86695208cd5122621a0f1d5c8a5dabff698782b9d1d22e952fbddef6a8de33b197729696999453d05c55c8ab371e603df977c775c00514f1577c2a1ac54fab56755f7fe4c91e643b835540cce529f43dd9b11e6c7d333b570b332622234be854bdb74f68063e769b23ed211a71e4ee01bf3f350576d7b0b5bd40395dc29a0ff8eaf8be7388127c291af127
SOAPACTION: "urn:schemas-upnp-org:service:tvcontrol:1#PowerOn"
USER-AGENT: Linux/6.8.0-47-generic, UPnP/1.0, Portable SDK for UPnP devices/17.2.1

<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body><u:PowerOn xmlns:u="urn:schemas-upnp-org:service:tvcontrol:1"></u:PowerOn>
</s:Body>
</s:Envelope>
```

response:

```html
HTTP/1.1 200 OK
CONTENT-LENGTH: 268
Accept-Ranges: bytes
CONTENT-TYPE: text/xml; charset="utf-8"
DATE: Mon, 21 Oct 2024 18:24:40 GMT
EXT:
SERVER: Linux/6.8.0-47-generic, UPnP/1.0, Portable SDK for UPnP devices/17.2.1
X-User-Agent: redsonic

<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>
<u:PowerOnResponse xmlns:u="urn:schemas-upnp-org:service:tvcontrol:1">
<Power>1</Power>
</u:PowerOnResponse>
</s:Body> </s:Envelope>
```

#### Secure Event Subscription

Message sent by CP, to subscribe to SD events.

```html
SUBSCRIBE /upnp/event/tvcontrol1 HTTP/1.1
HOST: 192.168.1.100:49153
CALLBACK: <http://192.168.1.100:49154/>
NONCE: 95be6089641d2d677dba8d9fc6b450655f6bd1f5821a9d9d3b731de3dfa54840
EVENT-SIG: ...
CAPTOKEN-LOCATION: http://192.168.1.100:49154/captoken_cp.json
CAPTOKEN-LOCATION-SIG: ...
NT: upnp:event
TIMEOUT: Second-1801
```

response: 

```html
HTTP/1.1 200 OK
DATE: Mon, 21 Oct 2024 18:24:37 GMT
SERVER: Linux/6.8.0-47-generic, UPnP/1.0, Portable SDK for UPnP devices/17.2.1
CONTENT-LENGTH: 0
Accept-Ranges: bytes
X-User-Agent: redsonic
SID: uuid:ba7a77f8-8fd9-11ef-8fba-85cd853f2837
TIMEOUT: Second-1801
```

<br/>

### Run Logs

For RA, SD, and CP run logs, refer to [upnp/sample/README.md](upnp/sample/README.md).

<br/>

## System Requirements

The `SUPnP` fork, same as the original SDK for UPnP Devices, is designed to compile and run under several operating systems.  
It does, however, have dependencies on some packages that may not be installed by default.
All packages that it requires are listed below.

| Dependency | Description                                                                              |
| ---------- | ---------------------------------------------------------------------------------------- |
| libpthread | The header and library are installed as part of the glibc-devel package (or equivalent). |
| libssl-dev | Required by [OpenSSL](#configure-openssl) / [SUPnP](#configure-supnp) only.              | 

Additionally, the documentation for the original `libupnp` can be auto-generated from the upnp.h header file using Doxygen.
Refer to `libupnp` [System Requirements](https://github.com/pupnp/pupnp/blob/branch-1.14.x/README.md#9-system-requirements) for more information.

For the UPnP library to function correctly, networking must be configured properly for multicasting.  To do this:

```bash
% route add -net 239.0.0.0 netmask 255.0.0.0 eth0
```

where 'eth0' is the network adapter that the UPnP library will use.  Without this addition, device advertisements 
and control point searches will not function.

`SUPnP` fork has an automation script which can be invoked for this purpose. It creates a virtual interface and sets it for multicasting.

```bash
./scripts/set_interface.sh eth0
```

<br/>

## Build Instructions

### Pre-requisites

Some packages/tools are required to build the library. Here's a minimal 'inspirational example'
that builds the library using a Docker Ubuntu image.

```bash
% docker run -it --rm ubuntu /bin/bash

# libssl-dev is required by SUPnP & OpenSSL layers.
% apt update \
  && apt install -y build-essential autoconf libtool pkg-config git shtool libssl-dev \
  && git clone https://github.com/romansko/supnp.git \
  && cd pupnp

% ./scripts/cmake_supnp.sh   # cmake build
# OR
% ./scripts/make_supnp.sh    # autotools build

# Cleaning:
# ./scripts/clean.sh
```

### Core Libraries

Note: On a git checkout, you need to run `./bootstrap` to generate the configure script.

```bash
% ./configure
% make
```

will build a version of the binaries without debug support, and with default options enabled (see below for
options available at configure time).

```bash
% ./configure CFLAGS="-DSPARC_SOLARIS -mtune=<cputype> -mcpu=<cputype>"
% make
```

will build a Sparc Solaris version of the binaries without debug support and with default options enabled (see below for options available at configure time). 
Please note: \<cputype\> has to be replaced by a token that fits to your platform and CPU (e.g. "supersparc").

To build the documentation, assuming all the necessary tools are installed:

To generate the HTML documentation:

```bash
% make html
```

To generate the PDF file:

```bash
% make pdf
```

A few options are available at configure time. Use "./configure --help" to display a complete list of options. 
Note that these options may be combined in any order. After installation, the file \<upnp/upnpconfig.h\> will provide a 
summary of the optional features that have been included in the library.

```bash
% ./configure --enable-debug
% make
```

will build a debug version with symbols support.

<a name="configure-openssl"></a>
To build the library with OpenSSL support:
```bash
apt install libssl-dev
% ./configure --enable-open_ssl
make
```

<a name="configure-supnp"></a>
To build the library with SUPnP secure layer as presented by the paper 
[Kayas, G., Hossain, M., Payton, J., & Islam, S. R. (2021). SUPnP: Secure Access and Service Registration for UPnP-Enabled Internet of Things. IEEE Internet of Things Journal, 8(14), 11561-11580](https://ieeexplore.ieee.org/document/9352973):

```bash
% ./configure --enable-supnp
% make
```

Automation script is available under `scripts/make_supnp.sh`

Note that SUPnP requires OpenSSL. Hence, The `--enable-open_ssl` flag is set automatically. 
However, the installation of `libssl-dev` should be done manually by:

```bash
% apt install libssl-dev
```

To build the library with the optional, integrated mini web server (note that this is the default):

```bash
% ./configure --enable-webserver
% make
```

To build without:

```bash
% ./configure --disable-webserver
% make
```

The SDK also contains some additional helper APIs, declared in inc/tools/upnptools.h. 
If these additional tools are not required, they can be compiled out:

```bash
% ./configure --disable-tools
% make
```

By default, the tools are included in the library.

To further remove code that is not required, the library can be build with or with out the control point (client) or 
device specific code.  To remove this code:

```bash
% ./configure --disable-client
% make
```

to remove client only code or:

```bash
% ./configure --disable-device
% make
```

to remove device only code.

By default, both client and device code is included in the library. 
The integrated web server is automatically removed when configuring with --disable-device.

To build the library without large-file support (enabled by default):

```bash
% ./configure --disable-largefile
% make
```

To remove all the targets, object files, and built documentation:

```bash
% make clean
```

or by `./scripts/clean.sh` script.

### Cross Compilation

To cross compile the SDK, a special "configure" directive is all that is required:

```bash
% ./configure --host=arm-linux
% make
```

This will invoke the "arm-linux-gcc" cross compiler to build the library.

### Samples

The SDK contains two samples: a TV device application and a control point that talks with the TV device.  
They are found in the $(LIBUPNP)/upnp/sample directory.

To build the samples (note: this is the default behavior):

```bash
% ./configure --enable-samples
% make
```

will build the sample device "$(LIBUPNP)/upnp/tv_device" and sample control point "$(LIBUPNP)/upnp/tv_ctrlpt".
Note : the sample device won't be built if --disable-device has been configured, and the sample control point won't be 
build if --disable-client has been configured.

To run the sample device, you need to create a tvdevice directory and move the web directory there,
giving: "$(LIBUPNP)/upnp/sample/tvdevice/web". To run the sample invoke from the command line as follows:

```bash
% cd ./upnp/sample/tvdevice
% ../tv_device
```

### Solaris Build

The building process for the Solaris operating system is similar to the one described above. 
Only the call to ./configure has to be done using an additional parameter:

```bash
% ./configure CFLAGS="-mcpu=<cputype> -mtune=<cputype> -DSPARC_SOLARIS"
```

where \<cputype\> has to be replaced by the appropriate CPU tuning flag (e.g. "supersparc"). Afterwards

```bash
% make
% make install
```

can be called as described above.

### Windows Build

See the section `CMake Build`

### CMake Build

In Order to build everything using the cmake build system, you just need to install cmake for your platform.
Standalone cmake is recommended, IDE's like Visual Studio have built-in support which works, but as cmake in general
encourages out-of-source builds and VS writes it's config into the source, cmake-gui should be used on windows.

All known options have the same meaning as stated previously. In Addition, 2 options have been added.

- DOWNLOAD_AND_BUILD_DEPS: This option is only available if a usable git program was found on your system.
  With this option on, the pthread4w package will be downloaded while configuring the build-env, then it will be build 
- and installed along with upnp.

- BUILD_TESTING: This option activates the tests.

**To build `libupnp` with SUPnP secure layer:**

```bash
cmake -DENABLE_SUPNP=ON .
make
```

Automation script is available under `scripts/cmake_supnp.sh`

If you don't want to build pthreads4w in the same build as upnp, 
you can download it from <https://github.com/Vollstrecker/pthreads4w>.
Just build and install it. The libs and headers will be found, 
if you set CMAKE_INSTALL_PREFIX (the base install dir) to the same location.

For information on general usage of the cmake build system see: <https://cmake.org/cmake/help/v3.19/guide/user-interaction/index.html>

<br/>

## Install/Uninstall Instructions

### Install

The top-level makefile for the UPnP SDK contains rules to install the necessary components.  To install the SDK, as root:

```bash
% make install
```

### Uninstall

Likewise, the top-level makefile contains an uninstall rule, reversing the steps in the install:

```bash
% make uninstall
```

<br/>

For original `libupnp` instructions (which are mostly the same as written above), refer to `libupnp` [Build Instructions](https://github.com/pupnp/pupnp/blob/branch-1.14.x/README.md#10-build-instructions)

<br/>


## Thanks

*Original thanks from `libupnp`*

- To all the people listed in [the THANKS file](THANKS).
- To [JetBrains](https://www.jetbrains.com/?from=pupnp) for kindly providing us with open source licenses of their amazing products.

![JetBrains Logo](site/jetbrains.svg)
