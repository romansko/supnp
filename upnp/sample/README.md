# SUPnP Run logs

This section contains truncated run logs for proof of concept of SUPnP samples.

## RA - single

```bash
supnp/upnp/sample$ ./registration_authority -i eth0
Initializing [S]UPnP Sdk with
        interface = eth0 port = 0
[SUPnP] [tid 136719972922688] SUpnpInit(212): Initializing SUPnP secure layer..
[SSL_W] [tid 136719972922688] OpenSslInitializeWrapper(50): Initializing OpenSSL Wrapper..
UPnP Initialized
        ipaddress = 192.168.1.100 port = 49152
Specifying the webserver root directory -- ./web
Registering the RootDevice
         with desc_doc_url: http://192.168.1.100:49152/radesc.xml
RootDevice Registered
Initializing State Table
Found service: urn:schemas-upnp-org:service:registration:1
serviceId: urn:upnp-org:serviceId:registration1
State Table Initialized
State Table Initialized
Advertisements Sent
```

## SD - single

```bash
supnp/upnp/sample$ ./tv_device -i eth0
Initializing UPnP Sdk with
        interface = eth0 port = 0
[SUPnP] [tid 125223405147456] SUpnpInit(212): Initializing SUPnP secure layer..
[SSL_W] [tid 125223405147456] OpenSslInitializeWrapper(50): Initializing OpenSSL Wrapper..
UPnP Initialized
        ipaddress = 192.168.1.100 port = 49152
Specifying the webserver root directory -- ./web
Registering the RootDevice
         with desc_doc_url: http://192.168.1.100:49152/tvdevicedesc.xml
         with cap_token_url: http://192.168.1.100:49152/captoken_sd.json
RootDevice Registered
Initializing State Table
Found service: urn:schemas-upnp-org:service:tvcontrol:1
serviceId: urn:upnp-org:serviceId:tvcontrol1
Found service: urn:schemas-upnp-org:service:tvpicture:1
serviceId: urn:upnp-org:serviceId:tvpicture1
State Table Initialized
Registering SD with RA..
```

## CP - single

```bash
supnp/upnp/sample$ ./tv_ctrlpt -i eth0
Initializing UPnP Sdk with
        interface = eth0 port = 0
[SUPnP] [tid 140600260490560] SUpnpInit(212): Initializing SUPnP secure layer..
[SSL_W] [tid 140600260490560] OpenSslInitializeWrapper(50): Initializing OpenSSL Wrapper..
UPnP Initialized
        ipv4 address = 192.168.1.100 port = 49152
        ipv6 address =  port = 0
        ipv6ulagua address =  port = 0
Registering Control Point..
```

## SD - while RA is running

```bash
supnp/upnp/sample$ ./tv_device -i eth0
Initializing UPnP Sdk with
        interface = eth0 port = 0
[SUPnP] [tid 125281159943488] SUpnpInit(212): Initializing SUPnP secure layer..
[SSL_W] [tid 125281159943488] OpenSslInitializeWrapper(50): Initializing OpenSSL Wrapper..
UPnP Initialized
        ipaddress = 192.168.1.100 port = 49153
Specifying the webserver root directory -- ./web
Registering the RootDevice
         with desc_doc_url: http://192.168.1.100:49153/tvdevicedesc.xml
         with cap_token_url: http://192.168.1.100:49153/captoken_sd.json
RootDevice Registered
Initializing State Table
Found service: urn:schemas-upnp-org:service:tvcontrol:1
serviceId: urn:upnp-org:serviceId:tvcontrol1
Found service: urn:schemas-upnp-org:service:tvpicture:1
serviceId: urn:upnp-org:serviceId:tvpicture1
State Table Initialized
Registering SD with RA..

[SUPnP] [tid 125281096435392] RegistrationCallbackEventHandler(767): SUPnP Device Registered
[SUPnP] [tid 125281096435392] RegistrationCallbackSD(1415): SD registered with RA successfully.
[SUPnP] [tid 125281096435392] SUpnpSendAdvertisement(1037): Secure Service Advertisement: sending..
```

## CP - while RA is running

```bash
supnp/upnp/sample$ ./tv_ctrlpt -i eth0
Initializing UPnP Sdk with
        interface = eth0 port = 0
[SUPnP] [tid 129309614556480] SUpnpInit(212): Initializing SUPnP secure layer..
[SSL_W] [tid 129309614556480] OpenSslInitializeWrapper(50): Initializing OpenSSL Wrapper..
UPnP Initialized
        ipv4 address = 192.168.1.100 port = 49153
        ipv6 address =  port = 0
        ipv6ulagua address =  port = 0
Registering Control Point..

>> [SUPnP] [tid 129309572335296] RegistrationCallbackEventHandler(767): SUPnP Device Registered
Control Point Registered with RA
[SUPnP] [tid 129309572335296] SUpnpSearchAsync(1154): Secure Service Discovery: sending..
```

## RA - while either SD is running

```bash
supnp/upnp/sample$ ./registration_authority -i eth0
Initializing [S]UPnP Sdk with
        interface = eth0 port = 0
[SUPnP] [tid 139669704783168] SUpnpInit(212): Initializing SUPnP secure layer..
[SSL_W] [tid 139669704783168] OpenSslInitializeWrapper(50): Initializing OpenSSL Wrapper..
UPnP Initialized
        ipaddress = 192.168.1.100 port = 49152
Specifying the webserver root directory -- ./web
Registering the RootDevice
         with desc_doc_url: http://192.168.1.100:49152/radesc.xml
RootDevice Registered
Initializing State Table
Found service: urn:schemas-upnp-org:service:registration:1
serviceId: urn:upnp-org:serviceId:registration1
State Table Initialized
State Table Initialized
Advertisements Sent

[SUPnP] [tid 139669620655808] SUpnpVerifyDocument(342): Verifying SD user-friendly name document. Type: 'SD'.
[SSL_W] [tid 139669620655808] OpenSslVerifyCertificate(298): Verifying 'UCA''s certificate..
[SSL_W] [tid 139669620655808] OpenSslVerifyCertificate(298): Verifying 'SD user-friendly name''s certificate..
[SUPnP] [tid 139669620655808] SUpnpVerifyDocument(373): Signature Verification Conditions: 2-of-2
[SUPnP] [tid 139669620655808] SUpnpVerifyDocument(426): 'SIG-OWNER' signature ok.
[SUPnP] [tid 139669620655808] SUpnpVerifyDocument(426): 'SIG-UCA' signature ok.
[SUPnP] [tid 139669620655808] SUpnpVerifyDocument(484): SD Services ok.
[SUPnP] [tid 139669620655808] SUpnpVerifyDocument(485): Service Device's DSD ok.
======================================================================
----------------------------------------------------------------------
UPNP_CONTROL_ACTION_REQUEST
ErrCode     =  0
ErrStr      =  
ActionName  =  Register
UDN         =  uuid:SUpnp-RA-1_0-1234567890001
ServiceID   =  urn:upnp-org:serviceId:registration1
ActRequest  =  <u:Register xmlns:u="urn:schemas-upnp-org:service:registration:1">
<SpecificationDocument>7b0a20202...</SpecificationDocument>
<CertificateDevice>2d2d2d2d2d424...</CertificateDevice>
<CertificateUCA>2d2d2d2d2d424547...</CertificateUCA>
<u:RegisterResponse xmlns:u="urn:schemas-upnp-org:service:registration:1">
<Challenge>b874de5b63de1491c6257...</Challenge>
</u:RegisterResponse>

----------------------------------------------------------------------
======================================================================



Device SD user-friendly name challenge successfully verified
[SUPnP] [tid 139669641627328] SUpnpGenerateCapToken(127): Generating CapToken for device 'SD' - SD user-friendly name..
[SUPnP] [tid 139669641627328] SUpnpGenerateCapToken(276): CapToken for device SD user-friendly name generated successfully.
======================================================================
----------------------------------------------------------------------
UPNP_CONTROL_ACTION_REQUEST
ErrCode     =  0
ErrStr      =  
ActionName  =  Challenge
UDN         =  uuid:SUpnp-RA-1_0-1234567890001
ServiceID   =  urn:upnp-org:serviceId:registration1
ActRequest  =  <u:Challenge xmlns:u="urn:schemas-upnp-org:service:registration:1">
<Challenge>0b170e6bf...</Challenge>
<PublicKey>308201223...</PublicKey>
</u:Challenge>

ActResult   =  <u:ChallengeResponse xmlns:u="urn:schemas-upnp-org:service:registration:1">
<CapToken>7b2249...</CapToken>
<ActionResponse>1</ActionResponse>
----------------------------------------------------------------------
======================================================================
```

## RA - while either CP is running

```bash
supnp/upnp/sample$ ./registration_authority -i eth0
Initializing [S]UPnP Sdk with
        interface = eth0 port = 0
[SUPnP] [tid 139973778056512] SUpnpInit(212): Initializing SUPnP secure layer..
[SSL_W] [tid 139973778056512] OpenSslInitializeWrapper(50): Initializing OpenSSL Wrapper..
UPnP Initialized
        ipaddress = 192.168.1.100 port = 49152
Specifying the webserver root directory -- ./web
Registering the RootDevice
         with desc_doc_url: http://192.168.1.100:49152/radesc.xml
RootDevice Registered
Initializing State Table
Found service: urn:schemas-upnp-org:service:registration:1
serviceId: urn:upnp-org:serviceId:registration1
State Table Initialized
State Table Initialized
Advertisements Sent

[SUPnP] [tid 139973693015744] SUpnpVerifyDocument(342): Verifying CP user-friendly name document. Type: 'CP'.
[SSL_W] [tid 139973693015744] OpenSslVerifyCertificate(298): Verifying 'UCA''s certificate..
[SSL_W] [tid 139973693015744] OpenSslVerifyCertificate(298): Verifying 'CP user-friendly name''s certificate..
[SUPnP] [tid 139973693015744] SUpnpVerifyDocument(373): Signature Verification Conditions: 2-of-2
[SUPnP] [tid 139973693015744] SUpnpVerifyDocument(426): 'SIG-OWNER' signature ok.
[SUPnP] [tid 139973693015744] SUpnpVerifyDocument(426): 'SIG-UCA' signature ok.
[SUPnP] [tid 139973693015744] SUpnpVerifyDocument(432): Control Point's SAD ok.
======================================================================
----------------------------------------------------------------------
UPNP_CONTROL_ACTION_REQUEST
ErrCode     =  0
ErrStr      =  
ActionName  =  Register
UDN         =  uuid:SUpnp-RA-1_0-1234567890001
ServiceID   =  urn:upnp-org:serviceId:registration1
ActRequest  =  <u:Register xmlns:u="urn:schemas-upnp-org:service:registration:1">
<SpecificationDocument>...</SpecificationDocument>
<CertificateDevice>...</CertificateDevice>
<CertificateUCA>...</CertificateUCA>
<u:RegisterResponse xmlns:u="urn:schemas-upnp-org:service:registration:1">
<Challenge>...</Challenge>
</u:RegisterResponse>

----------------------------------------------------------------------
======================================================================



[SUPnP] [tid 139973682529984] SUpnpVerifyDocument(342): Verifying CP user-friendly name document. Type: 'CP'.
[SSL_W] [tid 139973682529984] OpenSslVerifyCertificate(298): Verifying 'UCA''s certificate..
[SSL_W] [tid 139973682529984] OpenSslVerifyCertificate(298): Verifying 'CP user-friendly name''s certificate..
[SUPnP] [tid 139973682529984] SUpnpVerifyDocument(373): Signature Verification Conditions: 2-of-2
[SUPnP] [tid 139973682529984] SUpnpVerifyDocument(426): 'SIG-OWNER' signature ok.
[SUPnP] [tid 139973682529984] SUpnpVerifyDocument(426): 'SIG-UCA' signature ok.
[SUPnP] [tid 139973682529984] SUpnpVerifyDocument(432): Control Point's SAD ok.
======================================================================
----------------------------------------------------------------------
UPNP_CONTROL_ACTION_REQUEST
ErrCode     =  0
ErrStr      =  
ActionName  =  Register
UDN         =  uuid:SUpnp-RA-1_0-1234567890001
ServiceID   =  urn:upnp-org:serviceId:registration1
ActRequest  =  <u:Register xmlns:u="urn:schemas-upnp-org:service:registration:1">
<SpecificationDocument>...</SpecificationDocument>
<CertificateDevice>..</CertificateDevice>
<CertificateUCA>..   =  <u:RegisterResponse xmlns:u="urn:schemas-upnp-org:service:registration:1">
<Challenge>...</Challenge>
</u:RegisterResponse>

----------------------------------------------------------------------
======================================================================



Device CP user-friendly name challenge successfully verified
[SUPnP] [tid 139973713987264] SUpnpGenerateCapToken(127): Generating CapToken for device 'CP' - CP user-friendly name..
[SUPnP] [tid 139973713987264] SUpnpGenerateCapToken(276): CapToken for device CP user-friendly name generated successfully.
======================================================================
----------------------------------------------------------------------
UPNP_CONTROL_ACTION_REQUEST
ErrCode     =  0
ErrStr      =  
ActionName  =  Challenge
UDN         =  uuid:SUpnp-RA-1_0-1234567890001
ServiceID   =  urn:upnp-org:serviceId:registration1
ActRequest  =  <u:Challenge xmlns:u="urn:schemas-upnp-org:service:registration:1">
<Challenge>...</Challenge>
<PublicKey>...</PublicKey>
</u:Challenge>

ActResult   =  <u:ChallengeResponse xmlns:u="urn:schemas-upnp-org:service:registration:1">
<CapToken>...</CapToken>
<ActionResponse>1</ActionResponse>
</u:ChallengeResponse>
----------------------------------------------------------------------
======================================================================
```

## FULL - RA, SD, CP running at the same time

After registration, CP & SD are talking directly without RA. Hence the run log from above for RA is not changed.

### SD - Full

```bash
supnp/upnp/sample$ ./tv_device -i eth0
Initializing UPnP Sdk with
        interface = eth0 port = 0
[SUPnP] [tid 133694495704384] SUpnpInit(212): Initializing SUPnP secure layer..
[SSL_W] [tid 133694495704384] OpenSslInitializeWrapper(50): Initializing OpenSSL Wrapper..
UPnP Initialized
        ipaddress = 192.168.1.100 port = 49153
Specifying the webserver root directory -- ./web
Registering the RootDevice
         with desc_doc_url: http://192.168.1.100:49153/tvdevicedesc.xml
         with cap_token_url: http://192.168.1.100:49153/captoken_sd.json
RootDevice Registered
Initializing State Table
Found service: urn:schemas-upnp-org:service:tvcontrol:1
serviceId: urn:upnp-org:serviceId:tvcontrol1
Found service: urn:schemas-upnp-org:service:tvpicture:1
serviceId: urn:upnp-org:serviceId:tvpicture1
State Table Initialized
Registering SD with RA..

[SUPnP] [tid 133694452926144] RegistrationCallbackEventHandler(767): SUPnP Device Registered
[SUPnP] [tid 133694452926144] RegistrationCallbackSD(1415): SD registered with RA successfully.
[SUPnP] [tid 133694452926144] SUpnpSendAdvertisement(1037): Secure Service Advertisement: sending..
[SUPnP] [tid 133694390011584] SUpnpSecureServiceDiscoveryVerify(1172): Secure Service Discovery verification..
[SUPnP] [tid 133694390011584] SUpnpSecureServiceDiscoveryVerify(1176): Secure Service Discovery successful.
[SUPnP] [tid 133694421468864] SUpnpSendAdvertisement(1037): Secure Service Advertisement: sending..
[SUPnP] [tid 133694410983104] SUpnpSecureEventingVerify(1425): Secure Event Subscription verification..
[SUPnP] [tid 133694410983104] SUpnpSecureEventingVerify(1430): Secure Event Subscription successful.
======================================================================
----------------------------------------------------------------------
UPNP_EVENT_SUBSCRIPTION_REQUEST
ServiceID   =  urn:upnp-org:serviceId:tvcontrol1
UDN         =  uuid:Upnp-TVEmulator-1_0-1234567890001
SID         =  uuid:29a27b74-8fd7-11ef-ae84-d88797f1de9f
----------------------------------------------------------------------
======================================================================



[SUPnP] [tid 133694452926144] SUpnpSecureEventingVerify(1425): Secure Event Subscription verification..
[SUPnP] [tid 133694452926144] SUpnpSecureEventingVerify(1430): Secure Event Subscription successful.
======================================================================
----------------------------------------------------------------------
UPNP_EVENT_SUBSCRIPTION_REQUEST
ServiceID   =  urn:upnp-org:serviceId:tvpicture1
UDN         =  uuid:Upnp-TVEmulator-1_0-1234567890001
SID         =  uuid:29a31e62-8fd7-11ef-ae84-d88797f1de9f
----------------------------------------------------------------------
======================================================================
```

After sending `PowerOn 1` command from CP:

```bash


[SUPnP] [tid 131016094123712] SUpnpSecureControlVerify(1318): Secure Control verification..
[SUPnP] [tid 131016094123712] SUpnpSecureControlVerify(1322): Secure Control successful.
======================================================================
----------------------------------------------------------------------
UPNP_CONTROL_ACTION_REQUEST
ErrCode     =  0
ErrStr      =  
ActionName  =  PowerOn
UDN         =  uuid:Upnp-TVEmulator-1_0-1234567890001
ServiceID   =  urn:upnp-org:serviceId:tvcontrol1
ActRequest  =  <u:PowerOn xmlns:u="urn:schemas-upnp-org:service:tvcontrol:1"></u:PowerOn>

ActResult   =  <u:PowerOnResponse xmlns:u="urn:schemas-upnp-org:service:tvcontrol:1">
<Power>1</Power>
</u:PowerOnResponse>

----------------------------------------------------------------------
======================================================================
```


### CP - Full

```bash
supnp/upnp/sample$ ./tv_ctrlpt -i eth0
Initializing UPnP Sdk with
        interface = eth0 port = 0
[SUPnP] [tid 127513880167744] SUpnpInit(212): Initializing SUPnP secure layer..
[SSL_W] [tid 127513880167744] OpenSslInitializeWrapper(50): Initializing OpenSSL Wrapper..
UPnP Initialized
        ipv4 address = 192.168.1.100 port = 49154
        ipv6 address =  port = 0
        ipv6ulagua address =  port = 0
Registering Control Point..

>> [SUPnP] [tid 127513837700800] RegistrationCallbackEventHandler(767): SUPnP Device Registered
Control Point Registered with RA
[SUPnP] [tid 127513837700800] SUpnpSearchAsync(1154): Secure Service Discovery: sending..
======================================================================
----------------------------------------------------------------------
UPNP_DISCOVERY_ADVERTISEMENT_ALIVE
ErrCode      =  0
Expires      =  100
DeviceId     =  uuid:SUpnp-RA-1_0-1234567890001
DeviceType   =  
ServiceType  =  
ServiceVer   =  
Location     =  http://192.168.1.100:49152/radesc.xml
CapTokenUrl  =  
AdvSignature =  
OS           =  Linux/6.8.0-47-generic, UPnP/1.0, Portable SDK for UPnP devices/17.2.1
Date         =  
Ext          =  
----------------------------------------------------------------------
======================================================================


======================================================================
----------------------------------------------------------------------
UPNP_DISCOVERY_ADVERTISEMENT_ALIVE
ErrCode      =  0
Expires      =  100
DeviceId     =  uuid:SUpnp-RA-1_0-1234567890001
DeviceType   =  
ServiceType  =  urn:schemas-upnp-org:service:registration:1
ServiceVer   =  
Location     =  http://192.168.1.100:49152/radesc.xml
CapTokenUrl  =  
AdvSignature =  
OS           =  Linux/6.8.0-47-generic, UPnP/1.0, Portable SDK for UPnP devices/17.2.1
Date         =  
Ext          =  
----------------------------------------------------------------------
======================================================================

[SUPnP] [tid 127513837700800] SUpnpSecureServiceAdvertisementVerify(1063): Verifying Secure Service Advertisement ..
[SUPnP] [tid 127513837700800] SUpnpSecureServiceAdvertisementVerify(1078): Verifying Secure Service Advertisement..
[SUPnP] [tid 127513848186560] SUpnpSecureServiceAdvertisementVerify(1063): Verifying Secure Service Advertisement ..
[SUPnP] [tid 127513848186560] SUpnpSecureServiceAdvertisementVerify(1078): Verifying Secure Service Advertisement..
[SUPnP] [tid 127513837700800] SUpnpVerifyCapToken(434): Verifying Cap Token..
[SUPnP] [tid 127513848186560] SUpnpVerifyCapToken(434): Verifying Cap Token..
[SUPnP] [tid 127513837700800] SUpnpVerifyCapToken(454): Verifying RA Signature..
[SUPnP] [tid 127513848186560] SUpnpVerifyCapToken(454): Verifying RA Signature..
[SUPnP] [tid 127513837700800] SUpnpVerifyCapToken(470): RA Signature verified successfully.
[SUPnP] [tid 127513837700800] SUpnpVerifyCapToken(474): Verifying Description Signature..
[SUPnP] [tid 127513837700800] SUpnpVerifyCapToken(484): Description Signature verified successfully.
[SUPnP] [tid 127513837700800] SUpnpSecureServiceAdvertisementVerify(1105): Secure Service Advertisement verified successfully.
[SUPnP] [tid 127513848186560] SUpnpVerifyCapToken(470): RA Signature verified successfully.
[SUPnP] [tid 127513848186560] SUpnpVerifyCapToken(474): Verifying Description Signature..
======================================================================
----------------------------------------------------------------------
UPNP_DISCOVERY_ADVERTISEMENT_ALIVE
ErrCode      =  0
Expires      =  100
DeviceId     =  uuid:Upnp-TVEmulator-1_0-1234567890001
DeviceType   =  
ServiceType  =  
ServiceVer   =  
Location     =  http://192.168.1.100:49153/tvdevicedesc.xml
CapTokenUrl  =  http://192.168.1.100:49153/captoken_sd.json
AdvSignature =  ...
OS           =  Linux/6.8.0-47-generic, UPnP/1.0, Portable SDK for UPnP devices/17.2.1
Date         =  
Ext          =  
----------------------------------------------------------------------
======================================================================



[SUPnP] [tid 127513848186560] SUpnpVerifyCapToken(484): Description Signature verified successfully.
[SUPnP] [tid 127513848186560] SUpnpSecureServiceAdvertisementVerify(1105): Secure Service Advertisement verified successfully.

======================================================================
----------------------------------------------------------------------
UPNP_EVENT_RECEIVED
SID         =  uuid:5e166de8-8fd7-11ef-9d7f-d509b3d57143
EventKey    =  0
ChangedVars =  <e:propertyset xmlns:e="urn:schemas-upnp-org:event-1-0">
<e:property>
<Power>1</Power>
</e:property>
<e:property>
<Channel>1</Channel>
</e:property>
<e:property>
<Volume>5</Volume>
</e:property>
</e:propertyset>

----------------------------------------------------------------------
======================================================================


======================================================================
----------------------------------------------------------------------
UPNP_EVENT_RECEIVED
SID         =  uuid:5e1784ee-8fd7-11ef-9d7f-d509b3d57143
EventKey    =  0
ChangedVars =  <e:propertyset xmlns:e="urn:schemas-upnp-org:event-1-0">
<e:property>
<Color>5</Color>
</e:property>
<e:property>
<Tint>5</Tint>
</e:property>
<e:property>
<Contrast>5</Contrast>
</e:property>
<e:property>
<Brightness>5</Brightness>
</e:property>
</e:propertyset>

----------------------------------------------------------------------
======================================================================


Subscribed to EventURL with SID=uuid:5e1784ee-8fd7-11ef-9d7f-d509b3d57143
TvCtrlPointPrintList:
[SUPnP] [tid 127513642665664] SUpnpVerifyCapToken(434): Verifying Cap Token..
[SUPnP] [tid 127513642665664] SUpnpVerifyCapToken(454): Verifying RA Signature..


Found Tv device
TvCtrlPointPrintList:
   1 -- uuid:Upnp-TVEmulator-1_0-1234567890001
```

After sending `PowerOn 1` command from CP:

```bash
>> PowerOn 1
[SUPnP] [tid 124593467557568] SUpnpSendActionAsync(1262): Secure Control: Sending Secure Action..

>> ======================================================================
----------------------------------------------------------------------
UPNP_EVENT_RECEIVED
SID         =  uuid:0d52ffec-8fd8-11ef-9c7b-ceac702fb616
EventKey    =  1
ChangedVars =  <e:propertyset xmlns:e="urn:schemas-upnp-org:event-1-0">
<e:property>
<Power>1</Power>
</e:property>
</e:propertyset>

----------------------------------------------------------------------
======================================================================



Received Tv Control Event: 1 for SID uuid:0d52ffec-8fd8-11ef-9c7b-ceac702fb616
Tv State Update (service 0):
 Variable Name: Power New Value:'1'
======================================================================
----------------------------------------------------------------------
UPNP_CONTROL_ACTION_COMPLETE
ErrCode     =  0
CtrlUrl     =  http://192.168.1.100:49153/upnp/control/tvcontrol1
ActRequest  =  <u:PowerOn xmlns:u="urn:schemas-upnp-org:service:tvcontrol:1"></u:PowerOn>

ActResult   =  <u:PowerOnResponse xmlns:u="urn:schemas-upnp-org:service:tvcontrol:1">
<Power>1</Power>
</u:PowerOnResponse>

----------------------------------------------------------------------
======================================================================
```

