#
# "Makefile.am" for "libupnp/upnp"
#
# Copyright (C) 2005 Rémi Turboult <r3mi@users.sourceforge.net>
#

if ENABLE_JSON
JSON_DIR=../cJSON
else
JSON_DIR=
endif

SUBDIRS = . sample $(JSON_DIR)

AM_CPPFLAGS = \
	-I$(srcdir)/inc \
	-I$(top_srcdir)/ixml/inc

if ENABLE_JSON
AM_CPPFLAGS += -I$(top_srcdir)/cJSON
endif


LDADD = \
	libupnp.la \
	$(top_builddir)/ixml/libixml.la


upnpincludedir = $(includedir)/upnp
upnpinclude_HEADERS = \
    inc/UpnpActionComplete.h \
	inc/UpnpActionRequest.h \
	inc/Callback.h \
	inc/UpnpDiscovery.h \
	inc/UpnpEvent.h \
	inc/UpnpEventSubscribe.h \
	inc/UpnpExtraHeaders.h \
	inc/UpnpFileInfo.h \
	inc/list.h \
	inc/UpnpStateVarComplete.h \
	inc/UpnpStateVarRequest.h \
	inc/UpnpSubscriptionRequest.h \
	inc/UpnpString.h \
	inc/upnp.h \
	inc/upnpdebug.h \
	inc/UpnpGlobal.h \
	inc/UpnpInet.h \
	inc/UpnpIntTypes.h \
	inc/UpnpStdInt.h \
	inc/UpnpUniStd.h \
	inc/file_utils.h

nodist_upnpinclude_HEADERS = inc/upnpconfig.h 
if ENABLE_TOOLS
upnpinclude_HEADERS += inc/upnptools.h 
endif

if ENABLE_JSON
upnpinclude_HEADERS += $(top_srcdir)/cJSON/cJSON.h
endif

# OpenSSL Wrapper
if UPNP_ENABLE_OPEN_SSL
upnpinclude_HEADERS += inc/openssl_error.h \
    inc/openssl_wrapper.h \
    inc/openssl_nonce.h
endif

# SUPnP
if ENABLE_SUPNP
upnpinclude_HEADERS += \
	inc/supnp_common.h \
	inc/supnp_captoken.h \
	inc/supnp_device.h \
	inc/supnp.h
endif

lib_LTLIBRARIES = libupnp.la

libupnp_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)/src/inc 

libupnp_la_LDFLAGS = \
	-version-info $(LT_VERSION_UPNP) \
	$(top_builddir)/ixml/libixml.la


if UPNP_ENABLE_OPEN_SSL
	if ENABLE_SUPNP
		libupnp_la_LDFLAGS += -export-symbols-regex '^(S?Upnp.|OpenSsl)*'
	else
		libupnp_la_LDFLAGS += -export-symbols-regex '^(Upnp.|OpenSsl)*'
	endif
else
	libupnp_la_LDFLAGS += -export-symbols-regex '^Upnp.*'
endif

if WIN32
libupnp_la_LDFLAGS += \
	-no-undefined \
	-liphlpapi \
	-lws2_32
endif

libupnp_la_SOURCES = \
	src/inc/config.h \
	src/inc/client_table.h \
	src/inc/gena.h \
	src/inc/gena_ctrlpt.h \
	src/inc/gena_device.h \
	src/inc/GenlibClientSubscription.h \
	src/inc/httpparser.h \
	src/inc/httpreadwrite.h \
	src/inc/md5.h \
	src/inc/membuffer.h \
	src/inc/miniserver.h \
	src/inc/netall.h \
	src/inc/parsetools.h \
	src/inc/service_table.h \
	src/inc/soaplib.h \
	src/inc/sock.h \
	src/inc/statcodes.h \
	src/inc/strintmap.h \
	src/inc/ssdplib.h \
	src/inc/sysdep.h \
	src/inc/unixutil.h \
	src/inc/upnpapi.h \
	src/inc/uri.h \
	src/inc/urlconfig.h \
	src/inc/upnputil.h \
	src/inc/uuid.h \
	src/inc/VirtualDir.h \
	src/inc/webserver.h

# threadutil
upnpinclude_HEADERS += \
	inc/ithread.h

libupnp_la_CPPFLAGS += -I$(srcdir)/src/threadutil
libupnp_la_SOURCES += \
	src/threadutil/FreeList.h \
	src/threadutil/FreeList.c \
	src/threadutil/LinkedList.h \
	src/threadutil/LinkedList.c \
	src/threadutil/ThreadPool.h \
	src/threadutil/ThreadPool.c \
	src/threadutil/TimerThread.h \
	src/threadutil/TimerThread.c

# ssdp
if ENABLE_SSDP
libupnp_la_SOURCES += \
    src/ssdp/SSDPResultData.c \
	src/ssdp/SSDPResultData.h \
	src/ssdp/SSDPResultDataCallback.c \
	src/ssdp/SSDPResultDataCallback.h \
	src/ssdp/ssdp_device.c \
	src/ssdp/ssdp_ctrlpt.c \
	src/ssdp/ssdp_server.c
endif

# soap
if ENABLE_SOAP
libupnp_la_SOURCES += \
	src/soap/soap_device.c \
	src/soap/soap_ctrlpt.c \
	src/soap/soap_common.c
endif

# genlib
libupnp_la_SOURCES += \
	src/genlib/miniserver/miniserver.c \
	src/genlib/client_table/client_table.c \
	src/genlib/client_table/GenlibClientSubscription.c \
	src/genlib/service_table/service_table.c \
	src/genlib/util/membuffer.c \
	src/genlib/util/strintmap.c \
	src/genlib/util/util.c \
	src/genlib/util/list.c \
	src/genlib/net/sock.c \
	src/genlib/net/http/httpparser.c \
	src/genlib/net/http/httpreadwrite.c \
	src/genlib/net/http/statcodes.c \
	src/genlib/net/http/webserver.c \
	src/genlib/net/http/parsetools.c \
	src/genlib/net/uri/uri.c

# gena
if ENABLE_GENA
libupnp_la_SOURCES += \
	src/gena/gena_device.c \
	src/gena/gena_ctrlpt.c \
	src/gena/gena_callback2.c
endif

# api
libupnp_la_SOURCES += \
    src/api/UpnpActionComplete.c \
	src/api/UpnpActionRequest.c \
	src/api/UpnpDiscovery.c \
	src/api/UpnpEvent.c \
	src/api/UpnpEventSubscribe.c \
	src/api/UpnpExtraHeaders.c \
	src/api/UpnpFileInfo.c \
	src/api/UpnpStateVarComplete.c \
	src/api/UpnpStateVarRequest.c \
	src/api/UpnpSubscriptionRequest.c \
	src/api/UpnpString.c \
	src/api/upnpapi.c \
	src/api/upnpdebug.c

# File Utils
libupnp_la_SOURCES += src/file/file_utils.c

if ENABLE_TOOLS
libupnp_la_SOURCES += src/api/upnptools.c
endif

if ENABLE_JSON
libupnp_la_SOURCES += $(top_srcdir)/cJSON/cJSON.c
endif

if UPNP_ENABLE_OPEN_SSL
libupnp_la_SOURCES += src/openssl/openssl_wrapper.c \
    src/openssl/openssl_nonce.c
endif

if ENABLE_SUPNP
libupnp_la_SOURCES += \
	src/supnp/supnp.c \
	src/supnp/supnp_captoken.c \
	src/supnp/supnp_common.c \
	src/supnp/supnp_device.c
endif

if ENABLE_DEBUG
AM_CPPFLAGS         += -DDEBUG -DUPNP_HAVE_DEBUG -DSTATS
else
AM_CPPFLAGS         += -DNDEBUG
endif

# uuid
if ENABLE_UUID
libupnp_la_SOURCES += \
	src/uuid/md5.c \
	src/uuid/sysdep.c \
	src/uuid/uuid.c
endif


# urlconfig
libupnp_la_SOURCES += src/urlconfig/urlconfig.c


if WINDOWS
# inet_pton (needed on Win32, compiles to nothing elsewhere)
libupnp_la_SOURCES += \
	src/inet_pton.c \
	src/inc/inet_pton.h
endif


# check / distcheck tests
check_PROGRAMS = test_init test_url test_log test_list
TESTS = test_init test_url test_log test_list
test_init_SOURCES = test/test_init.c
test_url_SOURCES = test/test_url.c
test_log_SOURCES = test/test_log.c
test_list_SOURCES = test/test_list.c


EXTRA_DIST = \
	m4/libupnp.m4 \
	src/win_dll.c

CLEANFILES = libupnp_err.log libupnp_info.log
