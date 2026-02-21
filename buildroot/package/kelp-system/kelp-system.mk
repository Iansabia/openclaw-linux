################################################################################
#
# kelp-system
#
################################################################################

KELP_SYSTEM_VERSION = 0.1.0
KELP_SYSTEM_SITE = $(BR2_EXTERNAL_KELP_PATH)/..
KELP_SYSTEM_SITE_METHOD = local
KELP_SYSTEM_INSTALL_STAGING = YES
KELP_SYSTEM_INSTALL_TARGET = YES

KELP_SYSTEM_CONF_OPTS = \
	-DKELP_STATIC=ON \
	-DKELP_BUILD_TESTS=OFF \
	-DCMAKE_INSTALL_PREFIX=/usr

KELP_SYSTEM_DEPENDENCIES = \
	openssl \
	libcurl \
	cjson \
	libyaml \
	sqlite \
	libmicrohttpd

# Optional dependencies
ifeq ($(BR2_PACKAGE_LIBWEBSOCKETS),y)
KELP_SYSTEM_DEPENDENCIES += libwebsockets
endif

ifeq ($(BR2_PACKAGE_NCURSES),y)
KELP_SYSTEM_DEPENDENCIES += ncurses
endif

$(eval $(cmake-package))
