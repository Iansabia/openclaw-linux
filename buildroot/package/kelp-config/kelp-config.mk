################################################################################
#
# kelp-config
#
################################################################################

KELP_CONFIG_VERSION = 0.1.0
KELP_CONFIG_SITE = $(BR2_EXTERNAL_KELP_PATH)/board/kelp/rootfs_overlay
KELP_CONFIG_SITE_METHOD = local

define KELP_CONFIG_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0644 \
		$(BR2_EXTERNAL_KELP_PATH)/board/kelp/rootfs_overlay/etc/kelp/kelp.yaml \
		$(TARGET_DIR)/etc/kelp/kelp.yaml
endef

$(eval $(generic-package))
