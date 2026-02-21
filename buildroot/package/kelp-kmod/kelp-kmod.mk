################################################################################
#
# kelp-kmod
#
################################################################################

KELP_KMOD_VERSION = 0.1.0
KELP_KMOD_SITE = $(BR2_EXTERNAL_KELP_PATH)/../kernel/module
KELP_KMOD_SITE_METHOD = local

define KELP_KMOD_BUILD_CMDS
	$(MAKE) -C $(LINUX_DIR) M=$(@D) \
		ARCH=$(KERNEL_ARCH) \
		CROSS_COMPILE=$(TARGET_CROSS) \
		modules
endef

define KELP_KMOD_INSTALL_TARGET_CMDS
	$(MAKE) -C $(LINUX_DIR) M=$(@D) \
		ARCH=$(KERNEL_ARCH) \
		CROSS_COMPILE=$(TARGET_CROSS) \
		INSTALL_MOD_PATH=$(TARGET_DIR) \
		modules_install
endef

$(eval $(generic-package))
