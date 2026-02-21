# Convenience Makefile for clawd kernel module
# The actual build rules are in Kbuild; this wraps kbuild invocations.

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a

load:
	insmod clawd.ko

unload:
	rmmod clawd

.PHONY: all clean install load unload
