# Convenience Makefile for kelp kernel module
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
	insmod kelp.ko

unload:
	rmmod kelp

.PHONY: all clean install load unload
