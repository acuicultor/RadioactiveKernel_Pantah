#
# SPDX-License-Identifier: GPL-2.0-only
#
KERNEL_SRC ?= /lib/modules/$(shell uname -r)/build
M ?= $(shell pwd)
KBUILD_OPTIONS += CONFIG_SUBSYSTEM_COREDUMP_TEST=m

obj-$(CONFIG_SUBSYSTEM_COREDUMP_TEST) += sscoredump_test.o sscoredump_sample_test.o

modules modules_install clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(M) W=1 $(KBUILD_OPTIONS) $(@)
