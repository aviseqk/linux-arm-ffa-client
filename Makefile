ifneq ($(KERNELRELEASE),)

obj-m += arm-ffa-client.o
#arm-ffa-client-y := helpers/ffa-direct-msg.o

#ccflags-y := -I$(src)/include

else
ROOT          ?= $(abspath $(CURDIR))

KDIR ?= $(ROOT)/../kvm-ffa-guest-relay/linux/
KOBJ_DIR ?= $(ROOT)/../kvm-ffa-guest-relay/out/linux/host
KOUT ?= $(ROOT)/build

ARCH ?= arm64
CROSS_COMPILE ?= aarch64-none-linux-gnu-

.PHONY: all clean

all:
	$(MAKE) -C $(KDIR) \
		O=$(KOBJ_DIR) \
		M=$(CURDIR) \
		ARCH=$(ARCH) \
		CROSS_COMPILE="$(CROSS_COMPILE)" \
		modules

clean:
	$(MAKE) -C $(KDIR) \
		O=$(KOBJ_DIR) \
		M=$(CURDIR) \
		ARCH=$(ARCH) \
		CROSS_COMPILE="$(CROSS_COMPILE)" \
		clean

endif
