obj-m += hpkv_module.o

KDIR ?= /lib/modules/$(shell uname -r)/build
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

ifeq ($(ARCH),arm64)
    ifeq ($(shell uname -m),aarch64)
        # Native ARM64 build
        CROSS_COMPILE ?=
    else
        # Cross-compilation for ARM64
        CROSS_COMPILE ?= aarch64-linux-gnu-
    endif
endif

all: build

build:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f *.o *.ko *.mod.c *.mod *.symvers *.order
