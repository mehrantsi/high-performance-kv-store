obj-m += hpkv_module.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all: x86_64 arm64

x86_64:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

arm64:
	$(MAKE) ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \
		KCFLAGS="-DCONFIG_FUNCTION_TRACER -DCONFIG_HAVE_FENTRY" \
		-C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
