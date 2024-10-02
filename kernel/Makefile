obj-m += hpkv_module.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all: x86_64 arm64

x86_64:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

arm64:
	$(MAKE) ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f hpkv_module_x86_64.ko hpkv_module_arm64.ko
	rm -f *.o *.ko *.mod.c *.mod *.symvers *.order
