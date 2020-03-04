KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
obj-m := ip.o

default:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules
