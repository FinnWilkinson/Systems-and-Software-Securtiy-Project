TARGET = rootkit
rootkit-objs := rootkit_main.o modify_syscalls.o execmon_minimal/kmod/execmon.o
# obj-y   	 := execmon_minimal/
# rootkit-y    := /execmon_minimal/execmon.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

obj-m += $(TARGET).o

all:
	+$(MAKE) -C execmon_minimal
	make -C $(KDIR) M=$(PWD) modules

clean:
	+$(MAKE) -C execmon_minimal clean
	make -C $(KDIR) M=$(shell pwd) clean