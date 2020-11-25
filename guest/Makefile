TARGET = rootkit
rootkit-objs := rootkit_main.o modify_syscalls.o backdoor.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

obj-m += $(TARGET).o

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(shell pwd) clean
