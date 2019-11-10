obj-m := spoof.o

PWD := $(shell pwd)
KDIR := /lib/modules/$(shell uname -r)/build

default :
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean :
	$(MAKE) -C $(KDIR) M=$(PWD) clean

test :
	make default
	insmod spoof.ko
	dmesg | grep kn
	rmmod spoof
