obj-m := ivshmem_driver.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	make -C $(KDIR) M=$(CURDIR) modules

clean:
	make -C $(KDIR) M=$(CURDIR) clean

install:
	sudo insmod ivshmem_driver.ko

uninstall:
	sudo rmmod ivshmem_driver

reload: uninstall install

test:
	dmesg | tail -20
