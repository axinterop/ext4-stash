obj-m += hide_module.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# all: module utility
all: module

module:
	make -C $(KERNELDIR) M=$(PWD) modules

utility: hide_util.c
	gcc -Wall -o hide hide_util.c

clean:
	make -C $(KERNELDIR) M=$(PWD) clean
	rm -f hide

load: module
	sudo insmod hide_module.ko
	sudo chmod 666 /dev/hide_device

unload:
	sudo rmmod hide_module 2>/dev/null || true

logs:
	sudo dmesg | tail -20

test: all load
	@echo "Module loaded. Testing..."
	@echo "Creating test files..."
	dd if=/dev/zero of=/tmp/container.bin bs=1024 count=10
	echo "Secret test data 123!" > /tmp/secret.txt
	@echo ""
	@echo "Hiding /tmp/secret.txt into /tmp/container.bin..."
	sudo ./hide /tmp/container.bin /tmp/secret.txt
	@echo ""
	@echo "Retrieving hidden data..."
	sudo ./hide -r /tmp/container.bin /tmp/recovered.txt 21
	@echo ""
	@echo "Checking recovered data:"
	cat /tmp/recovered.txt
	@echo ""

rebuild: clean all

.PHONY: all module utility clean load unload logs test rebuild
