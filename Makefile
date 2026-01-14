MODULE_NAME := ext4_stash
CLI_NAME := stash_cli

obj-m += $(MODULE_NAME).o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

CC := gcc
CFLAGS := -Wall -O2

all: module cli

module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

cli: cli.c
	$(CC) $(CFLAGS) cli.c -o $(CLI_NAME)

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f $(CLI_NAME)

load:
	sudo insmod $(MODULE_NAME).ko
	sudo chmod 666 /proc/ext4_stash/hide /proc/ext4_stash/unhide

unload:
	sudo rmmod $(MODULE_NAME)

.PHONY: all module cli clean load unload
