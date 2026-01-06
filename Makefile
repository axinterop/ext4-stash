# Target names
MODULE_NAME := ext4_stash
CLI_NAME := stash_cli

# Kernel build variables
obj-m += $(MODULE_NAME).o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# Compilation flags for CLI
CC := gcc
CFLAGS := -Wall -O2

all: module cli

# Compile the Kernel Module
module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Compile the Userspace CLI
cli: cli.c
	$(CC) $(CFLAGS) cli.c -o $(CLI_NAME)

# Remove build artifacts
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f $(CLI_NAME)

# Helper to load the module (requires sudo)
load:
	sudo insmod $(MODULE_NAME).ko
	sudo chmod 666 /proc/ext4_stash/hide /proc/ext4_stash/unhide

# Helper to unload the module (requires sudo)
unload:
	sudo rmmod $(MODULE_NAME)

.PHONY: all module cli clean load unload
