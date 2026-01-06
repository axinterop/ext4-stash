#!/bin/bash
sudo dd if=/dev/sda2 bs=4096 skip=$1 count=1 of=block_dump.bin
hexdump -C block_dump.bin
