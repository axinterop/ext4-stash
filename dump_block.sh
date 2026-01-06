#!/bin/bash
if [ -z "$1" ]; then
    echo "Usage: $0 <file_path>"
    exit 1
fi

PHYS_BLOCK=$(sudo debugfs -R "dump_extents $1" /dev/sda2 2>/dev/null | awk '/0\/ 0/ {print $8}')

if [ -z "$PHYS_BLOCK" ]; then
    echo "Error: Could not find physical block for $1"
    exit 1
fi

echo "File: $1"
echo "Physical block offset: $PHYS_BLOCK"

sudo dd if=/dev/sda2 bs=4096 skip=$PHYS_BLOCK count=1 of=block_dump.bin
hexdump -C block_dump.bin
