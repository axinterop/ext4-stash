# ext4-stash: Hide data in file's slack space (ext4)

Simple Linux Kernel module for hiding string in slack space of specified file.

# Description

On initializiation module creates several procs: `/proc/hide`, `/proc/unhide` and `/proc/clear`. These procs are used to transfer data between user space and the kernel module. `cli.c` is a client to pass data to the module and get data from it.

## Hiding

```sh
$ stash_cli hide /example/file.pdf "data"
```

`hide` command accepts the absolute path of target file and string to hide. It creates a string and passes to the module through proc. String is defined by protocol: ```path\nphys\noff\nmsg```, where `path` is the path to target file, `phys` is the number of physical block where this file resides, `off` is the offset of the slack space within the block, and `msg` is data to be hidden.

## Unhiding (reading)

```
$ stash_cli unhide /example/file.pdf
data
```

`unhide` command passes the `path` (also `phys` and `off`) on write operation. This data is stored in global variables by module. Then, read operation is done and module, based on previously saved data, retrieves hidden data and returns it through writing to proc.

## Clearing

```
$ stash_cli clear /example/file.pdf
```

The `clear` command functions almost in the same way as `hide` command, except it clears the slack space (fills out with zeroes) instead of writing custom data.
