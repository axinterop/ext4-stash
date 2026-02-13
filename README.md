# ext4-stash: Hide data in file's slack space (ext4)

Simple Linux Kernel module for hiding string in slack space of specified file.

# Description

On initializiation the module creates several procs: /proc/hide, /proc/unhide and /proc/clear. These procs are used for data transfer between user space and the module. cli.c is used as a frontend binary to get coresponding data and pass it to the module through procs.

## Hiding

```sh
$ stash_cli hide /example/file.pdf "data"
```

User specifies `hide` command with absolute path of the target file and string to hide. The tool then looks up necessary data and constructs a string filled with that data. String is passed to /proc/hide on write operation. Passed string consists of several components and is defined by simple protocol: ```sh path\nphys\noff\nmsg```, where `path` is the path of target file used for hiding, `phys` is the number of physical block on a disk were the file resides, `off` specifes the start of slack space within the block, and `msg` is the string user wants to hide.

All those data we get in `cli.c` (in user space), specifically `phys` via fiemaps and `off` through as file's size from it's i-node. fiemap solution is chosen as it's the most stable solution for current Kernel API.

Next, data is recieved of the module's end, parsed and head to the physical block is accessed. Then, raw operations on that block is done, during which user's data is successfully written to the slack space.

## Unhiding (reading)

```
$ stash_cli unhide /example/file.pdf
data
```

Using `unhide` command first passes the `path`, `phys` and `off` through /proc/unhide on write operation. The module saves data in global variables (guarded by mutex locks), that waits for read operation. when such received, module extracts hidden data from the block using previously saved data, and writes back to /proc/unhide.

## Clearing

```
$ stash_cli clear /example/file.pdf
```

The `clear` command functions almost in the same way as `hide` command, except it clears the slack space (fills out with zeroes).
