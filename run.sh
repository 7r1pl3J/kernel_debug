#!/bin/sh
qemu-system-x86_64 \
    -kernel bzImage \
    -cpu qemu64,+smep,+smap \
    -m 3G \
    -smp 1 \
    -initrd rootfs.cpio \
    -append "console=ttyS0 nokaslr quiet loglevel=3 oops=panic panic_on_warn=1 panic=-1 " \
    -nographic \
    -no-reboot \
    -gdb tcp::12345
