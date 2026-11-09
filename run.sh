#!/bin/bash
set -e

echo "==> Packaging initramfs..."
cd initramfs
find . -print0 | cpio --null -o -H newc | gzip -9 > ../initramfs.cpio.gz
cd ..

echo "==> Booting QEMU..."
qemu-system-x86_64 \
  -kernel linux-6.18/arch/x86/boot/bzImage \
  -initrd initramfs.cpio.gz \
  -append "console=ttyS0 panic=-1" \
  -nographic -m 512M -no-reboot \
  -netdev user,id=net0 \
  -device virtio-net-pci,netdev=net0
