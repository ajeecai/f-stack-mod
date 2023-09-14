#!/bin/sh

modprobe uio_pci_generic
dpdk-devbind.py --bind=uio_pci_generic 0000:00:08.0
echo 0 > /proc/sys/kernel/randomize_va_space
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
