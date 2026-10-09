#!/bin/bash -e
# Standard pi-gen stage bootstrap: start from the previous stage's rootfs
# (stage2 = Raspberry Pi OS Lite) before layering Ragnar on top.
if [ ! -d "${ROOTFS_DIR}" ]; then
	copy_previous
fi
