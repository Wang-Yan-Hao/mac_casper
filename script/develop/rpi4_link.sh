#/bin/sh
# can't use sudo to execute
ld -m aarch64elf -d -warn-common --build-id=sha1 --no-relax -r -o mac_policy_ops.kld mac_policy_ops.o checker/checker.o
awk -f /usr/src/sys/conf/kmod_syms.awk mac_policy_ops.kld export_syms |  xargs -J % objcopy % mac_policy_ops.kld
ld -m aarch64elf -Bshareable -znotext -znorelro -d -warn-common --build-id=sha1 --no-relax -o mac_policy_ops.ko mac_policy_ops.kld
objcopy --strip-debug mac_policy_ops.ko

sudo sh script/unload_load.sh
