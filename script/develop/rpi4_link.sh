#/bin/sh
# can't use sudo to execute
ld -m aarch64elf -d -warn-common --build-id=sha1 --no-relax -r -o mac_casper.kld mac_casper.o checker.o
awk -f /usr/src/sys/conf/kmod_syms.awk mac_casper.kld export_syms |  xargs -J % objcopy % mac_casper.kld
ld -m aarch64elf -Bshareable -znotext -znorelro -d -warn-common --build-id=sha1 --no-relax -o mac_casper.ko mac_casper.kld
objcopy --strip-debug mac_casper.ko

#sudo sh script/unload_load.sh
