#!/bin/sh

set -e  # Exit on any command failure

echo "=== Testing Casper Services ==="

# DNS Service Tests
echo ""
echo ">>> Testing Casper DNS service: getaddr"
cd ../test_program/dns
make
./getadd || { echo "getaddr test FAILED"; exit 1; }

echo ">>> Testing Casper DNS service: cap_dns"
cd performance
make
./cap_dns || { echo "cap_dns test FAILED"; exit 1; }

# FILEARGS Service Test
echo ""
echo ">>> Testing Casper fileargs service"
cd ../../fileargs
make
sh run.sh || { echo "fileargs test FAILED"; exit 1; }

# GRP Service Test
echo ""
echo ">>> Testing Casper grp service"
cd ../grp
make
./casper_grp_demo || { echo "casper_grp_demo test FAILED"; exit 1; }

# NETDB Service Test
echo ""
echo ">>> Testing Casper netdb service"
cd ../netdb
make
./casper_netdb_demo || { echo "casper_netdb_demo test FAILED"; exit 1; }

# PWD Service Test
echo ""
echo ">>> Testing Casper pwd service"
cd ../pwd
make
./casper_pwd_demo || { echo "casper_pwd_demo test FAILED"; exit 1; }

# SYSCTL Service Test
echo ""
echo ">>> Testing Casper sysctl service"
cd ../sysctl
make
./casper_sysctl_demo || { echo "casper_sysctl_demo test FAILED"; exit 1; }

# SYSLOG Service Test
echo ""
echo ">>> Testing Casper syslog service"
cd ../syslog
make
./casper_syslog_demo || { echo "casper_syslog_demo test FAILED"; exit 1; }
tail -n 2 /var/log/messages

echo ""
echo "=== All Casper service tests completed successfully ==="
