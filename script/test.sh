#!/bin/sh

set -e  # Exit on any command failure

echo "=== Testing Casper Services ==="

# DNS Service Tests
echo ""
echo ">>> Testing Casper DNS service: getaddr"
cd test_program
make
./getadd || { echo "getaddr test FAILED"; exit 1; }

echo ">>> Testing Casper DNS service: cap_dns"
cd performance
make
./cap_dns || { echo "cap_dns test FAILED"; exit 1; }

# FILEARGS Service Test
echo ""
echo ">>> Testing Casper fileargs service"
cd ../fileargs
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
./casper_netdb_demo || { echo "caspr_netdb_demo test FAILED"; exit 1; }

# PWD Service Test
echo ""
echo ">>> Testing Casper pwd service"
cd ../pwd
make
./casper_pwd_demo || { echo "caspr_netdb_demo test FAILED"; exit 1; }

echo ""
echo "=== All Casper service tests completed successfully ==="
