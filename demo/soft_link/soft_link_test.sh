#!/bin/sh
# DNS service
echo "Setting up resolv.conf symlink..."
sudo cp /etc/resolv.conf ./resolv.conf.real
sudo ln -sf $(pwd)/resolv.conf.real /etc/resolv.conf

../dns/performance/cap_dns

sudo mv ./resolv.conf.real /etc/resolv.conf

# GRP service
echo "Setting up group ...symlink"
sudo cp /etc/group ./group.real
sudo ln -sf $(pwd)/group.real /etc/group

../grp/performance/casper_grp_perf

sudo mv ./group.real /etc/group

# NETDB service
echo "Setting up netdb ...symlink"
sudo cp /etc/protocols ./protocols.real
sudo ln -sf $(pwd)/protocols.real /etc/protocols

../netdb/performance/casper_netdb_perf

sudo mv ./protocols.real /etc/protocols

# PWD service

# SYSCTL service

# SYSLOG service
