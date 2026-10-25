#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd -P)
REPO_ROOT=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd -P)

run_demo()
{
	directory=$1
	binary=$2

	printf '\n>>> Building and running %s/%s\n' "$directory" "$binary"
	(
		cd "$REPO_ROOT/$directory"
		make
		"./$binary"
	)
}

printf '%s\n' "=== Casper service smoke tests ==="
printf '%s\n' "Run this on FreeBSD with the required Casper libraries and services."

run_demo demo/dns getadd
run_demo test/performance/function/dns cap_dns

printf '\n>>> Building and running demo/fileargs\n'
(
	cd "$REPO_ROOT/demo/fileargs"
	make
	sh ./run.sh
)

run_demo demo/grp casper_grp_demo
run_demo demo/netdb casper_netdb_demo
run_demo demo/pwd casper_pwd_demo
run_demo demo/sysctl casper_sysctl_demo
run_demo demo/syslog casper_syslog_demo

printf '\n%s\n' "=== Casper service smoke tests completed ==="
