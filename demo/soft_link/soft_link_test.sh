#!/bin/sh

set -eu

if [ "$#" -ne 1 ] || [ "$1" != "--confirm-system-file-replacement" ]; then
	echo "usage: sudo $0 --confirm-system-file-replacement" >&2
	echo "warning: temporarily replaces /etc/resolv.conf, /etc/group, and /etc/protocols" >&2
	exit 2
fi

if [ "$(id -u)" -ne 0 ]; then
	echo "error: run this test as root" >&2
	exit 1
fi

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd -P)
REPO_ROOT=$(CDPATH= cd "$SCRIPT_DIR/../.." && pwd -P)
WORK_DIR=$(mktemp -d "/tmp/mac_casper_soft_link.XXXXXX")

ACTIVE_TARGET=
ACTIVE_BACKUP=
ACTIVE_LINK=

cleanup_active()
{
	[ -n "$ACTIVE_TARGET" ] || return 0

	if [ -L "$ACTIVE_TARGET" ]; then
		if [ "$(readlink "$ACTIVE_TARGET")" != "$ACTIVE_LINK" ]; then
			echo "error: unexpected symlink at $ACTIVE_TARGET; backup retained at $ACTIVE_BACKUP" >&2
			return 1
		fi
		rm "$ACTIVE_TARGET"
	elif [ -e "$ACTIVE_TARGET" ]; then
		echo "error: unexpected file at $ACTIVE_TARGET; backup retained at $ACTIVE_BACKUP" >&2
		return 1
	fi

	if [ -n "$ACTIVE_BACKUP" ]; then
		mv "$ACTIVE_BACKUP" "$ACTIVE_TARGET"
	fi

	ACTIVE_TARGET=
	ACTIVE_BACKUP=
	ACTIVE_LINK=
}

cleanup()
{
	status=$?
	trap - 0 HUP INT TERM
	if ! cleanup_active; then
		status=1
	fi
	rm -f "$WORK_DIR/resolv.conf" "$WORK_DIR/group" "$WORK_DIR/protocols"
	if ! rmdir "$WORK_DIR"; then
		status=1
	fi
	exit "$status"
}

trap cleanup 0
trap 'exit 1' HUP INT TERM

run_with_system_symlink()
{
	target=$1
	fixture=$2
	program=$3
	source_file="$WORK_DIR/$fixture"
	program_path="$REPO_ROOT/test/performance/function/$program"

	if [ ! -x "$program_path" ]; then
		echo "error: benchmark not built or not executable: $program_path" >&2
		return 1
	fi
	if [ ! -e "$target" ]; then
		echo "error: required system file does not exist: $target" >&2
		return 1
	fi

	cp -p "$target" "$source_file"
	ACTIVE_TARGET=$target
	ACTIVE_LINK=$source_file
	ACTIVE_BACKUP=
	if [ -e "$target" ] || [ -L "$target" ]; then
		backup_path=$(mktemp "$target.mac_casper_backup.XXXXXX")
		if ! mv "$target" "$backup_path"; then
			rm -f "$backup_path"
			ACTIVE_TARGET=
			ACTIVE_LINK=
			return 1
		fi
		ACTIVE_BACKUP=$backup_path
	fi

	ln -s "$source_file" "$target"
	printf '\n>>> Running %s with %s linked to a temporary copy\n' \
	    "$program" "$target"
	"$program_path"
	cleanup_active
}

printf '%s\n' "This test briefly replaces system files. Do not run it on a production machine."
run_with_system_symlink /etc/resolv.conf resolv.conf dns/cap_dns
run_with_system_symlink /etc/group group grp/casper_grp_perf
run_with_system_symlink /etc/protocols protocols netdb/casper_netdb_perf
