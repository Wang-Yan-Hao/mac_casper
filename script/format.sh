#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd -P)
REPO_ROOT=$(CDPATH= cd "$SCRIPT_DIR/.." && pwd -P)

if ! command -v clang-format >/dev/null 2>&1; then
	echo "error: clang-format is required" >&2
	exit 127
fi

clang-format -i \
	"$REPO_ROOT/mac_casper.c" \
	"$REPO_ROOT/mac_casper.h" \
	"$REPO_ROOT/checker.c" \
	"$REPO_ROOT/checker.h" \
	"$REPO_ROOT/label.h" \
	"$REPO_ROOT"/src/*.c \
	"$REPO_ROOT"/src/*.h
