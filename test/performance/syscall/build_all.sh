#!/bin/sh

ARCH=$(uname -m)
case "$ARCH" in
    arm*|aarch64)
        DETECTED_MODE="arm"
        ;;
    *)
        DETECTED_MODE="amd64"
        ;;
esac

MODE=$DETECTED_MODE

while getopts "m:h" opt; do
  case $opt in
    m)
      MODE=$OPTARG
      ;;
    h)
      echo "Usage: $0 [-m amd64|arm]"
      echo "Default mode (auto-detected): $DETECTED_MODE"
      exit 0
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
  esac
done

echo "=== Casper Build System ==="
echo "Hardware Detected: $ARCH"
echo "Targeting Mode   : $MODE"

DIRS="open socket sysctl"

for d in $DIRS; do
    if [ -d "$d" ]; then
        if [ "$MODE" = "arm" ]; then
            case "$d" in
                "sysctl") ITER=400000 ;;
                "open")   ITER=200000 ;;
                "socket") ITER=400000 ;;
                *)        ITER=1      ;;
            esac
        else
            case "$d" in
                "sysctl") ITER=8000000 ;;
                "open")   ITER=4000000 ;;
                "socket") ITER=1600000 ;;
                *)        ITER=1       ;;
            esac
        fi

        echo ">> Compiling $d/ (Iterations: $ITER)..."

        make -C "$d" clean > /dev/null
        make -C "$d" ITERATIONS=$ITER

        if [ $? -eq 0 ]; then
            echo "   [OK] Success"
        else
            echo "   [ERROR] Failed to build $d"
            exit 1
        fi
    fi
done

echo "=== All binaries updated for $MODE ==="
