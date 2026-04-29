#!/bin/sh

if [ "$1" != "base" ] && [ "$1" != "exp" ]; then
    echo "Usage: $0 [base|exp]"
    exit 1
fi

MODE=$1
ITERATIONS=100
TRACE_FILE="/tmp/ktrace.out"
OUTPUT_FILE="kdump_${MODE}.txt"

ARCH=$(uname -m)
CPU_MODEL=$(sysctl -n hw.model)

echo "Detected Architecture: $ARCH"
echo "Detected CPU: $CPU_MODEL"

case "$ARCH" in
    "arm64")
        REPEAT_COUNT=25
        echo "Platform: RPI4/ARM64 - Setting REPEAT_COUNT to $REPEAT_COUNT"
        ;;
    "amd64")
        REPEAT_COUNT=250
        echo "Platform: AMD64 PC - Setting REPEAT_COUNT to $REPEAT_COUNT"
        ;;
    *)
        REPEAT_COUNT=50
        echo "Platform: Unknown - Using default REPEAT_COUNT: $REPEAT_COUNT"
        ;;
esac
# ----------------------------

if [ ! -f $TRACE_FILE ]; then
    echo "Generating ktrace data (ls -R /usr/include)..."
    ktrace -f $TRACE_FILE ls -R /usr/include > /dev/null 2>&1
    echo "Done generating $TRACE_FILE"
fi

rm -f $OUTPUT_FILE

echo "Running $ITERATIONS iterations (Sample size: $REPEAT_COUNT per iteration)..."

for i in $(jot 3); do
    kdump -f $TRACE_FILE > /dev/null
done

for i in $(jot $ITERATIONS); do
    ( /usr/bin/time -p sh -c "for j in \$(jot $REPEAT_COUNT); do kdump -f $TRACE_FILE > /dev/null; done" ) 2>&1 | grep real | awk '{print $2}' >> $OUTPUT_FILE

    if [ $((i % 10)) -eq 0 ]; then
        echo "Progress: $i / 100"
    fi
done

echo "Done! Data saved to $OUTPUT_FILE"
