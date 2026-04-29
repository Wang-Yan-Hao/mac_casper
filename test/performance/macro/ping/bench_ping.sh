#!/bin/sh

if [ "$1" != "base" ] && [ "$1" != "exp" ]; then
    echo "Usage: $0 [base|exp]"
    exit 1
fi

MODE=$1
OUTPUT_FILE="ping_${MODE}.txt"
ITERATIONS=100

ARCH=$(uname -m)
CPU_MODEL=$(sysctl -n hw.model)

echo "Detected Architecture: $ARCH"
echo "Detected CPU: $CPU_MODEL"

case "$ARCH" in
    "arm64")
        REPEAT_COUNT=120
        echo "Platform: RPI4/ARM64 - Setting REPEAT_COUNT to $REPEAT_COUNT"
        ;;
    "amd64")
        REPEAT_COUNT=500
        echo "Platform: AMD64 PC - Setting REPEAT_COUNT to $REPEAT_COUNT"
        ;;
    *)
        REPEAT_COUNT=100
        echo "Platform: Unknown - Using default REPEAT_COUNT: $REPEAT_COUNT"
        ;;
esac
# ----------------------------

if ! ping -c 1 localhost > /dev/null 2>&1; then
    echo "Error: Cannot ping localhost."
    exit 1
fi

rm -f $OUTPUT_FILE

echo "Starting benchmark ($ITERATIONS iterations, each sample has $REPEAT_COUNT calls)..."

# Warm up
for i in $(jot 5); do
    ping -c 1 localhost > /dev/null
done

for i in $(jot $ITERATIONS); do
    ( /usr/bin/time -p sh -c "for j in \$(jot $REPEAT_COUNT); do ping -c 1 localhost > /dev/null; done" ) 2>&1 | grep real | awk '{print $2}' >> $OUTPUT_FILE

    if [ $((i % 10)) -eq 0 ]; then
        echo "Progress: $i / 100"
    fi
done

echo "Done! Data saved to $OUTPUT_FILE"
